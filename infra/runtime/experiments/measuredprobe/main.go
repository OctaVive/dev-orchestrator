// measuredprobe exercises signed capability probes in a disposable guest only.
// Its explicit local fixture authority is not lifecycle or mTLS acceptance.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/policy"
	"dev-orchestrator/internal/runtimeagent"
	"dev-orchestrator/internal/runtimeengine"
	"dev-orchestrator/internal/runtimehost"
	"dev-orchestrator/internal/runtimeisolation"
	"fmt"
	"os"
	"strings"
	"time"
)

type fixtureAuthority struct{}

func (fixtureAuthority) Current(context.Context, runtimeagent.Command) error {
	return runtimeagent.ErrDenied
}
func (fixtureAuthority) Valid(context.Context, string, string) error { return nil }
func (fixtureAuthority) Image(string) (policy.Admission, error) {
	return policy.Admission{}, runtimeagent.ErrDenied
}
func (fixtureAuthority) Volume(string, string) (string, error) { return "", runtimeagent.ErrDenied }
func (fixtureAuthority) Secret(string, string, string) error   { return runtimeagent.ErrDenied }
func must(e error) {
	if e != nil {
		fmt.Println("M09-MEASURED-ERROR", e)
		os.Exit(1)
	}
}
func main() {
	if os.Geteuid() != 1000 {
		must(runtimeagent.ErrDenied)
	}
	_, err := os.Stat("/etc/m09-disposable-guest")
	must(err)
	p, err := runtimehost.Load()
	must(err)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	l, err := runtimeagent.OpenLedger(ctx, runtimehost.Root+"/agent/ledger.sqlite", p.WorkerID, p.Incarnation)
	must(err)
	defer l.Close()
	anchor, err := runtimeisolation.ReadAgentEnrollment()
	must(err)
	if !anchor.Matches(l) {
		must(runtimeagent.ErrDenied)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	reportPub, reportKey, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	for i, app := range p.Apps {
		enrolled, err := runtimeisolation.ReadEnrollment(app.ID)
		must(err)
		client, err := runtimeengine.NewClient(enrolled.Backend.Socket)
		must(err)
		enforcement, err := runtimeengine.NewMeasuredEnforcement(client, l, enrolled.Backend, runtimeengine.EnforcementConfig{WorkerID: p.WorkerID, Incarnation: p.Incarnation, TemplateHash: p.TemplateHash, ProfileHash: p.Hash(), CPUMillis: app.CPUMillis, PIDs: app.PIDs, Canary: *p.Canary})
		must(err)
		engine := &runtimeengine.Engine{Backend: &enrolled.Backend, Client: client, Ledger: l, Enforcement: enforcement, Delivery: &runtimeengine.Delivery{Client: client}, WorkerID: p.WorkerID, Incarnation: p.Incarnation, MACProfile: "tap-runtime"}
		authority := fixtureAuthority{}
		agent, err := runtimeagent.New(runtimeagent.Config{WorkerID: p.WorkerID, Incarnation: p.Incarnation, Keys: map[string]ed25519.PublicKey{"fixture": pub}, InventoryKey: reportKey, Resolver: authority, Approval: authority, Lease: authority, Engine: engine, Ledger: l})
		must(err)
		c := runtimeagent.Command{Version: 3, Operation: "probe", ID: fmt.Sprintf("33333333-3333-4333-8333-%012d", i+1), WorkerID: p.WorkerID, Incarnation: p.Incarnation, AppID: app.ID, DeploymentID: p.WorkerID, Generation: 1, Nonce: fmt.Sprintf("%064x", i+1), KeyID: "fixture", ExpiresAt: time.Now().UTC().Add(4 * time.Minute).Format(time.RFC3339Nano), PolicyHash: policy.Hash(), SpecHash: contracts.Digest([]byte(strings.Repeat("probe", 1)))}
		must(c.Sign(key))
		result, err := agent.Execute(ctx, c)
		fmt.Printf("M09-MEASURED-RESULT app=%s code=%s\n", app.ID, result.Code)
		must(err)
		if result.Inventory == nil {
			must(runtimeagent.ErrUnsupported)
		}
		must(result.Inventory.VerifyFor(time.Now(), p.WorkerID, p.Incarnation, app.ID, enrolled.Backend.Hash(), c.Nonce, reportPub))
		enforcement.Close()
		client.Close()
	}
	fmt.Println("M09-MEASURED-COMPLETE scope=signed-canary-only-not-R01")
}
