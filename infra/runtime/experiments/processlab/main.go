// processlab is an explicit disposable-lab issuer. It is not a product approval
// endpoint and cannot manufacture M07/M08 records or parse a workload archive.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/policy"
	"dev-orchestrator/internal/runtimeagent"
	"dev-orchestrator/internal/runtimehost"
	"dev-orchestrator/internal/runtimeisolation"
	"dev-orchestrator/internal/runtimeprocess"
	"dev-orchestrator/internal/storage"
)

const worker = "11111111-1111-4111-8111-111111111111"
const guestRoot = "/var/lib/m09-process"

type fixture struct {
	Scenario                                                  string `json:"scenario,omitempty"`
	WorkerID, Incarnation, InventoryPublic, WorkerFingerprint string
	CertificateUntil                                          time.Time
}
type handoffImage struct {
	Intent storage.BuildIntent `json:"intent"`
	Image  string              `json:"image"`
}
type handoff struct {
	External []handoffImage           `json:"external,omitempty"`
	Intent   storage.BuildIntent      `json:"intent"`
	Spec     contracts.RuntimeSpecV2  `json:"spec"`
	Result   contracts.ArtifactResult `json:"result"`
}

func must(e error) {
	if e != nil {
		fmt.Println("M09-PROCESS-ERROR", e)
		os.Exit(1)
	}
}
func write(path string, raw []byte) { must(os.WriteFile(path, raw, 0600)) }
func jsonFile(path string, v any)   { b, e := json.Marshal(v); must(e); write(path, b) }
func readJSON[T any](path string) T {
	b, e := os.Open(path)
	must(e)
	defer b.Close()
	v, e := contracts.DecodeConfiguration[T](b)
	must(e)
	return v
}
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func generate(dir string) {
	must(os.Mkdir(dir, 0700))
	must(os.Mkdir(filepath.Join(dir, "agent"), 0700))
	must(os.Mkdir(filepath.Join(dir, "controller"), 0700))
	caPub, caKey, e := ed25519.GenerateKey(rand.Reader)
	must(e)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "M09 isolated lab CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(6 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, caPub, caKey)
	must(e)
	issue := func(name, uri string, serial int64, usage x509.ExtKeyUsage) ([]byte, ed25519.PrivateKey) {
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		must(e)
		u, e := url.Parse(uri)
		must(e)
		c := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(4 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, URIs: []*url.URL{u}}
		if usage == x509.ExtKeyUsageServerAuth {
			c.IPAddresses = []net.IP{net.ParseIP("192.0.2.11")}
			c.DNSNames = []string{"runtime-controller.m09.invalid"}
		}
		der, e := x509.CreateCertificate(rand.Reader, c, ca, pub, caKey)
		must(e)
		return der, key
	}
	server, serverKey := issue("runtime controller", "spiffe://tap/runtime-controller", 2, x509.ExtKeyUsageServerAuth)
	agent, agentKey := issue("runtime agent", "spiffe://tap/runtime-agent/"+worker, 3, x509.ExtKeyUsageClientAuth)
	reportPub, reportKey, e := ed25519.GenerateKey(rand.Reader)
	must(e)
	commandPub, commandKey, e := ed25519.GenerateKey(rand.Reader)
	must(e)
	material := func(sub string, cert []byte, key ed25519.PrivateKey) {
		p := filepath.Join(dir, sub)
		write(filepath.Join(p, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
		write(filepath.Join(p, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}))
		raw, e := x509.MarshalPKCS8PrivateKey(key)
		must(e)
		write(filepath.Join(p, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}))
	}
	material("agent", agent, agentKey)
	material("controller", server, serverKey)
	write(filepath.Join(dir, "agent/inventory.key"), []byte(base64.StdEncoding.EncodeToString(reportKey)))
	write(filepath.Join(dir, "controller/command.key"), []byte(base64.StdEncoding.EncodeToString(commandKey)))
	keys := map[string]string{"fixture": base64.StdEncoding.EncodeToString(commandPub)}
	cert, e := x509.ParseCertificate(server)
	must(e)
	jsonFile(filepath.Join(dir, "agent/config.json"), runtimeprocess.AgentConfiguration{Origin: "https://192.0.2.11:9443", ServerName: "runtime-controller.m09.invalid", ControllerURI: "spiffe://tap/runtime-controller", ControllerSPKI: hash(cert.RawSubjectPublicKeyInfo), AllowedControllerCertificates: []string{hash(server)}, CA: "/var/lib/tap-runtime/agent/ca.pem", Certificate: "/var/lib/tap-runtime/agent/cert.pem", Key: "/var/lib/tap-runtime/agent/key.pem", InventoryKey: "/var/lib/tap-runtime/agent/inventory.key", CommandKeys: keys})
	jsonFile(filepath.Join(dir, "controller/config.json"), map[string]any{"database": guestRoot + "/metadata.db", "artifacts": guestRoot + "/artifacts", "listen": "192.0.2.11:9443", "ca": guestRoot + "/ca.pem", "certificate": guestRoot + "/cert.pem", "key": guestRoot + "/key.pem", "command_keys": keys})
	workerCert, e := x509.ParseCertificate(agent)
	must(e)
	jsonFile(filepath.Join(dir, "controller/fixture.json"), fixture{WorkerID: worker, Incarnation: worker, InventoryPublic: base64.StdEncoding.EncodeToString(reportPub), WorkerFingerprint: hash(agent), CertificateUntil: workerCert.NotAfter})
	fmt.Println("M09-PROCESS-TRUST-PREPARED")
}
func drive() {
	if os.Geteuid() != 1002 {
		must(runtimeagent.ErrDenied)
	}
	_, e := os.Stat("/etc/m09-disposable-guest")
	must(e)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	f := readJSON[fixture](guestRoot + "/fixture.json")
	h := readJSON[handoff](guestRoot + "/handoff.json")
	enrollments := readJSON[struct {
		Enrollments []runtimeisolation.Enrollment `json:"enrollments"`
	}](guestRoot + "/enrollments.json").Enrollments
	key, e := runtimeprocess.PrivateKey(guestRoot + "/command.key")
	must(e)
	pub := key.Public().(ed25519.PublicKey)
	report, e := base64.StdEncoding.Strict().DecodeString(f.InventoryPublic)
	must(e)
	state, e := storage.Open(ctx, guestRoot+"/metadata.db")
	must(e)
	defer state.Close()
	renew := func() {
		must(state.EnrollRuntimeWorker(ctx, storage.RuntimeWorker{WorkerID: f.WorkerID, Incarnation: f.Incarnation, InventoryKey: ed25519.PublicKey(report), LeaseUntil: time.Now().Add(55 * time.Second)}))
	}
	renew()
	must(state.EnrollRuntimeCertificate(ctx, f.WorkerID, f.Incarnation, f.WorkerFingerprint, f.CertificateUntil))
	for _, enrollment := range enrollments {
		if enrollment.WorkerID != f.WorkerID || enrollment.Incarnation != f.Incarnation {
			must(runtimeagent.ErrDenied)
		}
		must(state.EnrollRuntimeBackend(ctx, f.WorkerID, f.Incarnation, enrollment.Backend.AppID, enrollment.Backend.Hash()))
	}
	must(state.SetRuntimeScanPolicy(ctx, h.Intent.Job.Policy))
	for _, service := range h.Spec.Services {
		intent := h.Intent
		for _, external := range h.External {
			if external.Image == service.Image {
				intent = external.Intent
			}
		}
		admission, err := state.EnrollRuntimeImage(ctx, intent, service.Image)
		must(err)
		if admission.ID != service.AdmissionID {
			must(runtimeagent.ErrDenied)
		}
	}
	must(state.IssueRuntimeApproval(ctx, f.WorkerID, f.Incarnation, 1, h.Spec, time.Now().Add(10*time.Minute)))
	db, e := sql.Open("sqlite", guestRoot+"/metadata.db")
	must(e)
	defer db.Close()
	createID := "66666666-6666-4666-8666-000000000002"
	for i, operation := range []string{"probe", "create", "inspect", "logs", "stop", "inspect", "remove", "probe"} {
		renew()
		c := runtimeagent.Command{Version: 3, Operation: operation, ID: fmt.Sprintf("66666666-6666-4666-8666-%012d", i+1), WorkerID: f.WorkerID, Incarnation: f.Incarnation, AppID: h.Spec.AppID, DeploymentID: h.Spec.DeploymentID, Generation: 1, Nonce: fmt.Sprintf("%064x", i+1000), KeyID: "fixture", ExpiresAt: time.Now().UTC().Add(4 * time.Minute).Format(time.RFC3339Nano), PolicyHash: policy.Hash(), SpecHash: policy.SpecHash(h.Spec)}
		if operation == "create" {
			c.Spec = &h.Spec
		} else if operation != "probe" {
			c.Target = createID
		}
		if operation == "logs" {
			c.LogLimit = 4096
		}
		must(c.Sign(key))
		must(state.QueueRuntimeCommand(ctx, c, map[string]ed25519.PublicKey{"fixture": pub}))
		nextRenew := time.Now().Add(15 * time.Second)
		for {
			if ctx.Err() != nil {
				must(ctx.Err())
			}
			if time.Now().After(nextRenew) {
				renew()
				nextRenew = time.Now().Add(15 * time.Second)
			}
			var raw []byte
			e = db.QueryRowContext(ctx, "SELECT result_json FROM runtime_queue WHERE command=?", c.ID).Scan(&raw)
			must(e)
			if len(raw) > 0 {
				var result runtimeagent.Result
				must(json.Unmarshal(raw, &result))
				fmt.Printf("M09-PROCESS-RESULT operation=%s code=%s\n", operation, result.Code)
				if result.Code != "ok" {
					must(runtimeagent.ErrDenied)
				}
				if operation == "probe" && result.Inventory == nil {
					must(runtimeagent.ErrDenied)
				}
				if operation == "create" && f.Scenario == "agent-restart" {
					fmt.Println("M09-PROCESS-REQUEST restart-agent")
					time.Sleep(3 * time.Second)
				}
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	fmt.Println("M09-PROCESS-COMPLETE scope=real-M07-stateless-lifecycle-only")
}
func enroll() {
	if os.Geteuid() != 0 {
		must(runtimeagent.ErrDenied)
	}
	_, e := os.Stat("/etc/m09-disposable-guest")
	must(e)
	p, e := runtimehost.Load()
	must(e)
	var entries []runtimeisolation.Enrollment
	for _, app := range p.Apps {
		v, e := runtimeisolation.ReadEnrollment(app.ID)
		must(e)
		entries = append(entries, v)
	}
	raw, e := json.Marshal(entries)
	must(e)
	fmt.Println("M09-PROCESS-ENROLLMENTS", string(raw))
}
func main() {
	if len(os.Args) == 2 && os.Args[1] == "operator" {
		operator()
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "enroll" {
		enroll()
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "prepare" {
		generate(os.Args[2])
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "drive" {
		drive()
		return
	}
	must(runtimeagent.ErrDenied)
}
