package runtimeagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/policy"
)

const identity = "11111111-1111-4111-8111-111111111111"
const other = "22222222-2222-4222-8222-222222222222"
const image = "registry.example.org/apps/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type resolver struct{}

func (resolver) Image(s string) (policy.Admission, error) {
	return policy.Admission{ID: "admitted", Image: s, PolicyHash: policy.Hash(), Platform: "linux/amd64", User: "1000:1000"}, nil
}
func (resolver) Volume(string, string) (string, error) { return identity, nil }
func (resolver) Secret(string, string, string) error   { return nil }

type authority struct{ denied bool }

func (a *authority) Current(context.Context, Command) error {
	if a.denied {
		return ErrDenied
	}
	return nil
}
func (a *authority) Valid(context.Context, string, string) error {
	if a.denied {
		return ErrDenied
	}
	return nil
}

type fakeEngine struct {
	creates, prepares, stops, removes, probes int
	unsupported, fail                         bool
	before                                    func()
	logs                                      []byte
}

func (f *fakeEngine) Probe(context.Context) (Inventory, error) {
	f.probes++
	if f.unsupported {
		return Inventory{}, ErrUnsupported
	}
	return inventory(), nil
}
func (f *fakeEngine) Prepare(_ context.Context, _ Command, check func() error) error {
	f.prepares++
	return check()
}
func (f *fakeEngine) Create(_ context.Context, _ Command, check func() error) error {
	f.creates++
	if f.before != nil {
		f.before()
	}
	if f.fail {
		return errors.New("sensitive raw engine error")
	}
	return check()
}
func (f *fakeEngine) Inspect(context.Context, Command) (string, error) { return "running", nil }
func (f *fakeEngine) Logs(context.Context, Command) ([]byte, error)    { return f.logs, nil }
func (f *fakeEngine) Stop(_ context.Context, _ Command, check func() error) error {
	f.stops++
	return check()
}
func (f *fakeEngine) Remove(_ context.Context, _ Command, check func() error) error {
	f.removes++
	return check()
}
func inventory() Inventory {
	now := time.Now().UTC()
	return Inventory{Version: 1, WorkerID: identity, Incarnation: identity, Challenge: strings.Repeat("a", 64), MeasuredAt: now, ExpiresAt: now.Add(time.Minute), TemplateHash: contracts.Digest([]byte("template")), Kernel: "kernel", Engine: "engine", API: "1.47", DaemonID: "daemon", PolicyHash: policy.Hash(), Controls: policy.RequiredControls()}
}
func spec() contracts.RuntimeSpecV2 {
	return contracts.RuntimeSpecV2{Version: 2, Profile: policy.Profile, PolicyHash: policy.Hash(), AppID: identity, DeploymentID: identity, SHA: strings.Repeat("a", 40), ContextID: strings.Repeat("b", 64), PlanHash: contracts.Digest([]byte("plan")), Services: []contracts.RuntimeServiceV2{{Name: "web", Image: image, AdmissionID: "admitted", UID: 1000, GID: 1000, Command: []string{"/web"}, Expose: []int{8080}, Resources: policy.Defaults()}}, Ingress: contracts.Ingress{Service: "web", Port: 8080, HealthPath: "/health"}}
}
func command() Command {
	s := spec()
	return Command{Version: 3, Operation: "create", ID: identity, WorkerID: identity, Incarnation: identity, AppID: identity, DeploymentID: identity, Generation: 1, Nonce: strings.Repeat("a", 64), KeyID: "controller", ExpiresAt: time.Now().UTC().Add(4 * time.Minute).Format(time.RFC3339Nano), PolicyHash: policy.Hash(), SpecHash: policy.SpecHash(s), Spec: &s}
}

type fixture struct {
	agent           *Agent
	ledger          *Ledger
	engine          *fakeEngine
	approval, lease *authority
	key             ed25519.PrivateKey
	path            string
}

func setup(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("chmod")
	}
	p := filepath.Join(dir, "agent.db")
	l, e := OpenLedger(context.Background(), p, identity, identity)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	f := &fixture{ledger: l, engine: &fakeEngine{}, approval: &authority{}, lease: &authority{}, key: key, path: p}
	f.agent, e = New(Config{WorkerID: identity, Incarnation: identity, Keys: map[string]ed25519.PublicKey{"controller": pub}, Resolver: resolver{}, Approval: f.approval, Lease: f.lease, Engine: f.engine, Ledger: l})
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func (f *fixture) execute(c Command) (Result, error) {
	if e := c.Sign(f.key); e != nil {
		return Result{}, e
	}
	return f.agent.Execute(context.Background(), c)
}
func follow(c Command, op string, n int) Command {
	c.Operation = op
	c.Spec = nil
	c.Target = c.ID
	c.ID = fmt.Sprintf("33333333-3333-4333-8333-%012d", n)
	c.Nonce = fmt.Sprintf("%064x", n+10)
	return c
}

func TestSignedLifecycleAndDurableRetry(t *testing.T) {
	f := setup(t)
	c := command()
	r, e := f.execute(c)
	if e != nil || r.Code != "ok" {
		t.Fatal(r, e)
	}
	if _, e = f.execute(c); e != nil || f.engine.creates != 1 {
		t.Fatal("duplicate mutated", e)
	}
	if _, e = f.execute(follow(c, "inspect", 1)); e != nil {
		t.Fatal(e)
	}
	if _, e = f.execute(follow(c, "stop", 2)); e != nil {
		t.Fatal(e)
	}
	if _, e = f.execute(follow(c, "remove", 3)); e != nil || f.engine.stops != 1 || f.engine.removes != 1 {
		t.Fatal(e)
	}
	if f.ledger.Close() != nil {
		t.Fatal("close")
	}
	l, e := OpenLedger(context.Background(), f.path, identity, identity)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	f.agent.config.Ledger = l
	if _, e = f.execute(c); e != nil || f.engine.creates != 1 {
		t.Fatal("restart repeated mutation", e)
	}
}
func TestSignatureFieldTampering(t *testing.T) {
	f := setup(t)
	c := command()
	if c.Sign(f.key) != nil {
		t.Fatal("sign")
	}
	cases := map[string]func(*Command){"version": func(c *Command) { c.Version = 2 }, "operation": func(c *Command) { c.Operation = "prepare" }, "id": func(c *Command) { c.ID = other }, "worker": func(c *Command) { c.WorkerID = other }, "incarnation": func(c *Command) { c.Incarnation = other }, "app": func(c *Command) { c.AppID = other }, "deployment": func(c *Command) { c.DeploymentID = other }, "generation": func(c *Command) { c.Generation++ }, "nonce": func(c *Command) { c.Nonce = strings.Repeat("b", 64) }, "key": func(c *Command) { c.KeyID = "rotated" }, "expiry": func(c *Command) { c.ExpiresAt = time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano) }, "policy": func(c *Command) { c.PolicyHash = contracts.Digest([]byte("other")) }, "spec-hash": func(c *Command) { c.SpecHash = contracts.Digest([]byte("other")) }, "target": func(c *Command) { c.Target = other }, "log-limit": func(c *Command) { c.LogLimit = 1 }, "signature": func(c *Command) { c.Signature = strings.Repeat("A", 86) + "==" }, "spec": func(c *Command) { s := *c.Spec; s.SHA = strings.Repeat("c", 40); c.Spec = &s }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			bad := c
			change(&bad)
			if _, e := f.agent.Execute(context.Background(), bad); e == nil {
				t.Fatal("tampering accepted")
			}
		})
	}
	if f.engine.creates != 0 || f.engine.probes != 0 {
		t.Fatal("invalid signature reached engine")
	}
}
func TestStrictDecoder(t *testing.T) {
	c := command()
	b, _ := json.Marshal(c)
	for name, raw := range map[string]string{"unknown": strings.Replace(string(b), `"version":3`, `"version":3,"unknown":false`, 1), "duplicate": strings.Replace(string(b), `"version":3`, `"version":3,"version":3`, 1), "case-alias": strings.Replace(string(b), `"version"`, `"Version"`, 1), "float": strings.Replace(string(b), `"version":3`, `"version":3.0`, 1), "trailing": string(b) + `{}`, "oversize": strings.Repeat(" ", contracts.MaxPlanBytes) + string(b)} {
		t.Run(name, func(t *testing.T) {
			if _, e := Decode(strings.NewReader(raw)); e == nil {
				t.Fatal("invalid JSON accepted")
			}
		})
	}
}
func TestSemanticAndAuthorizationDenials(t *testing.T) {
	cases := map[string]func(*fixture, *Command){"expired": func(_ *fixture, c *Command) {
		c.ExpiresAt = time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)
	}, "too-far": func(_ *fixture, c *Command) { c.ExpiresAt = time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano) }, "zero-generation": func(_ *fixture, c *Command) { c.Generation = 0 }, "root": func(_ *fixture, c *Command) { c.Spec.Services[0].UID = 0; c.SpecHash = policy.SpecHash(*c.Spec) }, "mount": func(_ *fixture, c *Command) {
		c.Spec.Services[0].Volumes = []contracts.Mount{{VolumeID: identity, Target: "/data"}}
		c.SpecHash = policy.SpecHash(*c.Spec)
	}, "secret": func(_ *fixture, c *Command) {
		c.Spec.Services[0].Secrets = []contracts.SecretReference{{ID: identity, Version: contracts.Digest([]byte("secret")), Target: "/run/secrets/password"}}
		c.SpecHash = policy.SpecHash(*c.Spec)
	}, "approval": func(f *fixture, _ *Command) { f.approval.denied = true }, "lease": func(f *fixture, _ *Command) { f.lease.denied = true }, "unknown-op": func(_ *fixture, c *Command) { c.Operation = "exec" }}
	for n, change := range cases {
		t.Run(n, func(t *testing.T) {
			f := setup(t)
			c := command()
			change(f, &c)
			if _, e := f.execute(c); e == nil {
				t.Fatal("accepted")
			}
			if f.engine.creates != 0 || f.engine.probes != 0 {
				t.Fatal("denial reached engine")
			}
		})
	}
}
func TestConcurrentReplayAndConflicts(t *testing.T) {
	f := setup(t)
	c := command()
	c.Sign(f.key)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := f.agent.Execute(context.Background(), c); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if f.engine.creates != 1 {
		t.Fatal("concurrent replay", f.engine.creates)
	}
	changed := c
	changed.Generation++
	if _, e := f.execute(changed); !errors.Is(e, ErrConflict) {
		t.Fatal("conflicting command", e)
	}
	changed = c
	changed.ID = other
	if _, e := f.execute(changed); e == nil {
		t.Fatal("nonce reuse")
	}
	changed = c
	changed.ID = other
	changed.Nonce = strings.Repeat("b", 64)
	if _, e := f.execute(changed); e == nil {
		t.Fatal("second create same generation")
	}
}
func TestGenerationFencesAndCleanup(t *testing.T) {
	f := setup(t)
	old := command()
	if _, e := f.execute(old); e != nil {
		t.Fatal(e)
	}
	newer := command()
	newer.ID = other
	newer.Generation = 2
	newer.Nonce = strings.Repeat("b", 64)
	if _, e := f.execute(newer); e != nil {
		t.Fatal(e)
	}
	stale := command()
	stale.ID = "44444444-4444-4444-8444-444444444444"
	stale.Nonce = strings.Repeat("c", 64)
	if _, e := f.execute(stale); e == nil {
		t.Fatal("stale create")
	}
	if _, e := f.execute(follow(old, "stop", 1)); e != nil {
		t.Fatal("old-generation cleanup denied", e)
	}
	wrong := follow(old, "remove", 2)
	wrong.AppID = other
	if _, e := f.execute(wrong); e == nil {
		t.Fatal("wrong app cleanup")
	}
}
func TestPendingIntentAndUncertainFailure(t *testing.T) {
	f := setup(t)
	c := command()
	c.Sign(f.key)
	if _, _, e := f.ledger.reserve(context.Background(), c); e != nil {
		t.Fatal(e)
	}
	if _, e := f.agent.Execute(context.Background(), c); !errors.Is(e, ErrUncertain) || f.engine.creates != 0 {
		t.Fatal("pending intent reexecuted", e)
	}
	d := command()
	d.ID = other
	d.Generation = 2
	d.Nonce = strings.Repeat("b", 64)
	f.engine.fail = true
	r, e := f.execute(d)
	if !errors.Is(e, ErrUncertain) || r.Code != "uncertain" {
		t.Fatal(r, e)
	}
	if _, e = f.execute(d); !errors.Is(e, ErrUncertain) || f.engine.creates != 1 {
		t.Fatal("uncertain retried", e)
	}
	raw, _ := json.Marshal(r)
	if bytes.Contains(raw, []byte("sensitive")) {
		t.Fatal("raw engine error leaked")
	}
}
func TestRevocationDuringCreate(t *testing.T) {
	f := setup(t)
	f.engine.before = func() { f.approval.denied = true }
	if _, e := f.execute(command()); !errors.Is(e, ErrUncertain) {
		t.Fatal("revoked candidate marked ready", e)
	}
}
func TestUnsupportedReadiness(t *testing.T) {
	f := setup(t)
	f.engine.unsupported = true
	if _, e := f.execute(command()); e == nil || f.engine.creates != 0 {
		t.Fatal("unsupported execution", e)
	}
}
func TestBoundedSanitizedLogs(t *testing.T) {
	f := setup(t)
	c := command()
	if _, e := f.execute(c); e != nil {
		t.Fatal(e)
	}
	log := follow(c, "logs", 1)
	log.LogLimit = 100
	f.engine.logs = []byte("hello\x1b[31m\xff\n")
	r, e := f.execute(log)
	if e != nil || strings.ContainsRune(r.Logs, '\x1b') || !strings.ContainsRune(r.Logs, '\uFFFD') {
		t.Fatal(r, e)
	}
	log = follow(c, "logs", 2)
	log.LogLimit = 1
	if _, e := f.execute(log); e == nil {
		t.Fatal("oversized logs")
	}
}
func TestLedgerIsolationAndRestartIdentity(t *testing.T) {
	f := setup(t)
	if l, e := OpenLedger(context.Background(), f.path, identity, identity); e == nil {
		l.Close()
		t.Fatal("two dispatchers")
	}
	if f.ledger.Close() != nil {
		t.Fatal("close")
	}
	if l, e := OpenLedger(context.Background(), f.path, identity, other); e == nil {
		l.Close()
		t.Fatal("identity rollback")
	}
	if os.Chmod(f.path, 0644) != nil {
		t.Fatal("chmod")
	}
	if l, e := OpenLedger(context.Background(), f.path, identity, identity); e == nil {
		l.Close()
		t.Fatal("public ledger")
	}
}
func TestInventorySignatureAndControls(t *testing.T) {
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	i := inventory()
	if i.Sign(key) != nil || i.Verify(time.Now(), identity, identity, i.Challenge, pub) != nil {
		t.Fatal("valid inventory")
	}
	if i.Verify(time.Now(), identity, identity, strings.Repeat("b", 64), pub) == nil {
		t.Fatal("wrong challenge")
	}
	bad := i
	bad.Controls.MAC = false
	if bad.Verify(time.Now(), identity, identity, bad.Challenge, pub) == nil {
		t.Fatal("missing MAC")
	}
	bad = i
	bad.Engine = "changed"
	if bad.Verify(time.Now(), identity, identity, bad.Challenge, pub) == nil {
		t.Fatal("tampered inventory")
	}
	if i.Verify(time.Now().Add(2*time.Minute), identity, identity, i.Challenge, pub) == nil {
		t.Fatal("expired inventory")
	}
}
func FuzzCommandDecode(f *testing.F) {
	b, _ := json.Marshal(command())
	f.Add(b)
	f.Add([]byte(`{"version":3,"version":2}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, e := DecodeBytes(b)
		if e != nil && e != ErrDenied {
			t.Fatal("nonclosed decode error")
		}
	})
}
