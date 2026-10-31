package storage

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"dev-orchestrator/internal/artifacts"
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/policy"
	"dev-orchestrator/internal/runtimeagent"
	"dev-orchestrator/internal/runtimeauthority"
)

type runtimeFixture struct {
	buildPolicy       contracts.BuildPolicy
	store             *Store
	path              string
	command           runtimeagent.Command
	peer              artifacts.RuntimePeer
	keys              map[string]ed25519.PublicKey
	key, inventoryKey ed25519.PrivateKey
	approvalUntil     time.Time
}

func runtimeSetup(t *testing.T) *runtimeFixture {
	t.Helper()
	ctx := context.Background()
	s, path := testStore(t)
	i := buildIntent(t, s, true)
	clone, err := s.CloneReady(ctx, i.Job.Clone)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.BeginBuild(ctx, i); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordBuildExport(ctx, i, buildReceipt(i)); err != nil {
		t.Fatal(err)
	}
	result := admitted(i)
	result.Metadata = &contracts.ImageMetadata{User: "1000:1000", Platform: "linux/amd64", Command: []string{"/web"}}
	if err = s.RecordArtifact(ctx, i, result); err != nil {
		t.Fatal(err)
	}
	image := "registry.example.org/apps/web@" + result.ImageDigest
	if s.SetRuntimeScanPolicy(ctx, i.Job.Policy) != nil {
		t.Fatal("current scan policy")
	}
	admission, err := s.EnrollRuntimeImage(ctx, i, image)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := policy.Finalize(*clone.Plan, policy.Context{AppID: appID, DeploymentID: deploymentID, SHA: i.Job.SHA, ContextID: i.Job.ContextID, BuiltImages: map[string]string{"web": image}, Ingress: contracts.Ingress{Service: "web", Port: 8080, HealthPath: "/health"}}, runtimeResolver{map[string]policy.Admission{image: admission}})
	if err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ipub, ikey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.EnrollRuntimeWorker(ctx, RuntimeWorker{WorkerID: actorID, Incarnation: correlationID, LeaseUntil: time.Now().Add(time.Minute), InventoryKey: ipub}); err != nil {
		t.Fatal(err)
	}
	peer := artifacts.RuntimePeer{URI: "spiffe://tap/runtime-agent/" + actorID, CertificateSHA256: strings.Repeat("a", 64)}
	if err = s.EnrollRuntimeCertificate(ctx, actorID, correlationID, peer.CertificateSHA256, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err = s.EnrollRuntimeBackend(ctx, actorID, correlationID, appID, contracts.Digest([]byte("backend"))); err != nil {
		t.Fatal(err)
	}
	command := runtimeagent.Command{Version: 3, ID: userID, WorkerID: actorID, Incarnation: correlationID, AppID: appID, DeploymentID: deploymentID, Generation: 1, Operation: "create", KeyID: "controller", Nonce: strings.Repeat("b", 64), ExpiresAt: time.Now().UTC().Add(4 * time.Minute).Format(time.RFC3339Nano), SpecHash: policy.SpecHash(spec), PolicyHash: policy.Hash(), Spec: &spec}
	if command.Sign(key) != nil {
		t.Fatal("sign")
	}
	return &runtimeFixture{store: s, path: path, command: command, peer: peer, keys: map[string]ed25519.PublicKey{"controller": pub}, key: key, inventoryKey: ikey, approvalUntil: time.Now().Add(30 * time.Minute), buildPolicy: i.Job.Policy}
}
func (f *runtimeFixture) approve(t *testing.T) {
	t.Helper()
	if err := f.store.IssueRuntimeApproval(context.Background(), f.command.WorkerID, f.command.Incarnation, f.command.Generation, *f.command.Spec, f.approvalUntil); err != nil {
		t.Fatal(err)
	}
	if f.store.QueueRuntimeCommand(context.Background(), f.command, f.keys) != nil {
		t.Fatal("queue approved command")
	}
}
func TestRuntimeDurableAuthorityAndQueue(t *testing.T) {
	ctx := context.Background()
	f := runtimeSetup(t)
	if _, err := f.store.RuntimeGrant(ctx, f.peer, f.command); err == nil {
		t.Fatal("admission implicitly approved")
	}
	f.approve(t)
	f.approve(t)
	grant, err := f.store.RuntimeGrant(ctx, f.peer, f.command)
	if err != nil || !grant.Matches(time.Now(), f.command) {
		t.Fatal("current approval", err)
	}
	service := f.command.Spec.Services[0]
	claim := artifacts.RuntimeClaim{WorkerID: f.command.WorkerID, Incarnation: f.command.Incarnation, AppID: appID, DeploymentID: deploymentID, Generation: 1, SpecHash: f.command.SpecHash, PolicyHash: policy.Hash(), AdmissionID: service.AdmissionID, Image: service.Image}
	object, err := f.store.AuthorizeRuntime(ctx, f.peer, claim)
	if err != nil || object != grant.Images[0].Object {
		t.Fatal("artifact binding", err)
	}
	if err = f.store.QueueRuntimeCommand(ctx, f.command, f.keys); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 2; n++ {
		c, err := f.store.RuntimePoll(ctx, f.peer, runtimeauthority.PollRequest{WorkerID: actorID, Incarnation: correlationID})
		if err != nil || c == nil || c.Hash() != f.command.Hash() {
			t.Fatal("durable delivery", err)
		}
	}
	result := runtimeagent.Result{CommandID: f.command.ID, Code: "ok", State: "created"}
	for n := 0; n < 2; n++ {
		c, err := f.store.RuntimePoll(ctx, f.peer, runtimeauthority.PollRequest{WorkerID: actorID, Incarnation: correlationID, Result: &result})
		if err != nil || c != nil {
			t.Fatal("idempotent result", err)
		}
	}
	f.store.Close()
	f.store, err = Open(ctx, f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.store.Close()
	if _, err = f.store.AuthorizeRuntime(ctx, f.peer, claim); err != nil {
		t.Fatal("authority lost after restart", err)
	}
	if _, err = f.store.RuntimeGrant(ctx, f.peer, f.command); err == nil {
		t.Fatal("completed command resumed after ledger loss")
	}
	result.Code = "denied"
	if _, err = f.store.RuntimePoll(ctx, f.peer, runtimeauthority.PollRequest{WorkerID: actorID, Incarnation: correlationID, Result: &result}); err == nil {
		t.Fatal("conflicting result")
	}
}
func TestRuntimeCurrentStateDenials(t *testing.T) {
	for _, scenario := range []string{"worker", "incarnation", "certificate", "certificate-revoked", "worker-revoked", "approval-revoked", "image-revoked", "scan-policy", "app", "deployment", "generation", "policy", "spec", "disabled-app", "cancelled-deployment", "newer-submission", "source", "plan"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			f := runtimeSetup(t)
			defer f.store.Close()
			if scenario != "source" && scenario != "plan" {
				f.approve(t)
			}
			p, c := f.peer, f.command
			switch scenario {
			case "worker":
				c.WorkerID = userID
			case "incarnation":
				c.Incarnation = userID
			case "certificate":
				p.CertificateSHA256 = strings.Repeat("c", 64)
			case "certificate-revoked":
				if f.store.RevokeRuntimeCertificate(ctx, p.CertificateSHA256) != nil {
					t.Fatal("revoke")
				}
			case "worker-revoked":
				if f.store.RevokeRuntimeWorker(ctx, c.WorkerID) != nil {
					t.Fatal("revoke")
				}
			case "approval-revoked":
				if f.store.RevokeRuntimeApproval(ctx, c.AppID, c.Generation) != nil {
					t.Fatal("revoke")
				}
			case "image-revoked":
				if f.store.RevokeRuntimeImage(ctx, c.Spec.Services[0].AdmissionID) != nil {
					t.Fatal("revoke")
				}
			case "scan-policy":
				updated := f.buildPolicy
				updated.ScannerDigest = contracts.Digest([]byte("updated-scanner"))
				if f.store.SetRuntimeScanPolicy(ctx, updated) != nil {
					t.Fatal("set scan policy")
				}
			case "app":
				c.AppID = userID
			case "deployment":
				c.DeploymentID = userID
			case "generation":
				c.Generation++
			case "policy":
				c.PolicyHash = contracts.Digest([]byte("obsolete"))
			case "spec":
				c.SpecHash = contracts.Digest([]byte("other"))
			case "disabled-app":
				execSQL(t, f.store, "UPDATE applications SET state='disabled' WHERE id=?", appID)
			case "cancelled-deployment":
				execSQL(t, f.store, "UPDATE deployments SET state='CANCELLED' WHERE id=?", deploymentID)
			case "newer-submission":
				execSQL(t, f.store, "UPDATE applications SET deployment_generation=2 WHERE id=?", appID)
			case "source":
				spec := *c.Spec
				spec.SHA = strings.Repeat("d", 40)
				if f.store.IssueRuntimeApproval(ctx, c.WorkerID, c.Incarnation, 1, spec, f.approvalUntil) == nil {
					t.Fatal("foreign source approved")
				}
				return
			case "plan":
				spec := *c.Spec
				spec.PlanHash = contracts.Digest([]byte("other-plan"))
				if f.store.IssueRuntimeApproval(ctx, c.WorkerID, c.Incarnation, 1, spec, f.approvalUntil) == nil {
					t.Fatal("wrong plan approved")
				}
				return
			}
			if _, err := f.store.RuntimeGrant(ctx, p, c); err == nil {
				t.Fatal("stale/unbound grant")
			}
		})
	}
}
func TestRuntimeSignedInventoryAcknowledgment(t *testing.T) {
	ctx := context.Background()
	f := runtimeSetup(t)
	defer f.store.Close()
	c := f.command
	c.Spec = nil
	c.Operation = "probe"
	if c.Sign(f.key) != nil {
		t.Fatal("sign")
	}
	if f.store.QueueRuntimeCommand(ctx, c, f.keys) != nil {
		t.Fatal("queue")
	}
	now := time.Now().UTC()
	inv := runtimeagent.Inventory{Version: 2, WorkerID: actorID, Incarnation: correlationID, AppID: appID, BackendHash: contracts.Digest([]byte("backend")), Challenge: c.Nonce, MeasuredAt: now, ExpiresAt: now.Add(time.Minute), TemplateHash: contracts.Digest([]byte("template")), Kernel: "kernel", Engine: "engine", API: "1.47", DaemonID: "daemon", PolicyHash: policy.Hash(), Controls: policy.RequiredControls()}
	if inv.Sign(f.inventoryKey) != nil {
		t.Fatal("sign inventory")
	}
	r := runtimeagent.Result{CommandID: c.ID, Code: "ok", Inventory: &inv}
	bad := inv
	bad.AppID = userID
	r.Inventory = &bad
	if _, err := f.store.RuntimePoll(ctx, f.peer, runtimeauthority.PollRequest{WorkerID: actorID, Incarnation: correlationID, Result: &r}); err == nil {
		t.Fatal("tampered app report")
	}
	r.Inventory = &inv
	if next, err := f.store.RuntimePoll(ctx, f.peer, runtimeauthority.PollRequest{WorkerID: actorID, Incarnation: correlationID, Result: &r}); err != nil || next != nil {
		t.Fatal("signed report", err)
	}
}

func TestRuntimeEnrollmentRejectsChangedBuildBinding(t *testing.T) {
	f := runtimeSetup(t)
	ctx := context.Background()
	var raw string
	if err := f.store.db.QueryRow("SELECT job_json FROM build_attempts WHERE stage='admitted'").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var job contracts.BuildJob
	if err := json.Unmarshal([]byte(raw), &job); err != nil {
		t.Fatal(err)
	}
	// Completed rows remain immutable even to a timestamp rewrite. A caller
	// cannot turn a changed job into either runtime admission or build authority.
	job.ExpiresAt = time.Now().Add(-time.Minute).UTC()
	job.Clone.ExpiresAt = job.ExpiresAt
	encoded, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.db.Exec("UPDATE build_attempts SET job_json=?,job_hash=?,expires_at=? WHERE job_id=?", string(encoded), buildHash(job), job.ExpiresAt.UnixNano(), job.Clone.JobID); err == nil {
		t.Fatal("completed build binding changed")
	}
	intent := BuildIntent{Job: job, Actor: Actor{Kind: "controller", ID: actorID}, CorrelationID: correlationID}
	if _, err = f.store.EnrollRuntimeImage(ctx, intent, f.command.Spec.Services[0].Image); err == nil {
		t.Fatal("changed historical binding enrolled")
	}
	if err = f.store.BeginBuild(ctx, intent); err == nil {
		t.Fatal("historical admission reauthorized a build")
	}
	if _, err = f.store.AdmittedArtifact(ctx, intent); err == nil {
		t.Fatal("M07 live build fence was weakened")
	}
	intent.Job.SHA = strings.Repeat("f", 40)
	if _, err = f.store.EnrollRuntimeImage(ctx, intent, f.command.Spec.Services[0].Image); err == nil {
		t.Fatal("changed historical job accepted")
	}
}

func TestRuntimeGrantKeepsStrictBoundWithSmallClockOffset(t *testing.T) {
	f := runtimeSetup(t)
	ctx := context.Background()
	f.approve(t)
	grant, err := f.store.RuntimeGrant(ctx, f.peer, f.command)
	if err != nil {
		t.Fatal(err)
	}
	observerNow := time.Now().Add(-500 * time.Millisecond)
	if !grant.Matches(observerNow, f.command) {
		t.Fatal("fresh grant rejected for a small independent VM clock offset")
	}
	grant.ExpiresAt = observerNow.Add(6 * time.Second)
	if grant.Matches(observerNow, f.command) {
		t.Fatal("protocol expiry ceiling weakened")
	}
}
