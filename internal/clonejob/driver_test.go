package clonejob

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/domain"
	"dev-orchestrator/internal/provisioner"
	"dev-orchestrator/internal/storage"
)

const jobID = "11111111-1111-4111-8111-111111111111"
const deploymentID = "22222222-2222-4222-8222-222222222222"
const appID = "33333333-3333-4333-8333-333333333333"
const userID = "44444444-4444-4444-8444-444444444444"
const branchID = "55555555-5555-4555-8555-555555555555"

func driverFixture(t *testing.T, scenario string) (*storage.Store, storage.CloneIntent) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "metadata.db")
	s, e := storage.Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	queries := []string{
		`INSERT INTO users(id,username,password_hash,created_at,updated_at) VALUES('` + userID + `','admin','fixture',0,0)`,
		`INSERT INTO applications(id,slug,display_name,owner_id,created_at,updated_at) VALUES('` + appID + `','fixture','Fixture','` + userID + `',0,0)`,
		`INSERT INTO git_repositories(id,canonical_url,allowed_origin,owner_id,created_at) VALUES('` + jobID + `','https://ok.m06.example/` + scenario + `.git','ok.m06.example','` + userID + `',0)`,
		`INSERT INTO git_branches(id,repository_id,ref_name) VALUES('` + branchID + `','` + jobID + `','main')`,
	}
	for _, q := range queries {
		if _, e = db.ExecContext(ctx, q); e != nil {
			t.Fatal(e)
		}
	}
	if _, _, e = s.Create(ctx, storage.CreateDeployment{ID: deploymentID, AppID: appID, BranchID: branchID, SubmittedBy: userID, IdempotencyKey: "fixture-key-00001", RequestHash: strings.Repeat("a", 64), CorrelationID: jobID}); e != nil {
		t.Fatal(e)
	}
	c := storage.Transition{DeploymentID: deploymentID, ExpectedState: domain.Submitted, ExpectedVersion: 1, ExpectedGeneration: 1, To: domain.Validating, Reason: storage.ReasonValidated, Actor: storage.Actor{Kind: "controller", ID: userID}, CorrelationID: jobID}
	if _, e = s.Advance(ctx, c); e != nil {
		t.Fatal(e)
	}
	c.ExpectedState = domain.Validating
	c.ExpectedVersion = 2
	c.To = domain.Cloning
	if _, e = s.Advance(ctx, c); e != nil {
		t.Fatal(e)
	}
	p := contracts.ClonePolicy{Version: 1, Hosts: []string{"ok.m06.example"}, Limits: contracts.DefaultCloneLimits()}
	j := contracts.CloneJob{Version: 1, JobID: jobID, DeploymentID: deploymentID, LeaseID: jobID, Attempt: 1, Generation: 1, ExpiresAt: time.Now().UTC().Add(90 * time.Second), TemplateDigest: "sha256:" + strings.Repeat("a", 64), Policy: p, PolicyHash: p.Hash(), RepositoryURL: "https://ok.m06.example/" + scenario + ".git", Branch: "main", ConfigPath: "Dockerfile", BuildContext: "."}
	return s, storage.CloneIntent{Job: j, ExpectedVersion: 3, Actor: storage.Actor{Kind: "controller", ID: userID}, CorrelationID: jobID}
}

type fakeBackend struct {
	frames           []contracts.CloneResult
	created, cleaned bool
	failCleanup      bool
}

func (b *fakeBackend) Controls() provisioner.Controls {
	return provisioner.Controls{PinnedTemplate: true, KVMIsolation: true, ExternalQuotas: true, IsolatedNetwork: true, HostDeadline: true, LateStartFence: true, OwnershipChecks: true, ConfirmedCleanup: true}
}
func (b *fakeBackend) Create(context.Context, provisioner.Machine) error {
	b.created = true
	return nil
}
func (b *fakeBackend) CloneResults(context.Context, provisioner.Machine) ([]contracts.CloneResult, error) {
	return b.frames, nil
}
func (b *fakeBackend) Cleanup(context.Context, provisioner.Machine) (provisioner.CleanupResult, error) {
	b.cleaned = true
	if b.failCleanup {
		return provisioner.CleanupResult{}, provisioner.ErrCleanup
	}
	return provisioner.CleanupResult{VMAbsent: true, ArtifactsAbsent: true, StartFenced: true}, nil
}
func machineFor(j contracts.CloneJob) provisioner.Machine {
	return provisioner.Machine{Lease: provisioner.Lease{JobID: j.JobID, CommandID: j.LeaseID, DeploymentID: j.DeploymentID, Template: provisioner.Template{ID: "build-m06-v1", Digest: j.TemplateDigest}, ProfileID: "build-small-v1", ExpiresAt: j.ExpiresAt}, Budget: provisioner.SmallBudget(), OwnershipProof: strings.Repeat("a", 64)}
}

func TestDriverFencesHandoffAndConfirmsCleanup(t *testing.T) {
	for _, scenario := range []string{"success", "denied", "cancelled", "cleanup-failure", "success-without-resolution", "policy-timeout"} {
		t.Run(scenario, func(t *testing.T) {
			s, i := driverFixture(t, "good")
			if scenario == "policy-timeout" {
				i.Job.Policy.Limits.Seconds = 1
				i.Job.PolicyHash = i.Job.Policy.Hash()
			}
			b := &fakeBackend{}
			r := contracts.NewCloneResult(i.Job)
			r.SHA = strings.Repeat("b", 40)
			r.Outcome = "resolved"
			if scenario != "cancelled" && scenario != "policy-timeout" {
				b.frames = append(b.frames, r)
			}
			r.Outcome = "denied"
			if scenario == "success" || scenario == "success-without-resolution" {
				r.Outcome = "success"
				r.ContextID = strings.Repeat("c", 64)
				r.Entries = 1
			}
			if scenario != "cancelled" && scenario != "policy-timeout" {
				b.frames = append(b.frames, r)
			}
			if scenario == "success-without-resolution" {
				b.frames = b.frames[1:]
			}
			b.failCleanup = scenario == "cleanup-failure"
			d := Driver{Store: s, Backend: b}
			timeout := 100 * time.Millisecond
			if scenario == "policy-timeout" {
				timeout = 5 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			started := time.Now()
			result, e := d.Execute(ctx, machineFor(i.Job), i)
			if scenario == "success" {
				if e != nil || result.SHA != r.SHA || b.cleaned {
					t.Fatal(result, e, b.cleaned)
				}
				if e = d.Release(machineFor(i.Job), i.Job); e != nil || !b.cleaned {
					t.Fatal(e)
				}
			} else if e == nil || !b.cleaned {
				t.Fatal("invalid handoff", e, b.cleaned)
			}
			if scenario == "policy-timeout" {
				if !errors.Is(e, context.DeadlineExceeded) || time.Since(started) > 4*time.Second {
					t.Fatal("clone policy deadline not enforced independently", e)
				}
				messages, e := s.PendingCloneOutbox(context.Background(), 10)
				if e != nil || len(messages) != 1 || messages[0].Type != "clone.timeout" {
					t.Fatal("timeout not durably recorded", messages, e)
				}
			}
			if scenario == "cleanup-failure" && !errors.Is(e, provisioner.ErrCleanup) {
				t.Fatal("uncertain cleanup hidden", e)
			}
		})
	}
}

func TestRealCloneDurableAdapter(t *testing.T) {
	if os.Getenv("M06_DISPOSABLE_HOST") != "YES-I-AUTHORIZE-CLONE-LAB" {
		t.Skip("requires approved disposable KVM lab")
	}
	for _, scenario := range []string{"good", "attributes"} {
		t.Run(scenario, func(t *testing.T) {
			c, e := provisioner.LoadLinuxConfig(os.Getenv("M04_HOST_CONFIG"))
			if e != nil {
				t.Fatal(e)
			}
			backend, e := provisioner.NewLinuxBackend(c)
			if e != nil {
				t.Fatal(e)
			}
			b, ok := backend.(provisioner.CloneBackend)
			if !ok {
				t.Fatal("clone backend unavailable")
			}
			s, i := driverFixture(t, scenario)
			i.Job.TemplateDigest = c.Digest
			// Job identity is unique across real runs; DB deployment identity is local.
			id := time.Now().UTC().Format("150405.000000000")
			i.Job.JobID = jobID[:24] + strings.ReplaceAll(id, ".", "")[:12]
			i.Job.LeaseID = i.Job.JobID
			m := machineFor(i.Job)
			m.Lease.Template = provisioner.Template{ID: c.TemplateID, Digest: c.Digest}
			d := Driver{Store: s, Backend: b}
			defer func() {
				if e := d.Release(m, i.Job); e != nil {
					t.Error(e)
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			r, e := d.Execute(ctx, m, i)
			if scenario == "good" {
				if e != nil || r.Outcome != "success" {
					t.Fatal(r, e)
				}
				ready, e := s.CloneReady(ctx, i.Job)
				if e != nil || ready.SHA != r.SHA {
					t.Fatal(ready, e)
				}
				queue, e := s.PendingCloneOutbox(ctx, 10)
				if e != nil || len(queue) != 2 {
					t.Fatal(queue, e)
				}
			} else {
				if e == nil {
					t.Fatal("unsupported attributes accepted")
				}
				if _, e = s.CloneReady(ctx, i.Job); e == nil {
					t.Fatal("failed context handed off")
				}
				messages, e := s.PendingCloneOutbox(ctx, 10)
				if e != nil || len(messages) != 2 || messages[0].Result.SHA == "" || messages[0].Result.SHA != messages[1].Result.SHA || messages[1].Result.Outcome != "denied" {
					t.Fatal("failed context lost durable SHA", messages, e)
				}
			}
			t.Logf("durable clone outcome=%s error=%v", r.Outcome, e)
		})
	}
}
