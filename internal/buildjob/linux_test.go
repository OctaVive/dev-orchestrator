//go:build linux

package buildjob

import (
	"bytes"
	"context"
	"database/sql"
	"dev-orchestrator/internal/artifacts"
	"dev-orchestrator/internal/clonejob"
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/domain"
	"dev-orchestrator/internal/provisioner"
	"dev-orchestrator/internal/storage"
	"encoding/json"
	"github.com/google/uuid"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const jobID = "11111111-1111-4111-8111-111111111111"
const deploymentID = "22222222-2222-4222-8222-222222222222"
const appID = "33333333-3333-4333-8333-333333333333"
const userID = "44444444-4444-4444-8444-444444444444"
const branchID = "55555555-5555-4555-8555-555555555555"

func pipelineFixture(t *testing.T, scenario string) (*storage.Store, storage.CloneIntent) {
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

func TestRealM07Pipeline(t *testing.T) {
	if os.Getenv("M07_DISPOSABLE_HOST") != "YES-I-AUTHORIZE-BUILD-LAB" {
		t.Skip("isolated M07 lab not enabled")
	}
	for _, scenario := range []string{"success", "build-timeout", "cancelled", "controller-loss", "scanner-timeout", "log-flood", "disk-exhaustion", "memory-exhaustion", "pid-exhaustion", "remote-source"} {
		t.Run(scenario, func(t *testing.T) { runM07Pipeline(t, scenario) })
	}
}
func runM07Pipeline(t *testing.T, scenario string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	repo := "build"
	if scenario == "remote-source" {
		repo = "build-remote"
	}
	if scenario == "controller-loss" || scenario == "build-timeout" {
		repo = "build-cpu"
	}
	if scenario == "log-flood" {
		repo = "build-flood"
	}
	if scenario == "disk-exhaustion" {
		repo = "build-disk"
	}
	if scenario == "memory-exhaustion" {
		repo = "build-memory"
	}
	if scenario == "pid-exhaustion" {
		repo = "build-pids"
	}
	s, ci := pipelineFixture(t, repo)
	bc, e := provisioner.LoadLinuxConfig(os.Getenv("M04_HOST_CONFIG"))
	if e != nil {
		t.Fatal(e)
	}
	backend, e := provisioner.NewLinuxBackend(bc)
	if e != nil {
		t.Fatal(e)
	}
	sc, e := provisioner.LoadLinuxConfig(os.Getenv("M07_INGEST_CONFIG"))
	if e != nil {
		t.Fatal(e)
	}
	scanner, e := provisioner.NewLinuxBackend(sc)
	if e != nil {
		t.Fatal(e)
	}
	tool, e := os.ReadFile(os.Getenv("M07_TRIVY"))
	if e != nil {
		t.Fatal(e)
	}
	lock, e := os.ReadFile(os.Getenv("M07_TOOLS_LOCK"))
	if e != nil {
		t.Fatal(e)
	}
	var pins struct {
		DB struct {
			SHA      string `json:"sha256"`
			Metadata struct {
				UpdatedAt time.Time `json:"UpdatedAt"`
			} `json:"metadata"`
		} `json:"vulnerability_database"`
	}
	if json.Unmarshal(lock, &pins) != nil {
		t.Fatal("pins")
	}
	policy := contracts.BuildPolicy{EgressPolicyHash: bc.EgressPolicyHash, UploadOrigin: "https://ingest.m06.example", Version: 1, BuildSeconds: 120, ScanSeconds: 180, Limits: contracts.DefaultArtifactLimits(), ScannerDigest: contracts.Digest(tool), DatabaseDigest: "sha256:" + pins.DB.SHA, DatabaseCreatedAt: pins.DB.Metadata.UpdatedAt, DatabaseMaxAgeSeconds: 172800}
	if scenario == "build-timeout" {
		policy.BuildSeconds = 1
	}
	if scenario == "controller-loss" {
		policy.BuildSeconds = 5
	}
	if scenario == "scanner-timeout" {
		policy.ScanSeconds = 10
	}
	if scenario == "disk-exhaustion" || scenario == "memory-exhaustion" || scenario == "pid-exhaustion" {
		policy.BuildSeconds = 20
	}
	ci.Job.JobID = uuid.NewString()
	ci.Job.LeaseID = ci.Job.JobID
	ci.Job.ExpiresAt = time.Now().UTC().Add(10 * time.Minute)
	ci.Job.TemplateDigest = bc.Digest
	ci.Job.Build = &contracts.BuildSettings{Policy: policy, Dockerfile: "Dockerfile"}
	m := provisioner.Machine{Lease: provisioner.Lease{JobID: ci.Job.JobID, CommandID: ci.Job.LeaseID, DeploymentID: ci.Job.DeploymentID, Template: provisioner.Template{ID: bc.TemplateID, Digest: bc.Digest}, ProfileID: "build-small-v1", CreatedAt: time.Now(), ExpiresAt: ci.Job.ExpiresAt}, Budget: provisioner.SmallBudget(), OwnershipProof: strings.Repeat("a", 64), Clone: &ci.Job}
	cloneDriver := clonejob.Driver{Store: s, Backend: backend.(provisioner.CloneBackend)}
	t.Cleanup(func() {
		if e := cloneDriver.Release(m, ci.Job); e != nil {
			t.Error(e)
		}
	})
	r, e := cloneDriver.Execute(ctx, m, ci)
	if e != nil {
		t.Fatal("clone", e)
	}
	j := contracts.BuildJob{Version: 1, Clone: ci.Job, SHA: r.SHA, ContextID: r.ContextID, Policy: policy, PolicyHash: policy.Hash(), Dockerfile: "Dockerfile", ExpiresAt: ci.Job.ExpiresAt}
	uploads := artifacts.NewClient(os.Getenv("M07_CONTROL"))
	driver := Driver{Store: s, Uploads: uploads, ArtifactRoot: os.Getenv("M07_ARTIFACT_ROOT"), Backend: tracedBackend{t: t, LinuxAdapter: LinuxAdapter{Builder: backend.(provisioner.BuildBackend), Scanner: scanner.(provisioner.IngestBackend), ScannerTemplate: provisioner.Template{ID: sc.TemplateID, Digest: sc.Digest}}}}
	i := storage.BuildIntent{Job: j, Actor: ci.Actor, CorrelationID: ci.CorrelationID}
	// Inspect host controls while the actual source/build VM is active.
	controls, e := exec.Command("/usr/bin/systemctl", "show", "orchestrator-build-"+m.Lease.JobID+".service", "--property=MemoryMax,TasksMax,CPUQuotaPerSecUSec,CapabilityBoundingSet").Output()
	if e != nil {
		t.Fatal(e)
	}
	text := string(controls)
	if !strings.Contains(text, "MemoryMax=4831838208") || !strings.Contains(text, "TasksMax=128") || !strings.Contains(text, "CPUQuotaPerSecUSec=2s") || !strings.Contains(text, "cap_kill") {
		t.Fatal("host quota drift", text)
	}
	if st, e := os.Stat(filepath.Join(bc.Root, m.Lease.JobID+".raw")); e != nil || st.Size() != 10<<30 {
		t.Fatal("disk cap", e)
	}
	canary := filepath.Join(bc.Root, "foreign-"+m.Lease.JobID)
	if e = os.WriteFile(canary, []byte("foreign-canary"), 0600); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		b, e := os.ReadFile(canary)
		if e != nil || string(b) != "foreign-canary" {
			t.Error("foreign resource changed")
		}
	})
	if scenario == "controller-loss" {
		if e = s.BeginBuild(ctx, i); e != nil {
			t.Fatal(e)
		}
		id, token, e := uploads.Issue(artifacts.Binding{JobID: j.Clone.JobID, DeploymentID: j.Clone.DeploymentID, Attempt: 1, Generation: 1}, j.Policy.Limits.UploadBytes, time.Now().Add(time.Minute))
		if e != nil {
			t.Fatal(e)
		}
		defer uploads.Revoke(id)
		if e = backend.(provisioner.BuildBackend).AuthorizeBuild(ctx, m, contracts.BuildAuthorization{Job: j, ObjectID: id, Token: token}); e != nil {
			t.Fatal(e)
		}
		deadline := time.Now().Add(12 * time.Second)
		stopped := false
		for time.Now().Before(deadline) {
			_, e = exec.Command("/usr/bin/systemctl", "is-active", "--quiet", "orchestrator-build-"+m.Lease.JobID+".service").Output()
			if e != nil {
				stopped = true
				break
			}
			if e = s.CheckIntegrity(ctx); e != nil {
				t.Fatal("management became unavailable", e)
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !stopped {
			out, _ := exec.Command("/usr/bin/systemctl", "show", "orchestrator-build-"+m.Lease.JobID+".service", "--property=MainPID", "--value").Output()
			pid := strings.TrimSpace(string(out))
			t.Log("supervisor PID", pid)
			entries, _ := os.ReadDir("/proc/" + pid + "/fdinfo")
			for _, entry := range entries {
				data, e := os.ReadFile("/proc/" + pid + "/fdinfo/" + entry.Name())
				if e == nil && bytes.Contains(data, []byte("clockid:")) {
					t.Log("timer info", string(data))
				}
			}
			data, _ := os.ReadFile("/sys/fs/cgroup/system.slice/orchestrator-build-" + m.Lease.JobID + ".service/cgroup.procs")
			t.Log("remaining processes", string(data))
			t.Fatal("host build deadline did not terminate guest without controller")
		}
		failure := contracts.ArtifactResult{Version: 1, JobID: j.Clone.JobID, DeploymentID: j.Clone.DeploymentID, Attempt: j.Clone.Attempt, Generation: j.Clone.Generation, PolicyHash: j.PolicyHash, Outcome: "timeout"}
		if e = s.RecordBuildFailure(ctx, i, failure); e != nil {
			t.Fatal("recovered timeout was not durable", e)
		}
		if e = cloneDriver.Release(m, ci.Job); e != nil {
			t.Fatal(e)
		}
		t.Log("external build deadline terminated guest; metadata remained available; recovery recorded timeout")
		return
	}
	if scenario == "cancelled" {
		timer := time.AfterFunc(500*time.Millisecond, cancel)
		defer timer.Stop()
	}
	result, e := driver.Execute(ctx, m, i)
	if scenario != "success" {
		if e == nil {
			t.Fatal("failure admitted", scenario)
		}
		fresh, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := s.AdmittedArtifact(fresh, i); err == nil {
			t.Fatal("failed artifact admitted")
		}
		d, err := s.Deployment(fresh, j.Clone.DeploymentID)
		if err != nil || d.State != domain.Failed && d.State != domain.Cancelled {
			t.Fatal("failure not durable", d, err, e)
		}
		t.Log("bounded failure with durable state", scenario, d.State)
		return
	}

	if e != nil {
		t.Fatal("build/ingest", e)
	}
	if result.Outcome != "admitted" || result.ArchiveDigest == result.ImageDigest {
		t.Fatal("digest semantics", result)
	}
	d, e := s.Deployment(ctx, j.Clone.DeploymentID)
	if e != nil || d.State != domain.Scanning {
		t.Fatal("premature approval", d, e)
	}
	t.Logf("commit=%s context=%s archive=%s image=%s report=%s sbom=%s", j.SHA, j.ContextID, result.ArchiveDigest, result.ImageDigest, result.ReportDigest, result.SBOMDigest)
	b, e := os.ReadFile(filepath.Join(os.Getenv("M07_ARTIFACT_ROOT"), strings.TrimPrefix(result.ArchiveDigest, "sha256:")))
	if e != nil || contracts.Digest(b) != result.ArchiveDigest {
		t.Fatal("promoted bytes", e)
	}
}

type tracedBackend struct {
	LinuxAdapter
	t *testing.T
}

func (b tracedBackend) Build(ctx context.Context, m provisioner.Machine, j contracts.BuildJob, g UploadGrant) error {
	e := b.LinuxAdapter.Build(ctx, m, j, g)
	b.t.Log("build stage", e)
	if e != nil {
		c, err := provisioner.LoadLinuxConfig(os.Getenv("M04_HOST_CONFIG"))
		if err == nil {
			f, err := os.Open(filepath.Join(c.Root, m.Lease.JobID+".raw"))
			if err == nil {
				defer f.Close()
				data := make([]byte, 49152)
				_, _ = f.ReadAt(data, 20971390*512)
				b.t.Log("fixture diagnostics", strings.TrimRight(string(data), "\x00"))
			}
		}
	}
	return e
}
func (b tracedBackend) Ingest(ctx context.Context, j contracts.BuildJob, r artifacts.Receipt) (contracts.ArtifactResult, error) {
	result, e := b.LinuxAdapter.Ingest(ctx, j, r)
	b.t.Log("ingest stage", result.Outcome, e)
	return result, e
}
