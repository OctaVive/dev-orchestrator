package storage

import (
	"context"
	"dev-orchestrator/internal/artifacts"
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/domain"
	"errors"
	"strings"
	"testing"
	"time"
)

func buildIntent(t *testing.T, s *Store) BuildIntent {
	t.Helper()
	ctx := context.Background()
	i := cloneIntent(t, s)
	p := contracts.BuildPolicy{EgressPolicyHash: strings.Repeat("a", 64), UploadOrigin: "https://ingest.example.com", Version: 1, BuildSeconds: 1200, ScanSeconds: 300, Limits: contracts.DefaultArtifactLimits(), ScannerDigest: contracts.Digest([]byte("tool")), DatabaseDigest: contracts.Digest([]byte("db")), DatabaseCreatedAt: time.Now().UTC().Add(-time.Hour), DatabaseMaxAgeSeconds: 172800}
	i.Job.Build = &contracts.BuildSettings{Policy: p, Dockerfile: "Dockerfile"}
	i.Job.ExpiresAt = time.Now().UTC().Add(25 * time.Minute)
	if e := s.BeginClone(ctx, i); e != nil {
		t.Fatal(e)
	}
	r := contracts.NewCloneResult(i.Job)
	r.SHA = strings.Repeat("b", 40)
	r.Outcome = "resolved"
	if e := s.RecordClone(ctx, i, r); e != nil {
		t.Fatal(e)
	}
	r.Outcome = "success"
	r.ContextID = strings.Repeat("c", 64)
	r.Entries = 1
	r.Bytes = 12
	if e := s.RecordClone(ctx, i, r); e != nil {
		t.Fatal(e)
	}

	j := contracts.BuildJob{Version: 1, Clone: i.Job, SHA: r.SHA, ContextID: r.ContextID, Policy: p, PolicyHash: p.Hash(), Dockerfile: "Dockerfile", ExpiresAt: i.Job.ExpiresAt}
	return BuildIntent{Job: j, Actor: i.Actor, CorrelationID: i.CorrelationID}
}
func buildReceipt(i BuildIntent) artifacts.Receipt {
	return artifacts.Receipt{ObjectID: strings.Repeat("d", 32), Digest: contracts.Digest([]byte("archive")), Bytes: 1024, Binding: artifacts.Binding{JobID: i.Job.Clone.JobID, DeploymentID: i.Job.Clone.DeploymentID, Attempt: i.Job.Clone.Attempt, Generation: i.Job.Clone.Generation}}
}
func admitted(i BuildIntent) contracts.ArtifactResult {
	return contracts.ArtifactResult{Version: 1, JobID: i.Job.Clone.JobID, DeploymentID: i.Job.Clone.DeploymentID, Attempt: i.Job.Clone.Attempt, Generation: i.Job.Clone.Generation, PolicyHash: i.Job.PolicyHash, ArchiveDigest: buildReceipt(i).Digest, ImageDigest: contracts.Digest([]byte("manifest")), ScannerDigest: i.Job.Policy.ScannerDigest, DatabaseDigest: i.Job.Policy.DatabaseDigest, ReportDigest: contracts.Digest([]byte("report")), SBOMDigest: contracts.Digest([]byte("sbom")), Outcome: "admitted"}
}
func TestBuildDurableAdmission(t *testing.T) {
	ctx := context.Background()
	s, path := testStore(t)
	i := buildIntent(t, s)
	if _, e := s.AdmittedArtifact(ctx, i); e == nil {
		t.Fatal("premature admission")
	}
	if e := s.BeginBuild(ctx, i); e != nil {
		t.Fatal(e)
	}
	if e := s.BeginBuild(ctx, i); e != nil {
		t.Fatal("idempotency", e)
	}
	r := admitted(i)
	if e := s.RecordArtifact(ctx, i, r); e == nil {
		t.Fatal("unexported admission")
	}
	if e := s.RecordBuildExport(ctx, i, buildReceipt(i)); e != nil {
		t.Fatal(e)
	}
	if e := s.RecordBuildExport(ctx, i, buildReceipt(i)); e != nil {
		t.Fatal("export retry", e)
	}
	if e := s.RecordArtifact(ctx, i, r); e != nil {
		t.Fatal(e)
	}
	if e := s.RecordArtifact(ctx, i, r); e != nil {
		t.Fatal("result replay", e)
	}
	s.Close()
	s, e := Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	got, e := s.AdmittedArtifact(ctx, i)
	if e != nil || got != r {
		t.Fatal(got, e)
	}
	d, e := s.Deployment(ctx, i.Job.Clone.DeploymentID)
	if e != nil || d.State != domain.Scanning {
		t.Fatal("admission became approval", d, e)
	}
	if n := scalar(t, s, "SELECT count(*) FROM build_outbox"); n != 3 {
		t.Fatal("outbox", n)
	}
	if n := scalar(t, s, "SELECT count(*) FROM audit_events WHERE action LIKE 'build.%' OR action LIKE 'scan.%'"); n != 3 {
		t.Fatal("audit", n)
	}
	if e = s.CheckIntegrity(ctx); e != nil {
		t.Fatal(e)
	}
	r.ImageDigest = contracts.Digest([]byte("conflict"))
	if e = s.RecordArtifact(ctx, i, r); !errors.Is(e, ErrConflict) {
		t.Fatal("conflicting result", e)
	}
}
func TestBuildTransactionFences(t *testing.T) {
	for _, name := range []string{"wrong-context", "wrong-sha", "rollback-start", "cancelled", "generation", "wrong-archive", "rollback-admission", "wrong-policy", "denied"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s, _ := testStore(t)
			i := buildIntent(t, s)
			switch name {
			case "wrong-context":
				i.Job.ContextID = strings.Repeat("f", 64)
				if e := s.BeginBuild(ctx, i); e == nil {
					t.Fatal("wrong context")
				}
				return
			case "wrong-sha":
				i.Job.SHA = strings.Repeat("f", 40)
				if e := s.BeginBuild(ctx, i); e == nil {
					t.Fatal("wrong sha")
				}
				return
			case "rollback-start":
				execSQL(t, s, `CREATE TRIGGER fail_build BEFORE INSERT ON build_events BEGIN SELECT RAISE(ABORT,'injected'); END`)
				if e := s.BeginBuild(ctx, i); e == nil {
					t.Fatal("not rolled back")
				}
				d, _ := s.Deployment(ctx, i.Job.Clone.DeploymentID)
				if d.State != domain.Cloning || scalar(t, s, "SELECT count(*) FROM build_attempts") != 0 {
					t.Fatal("partial commit")
				}
				return
			}
			if e := s.BeginBuild(ctx, i); e != nil {
				t.Fatal(e)
			}
			if e := s.RecordBuildExport(ctx, i, buildReceipt(i)); e != nil {
				t.Fatal(e)
			}
			r := admitted(i)
			switch name {
			case "cancelled":
				d, _ := s.Deployment(ctx, i.Job.Clone.DeploymentID)
				_, e := s.Advance(ctx, Transition{DeploymentID: d.ID, ExpectedState: d.State, ExpectedVersion: d.Version, ExpectedGeneration: d.Generation, To: domain.Cancelled, Reason: ReasonCancelled, Actor: i.Actor, CorrelationID: i.CorrelationID})
				if e != nil {
					t.Fatal(e)
				}
			case "generation":
				execSQL(t, s, "UPDATE deployments SET generation=generation+1 WHERE id=?", i.Job.Clone.DeploymentID)
			case "wrong-archive":
				r.ArchiveDigest = contracts.Digest([]byte("other"))
			case "wrong-policy":
				i.Job.PolicyHash = contracts.Digest([]byte("other"))
			case "rollback-admission":
				execSQL(t, s, `CREATE TRIGGER fail_admission BEFORE INSERT ON build_outbox BEGIN SELECT RAISE(ABORT,'injected'); END`)
			case "denied":
				r.ImageDigest = ""
				r.Outcome = "denied"
				if e := s.RecordArtifact(ctx, i, r); e != nil {
					t.Fatal(e)
				}
				if _, e := s.AdmittedArtifact(ctx, i); e == nil {
					t.Fatal("denial admitted")
				}
				return
			}
			if e := s.RecordArtifact(ctx, i, r); e == nil {
				t.Fatal("accepted")
			}
			if name == "rollback-admission" {
				if scalar(t, s, "SELECT count(*) FROM build_attempts WHERE result_json IS NOT NULL") != 0 {
					t.Fatal("partial admission")
				}
			}
		})
	}
}

func TestBuildExportRecoveryAndOutbox(t *testing.T) {
	ctx := context.Background()
	s, path := testStore(t)
	i := buildIntent(t, s)
	if e := s.BeginBuild(ctx, i); e != nil {
		t.Fatal(e)
	}
	want := buildReceipt(i)
	if e := s.RecordBuildExport(ctx, i, want); e != nil {
		t.Fatal(e)
	}
	bad := want
	bad.Bytes++
	if e := s.RecordBuildExport(ctx, i, bad); e == nil {
		t.Fatal("conflicting receipt size")
	}
	s.Close()
	s, e := Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	got, e := s.BuildExport(ctx, i)
	if e != nil || got != want {
		t.Fatal("durable receipt", got, e)
	}
	messages, e := s.PendingBuildOutbox(ctx, 100)
	if e != nil || len(messages) != 2 {
		t.Fatal(messages, e)
	}
	for _, m := range messages {
		if e = s.MarkBuildDelivered(ctx, m.ID); e != nil {
			t.Fatal(e)
		}
	}
	messages, e = s.PendingBuildOutbox(ctx, 100)
	if e != nil || len(messages) != 0 {
		t.Fatal(messages, e)
	}
}
func TestBuildFailureAfterDeadline(t *testing.T) {
	ctx := context.Background()
	s, _ := testStore(t)
	i := buildIntent(t, s)
	i.Job.ExpiresAt = time.Now().Add(200 * time.Millisecond)
	if e := s.BeginBuild(ctx, i); e != nil {
		t.Fatal(e)
	}
	time.Sleep(220 * time.Millisecond)
	r := admitted(i)
	r.ImageDigest = ""
	r.Outcome = "timeout"
	if e := s.RecordBuildFailure(ctx, i, r); e != nil {
		t.Fatal(e)
	}
	d, e := s.Deployment(ctx, i.Job.Clone.DeploymentID)
	if e != nil || d.State != domain.Failed {
		t.Fatal(d, e)
	}
	r = admitted(i)
	if e = s.RecordArtifact(ctx, i, r); e == nil {
		t.Fatal("late admission")
	}
}
