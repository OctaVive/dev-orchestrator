//go:build linux

package buildjob

import (
	"context"
	"dev-orchestrator/internal/artifacts"
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/domain"
	"dev-orchestrator/internal/provisioner"
	"dev-orchestrator/internal/storage"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

type workflowBackend struct {
	uploads  *artifacts.Store
	scenario string
	cleanups int
}

func (b *workflowBackend) Controls() provisioner.Controls {
	return provisioner.Controls{PinnedTemplate: true, KVMIsolation: true, ExternalQuotas: true, IsolatedNetwork: true, HostDeadline: true, LateStartFence: true, OwnershipChecks: true, ConfirmedCleanup: true}
}
func (b *workflowBackend) Build(ctx context.Context, m provisioner.Machine, j contracts.BuildJob, g UploadGrant) error {
	if b.scenario == "build-timeout" {
		return context.DeadlineExceeded
	}
	if b.scenario == "cancelled" {
		return context.Canceled
	}
	if b.scenario == "build-error" {
		return ErrBuild
	}
	if b.scenario == "no-upload" {
		return nil
	}
	_, e := b.uploads.Put(ctx, g.ID, g.Token, strings.NewReader("opaque fixture bytes"))
	return e
}
func (b *workflowBackend) Cleanup(context.Context, provisioner.Machine, contracts.BuildJob) error {
	b.cleanups++
	if b.scenario == "cleanup-failure" {
		return provisioner.ErrCleanup
	}
	return nil
}
func (b *workflowBackend) Ingest(ctx context.Context, j contracts.BuildJob, receipt artifacts.Receipt) (contracts.ArtifactResult, error) {
	if b.cleanups == 0 {
		return contracts.ArtifactResult{}, ErrBuild
	}
	r := contracts.ArtifactResult{Version: 1, JobID: j.Clone.JobID, DeploymentID: j.Clone.DeploymentID, Attempt: j.Clone.Attempt, Generation: j.Clone.Generation, PolicyHash: j.PolicyHash, ArchiveDigest: receipt.Digest, ImageDigest: contracts.Digest([]byte("manifest")), ScannerDigest: j.Policy.ScannerDigest, DatabaseDigest: j.Policy.DatabaseDigest, ReportDigest: contracts.Digest([]byte("report")), SBOMDigest: contracts.Digest([]byte("sbom")), Outcome: "admitted"}
	switch b.scenario {
	case "scan-timeout":
		return r, context.DeadlineExceeded
	case "wrong-digest":
		r.ArchiveDigest = contracts.Digest(nil)
	case "stale-result":
		r.Generation++
	case "denied":
		r.Outcome = "denied"
		r.ImageDigest = ""
	}
	return r, nil
}
func TestWorkflowAdmissionAndFailure(t *testing.T) {
	for _, scenario := range []string{"success", "build-error", "no-upload", "build-timeout", "scan-timeout", "wrong-digest", "stale-result", "denied", "cleanup-failure", "resume", "promotion-crash", "service-restart"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			s, ci := pipelineFixture(t, "good")
			p := contracts.BuildPolicy{EgressPolicyHash: strings.Repeat("a", 64), UploadOrigin: "https://ingest.example.com", Version: 1, BuildSeconds: 30, ScanSeconds: 30, Limits: contracts.DefaultArtifactLimits(), ScannerDigest: contracts.Digest([]byte("tool")), DatabaseDigest: contracts.Digest([]byte("db")), DatabaseCreatedAt: time.Now().Add(-time.Hour), DatabaseMaxAgeSeconds: 172800}
			ci.Job.Build = &contracts.BuildSettings{Policy: p, Dockerfile: "Dockerfile"}
			if e := s.BeginClone(ctx, ci); e != nil {
				t.Fatal(e)
			}
			r := contracts.NewCloneResult(ci.Job)
			r.SHA = strings.Repeat("b", 40)
			r.Outcome = "resolved"
			if e := s.RecordClone(ctx, ci, r); e != nil {
				t.Fatal(e)
			}
			r.Outcome = "success"
			r.ContextID = strings.Repeat("c", 64)
			r.Entries = 1
			r.Bytes = 12
			if e := s.RecordClone(ctx, ci, r); e != nil {
				t.Fatal(e)
			}

			j := contracts.BuildJob{Version: 1, Clone: ci.Job, SHA: r.SHA, ContextID: r.ContextID, Policy: p, PolicyHash: p.Hash(), Dockerfile: "Dockerfile", ExpiresAt: ci.Job.ExpiresAt}
			m := provisioner.Machine{Lease: provisioner.Lease{JobID: ci.Job.JobID, CommandID: ci.Job.LeaseID, DeploymentID: ci.Job.DeploymentID, Template: provisioner.Template{Digest: ci.Job.TemplateDigest}, ExpiresAt: ci.Job.ExpiresAt}}
			dir := t.TempDir()
			os.Chmod(dir, 0700)
			uploads, e := artifacts.OpenWithReserve(dir, 2<<30, 0)
			if e != nil {
				t.Fatal(e)
			}
			root := t.TempDir()
			os.Chmod(root, 0700)
			backend := &workflowBackend{uploads: uploads, scenario: scenario}
			driver := Driver{Store: s, Uploads: uploads, Backend: backend, ArtifactRoot: root}
			i := storage.BuildIntent{Job: j, Actor: ci.Actor, CorrelationID: ci.CorrelationID}
			var result contracts.ArtifactResult
			if scenario == "resume" || scenario == "promotion-crash" || scenario == "service-restart" {
				if e = s.BeginBuild(ctx, i); e != nil {
					t.Fatal(e)
				}
				var id, token string
				id, token, e = uploads.Issue(artifacts.Binding{JobID: j.Clone.JobID, DeploymentID: j.Clone.DeploymentID, Attempt: 1, Generation: 1}, j.Policy.Limits.UploadBytes, j.ExpiresAt)
				if e != nil {
					t.Fatal(e)
				}
				var receipt artifacts.Receipt
				receipt, e = uploads.Put(ctx, id, token, strings.NewReader("opaque fixture bytes"))
				if e != nil {
					t.Fatal(e)
				}
				if e = s.RecordBuildExport(ctx, i, receipt); e != nil {
					t.Fatal(e)
				}
				if scenario == "promotion-crash" {
					if _, e = uploads.Promote(receipt, root); e != nil {
						t.Fatal(e)
					}
					if _, e = s.AdmittedArtifact(ctx, i); e == nil {
						t.Fatal("orphan admitted")
					}
				}
				if scenario == "service-restart" {
					replacement, e := artifacts.OpenWithReserve(dir, 2<<30, 0)
					if e != nil {
						t.Fatal(e)
					}
					driver.Uploads = replacement
				}
				result, e = driver.ResumeIngest(ctx, m, i)
			} else {
				result, e = driver.Execute(ctx, m, i)
			}
			if scenario == "success" || scenario == "resume" || scenario == "promotion-crash" {
				if e != nil || result.Outcome != "admitted" {
					t.Fatal(result, e)
				}
				d, _ := s.Deployment(ctx, j.Clone.DeploymentID)
				if d.State != domain.Scanning {
					t.Fatal("premature approval")
				}
			} else {
				if e == nil {
					t.Fatal("failure admitted")
				}
				if _, e := s.AdmittedArtifact(ctx, i); e == nil {
					t.Fatal("failed artifact retrievable")
				}
				if scenario == "cleanup-failure" && !errors.Is(e, provisioner.ErrCleanup) {
					t.Fatal("hidden cleanup failure", e)
				}
			}
			if backend.cleanups == 0 {
				t.Fatal("resources not cleaned")
			}
		})
	}
}
