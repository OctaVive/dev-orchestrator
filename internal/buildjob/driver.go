// Package buildjob owns the narrow M07 workflow; reservation/scheduling and
// deployment approval remain controller responsibilities.
package buildjob

import (
	"context"
	"dev-orchestrator/internal/artifacts"
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/provisioner"
	"dev-orchestrator/internal/storage"
	"errors"
	"time"
)

var ErrBuild = errors.New("build or artifact admission failed")

type UploadGrant struct {
	ID        string
	Token     string
	ExpiresAt time.Time
}

// Backend implementations must execute builds in the retained clone VM and
// ingest in a separate fresh VM. Results are bounded untrusted guest assertions.
type Backend interface {
	Controls() provisioner.Controls
	Build(context.Context, provisioner.Machine, contracts.BuildJob, UploadGrant) error
	Ingest(context.Context, contracts.BuildJob, artifacts.Receipt) (contracts.ArtifactResult, error)
	Cleanup(context.Context, provisioner.Machine, contracts.BuildJob) error
}
type UploadService interface {
	Issue(artifacts.Binding, int64, time.Time) (string, string, error)
	Receipt(string) (artifacts.Receipt, error)
	Revoke(string)
	Promote(artifacts.Receipt, string) (string, error)
}
type Driver struct {
	Store        *storage.Store
	Uploads      UploadService
	Backend      Backend
	ArtifactRoot string
}

func (d Driver) Execute(parent context.Context, m provisioner.Machine, i storage.BuildIntent) (contracts.ArtifactResult, error) {
	if d.Store == nil || d.Uploads == nil || d.Backend == nil || !d.Backend.Controls().Ready() || i.Job.Validate(time.Now()) != nil || m.Lease.JobID != i.Job.Clone.JobID || m.Lease.CommandID != i.Job.Clone.LeaseID || m.Lease.DeploymentID != i.Job.Clone.DeploymentID || m.Lease.Template.Digest != i.Job.Clone.TemplateDigest || i.Job.ExpiresAt.After(m.Lease.ExpiresAt) {
		return contracts.ArtifactResult{}, ErrBuild
	}
	if result, e := d.Store.AdmittedArtifact(parent, i); e == nil {
		return result, nil
	}
	ctx, cancel := context.WithDeadline(parent, i.Job.ExpiresAt)
	defer cancel()
	cleanup := func() error {
		fresh, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		return d.Backend.Cleanup(fresh, m, i.Job)
	}
	if e := d.Store.BeginBuild(ctx, i); e != nil {
		return contracts.ArtifactResult{}, e
	}
	binding := artifacts.Binding{JobID: i.Job.Clone.JobID, DeploymentID: i.Job.Clone.DeploymentID, Attempt: i.Job.Clone.Attempt, Generation: i.Job.Clone.Generation}
	expiry := time.Now().Add(time.Duration(i.Job.Policy.BuildSeconds) * time.Second)
	if i.Job.ExpiresAt.Before(expiry) {
		expiry = i.Job.ExpiresAt
	}
	fail := func(outcome string) (contracts.ArtifactResult, error) {
		r := contracts.ArtifactResult{Version: 1, JobID: binding.JobID, DeploymentID: binding.DeploymentID, Attempt: binding.Attempt, Generation: binding.Generation, PolicyHash: i.Job.PolicyHash, Outcome: outcome}
		if ctx.Err() != nil {
			r.Outcome = "cancelled"
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				r.Outcome = "timeout"
			}
		}
		fresh, stop := context.WithTimeout(context.Background(), 5*time.Second)
		recordErr := d.Store.RecordBuildFailure(fresh, i, r)
		stop()
		if e := cleanup(); e != nil {
			return contracts.ArtifactResult{}, errors.Join(e, recordErr)
		}
		return contracts.ArtifactResult{}, errors.Join(ErrBuild, recordErr)
	}
	id, token, e := d.Uploads.Issue(binding, i.Job.Policy.Limits.UploadBytes, expiry)
	if e != nil {
		return fail("error")
	}
	defer d.Uploads.Revoke(id)
	buildCtx, stopBuild := context.WithDeadline(ctx, expiry)
	e = d.Backend.Build(buildCtx, m, i.Job, UploadGrant{id, token, expiry})
	stopBuild()
	if e != nil {
		if errors.Is(e, context.DeadlineExceeded) {
			return fail("timeout")
		}
		return fail("error")
	}
	receipt, e := d.Uploads.Receipt(id)
	if e != nil {
		return fail("error")
	}
	if e = d.Store.RecordBuildExport(ctx, i, receipt); e != nil {
		return fail("error")
	}
	// Builder is no longer needed. Free its memory before starting the separate
	// scanner VM, while retaining the already committed quarantine object.
	if e = cleanup(); e != nil {
		return contracts.ArtifactResult{}, e
	}
	scanCtx, stopScan := context.WithTimeout(ctx, time.Duration(i.Job.Policy.ScanSeconds)*time.Second)
	r, e := d.Backend.Ingest(scanCtx, i.Job, receipt)
	stopScan()
	if e == nil && r.Validate(i.Job) == nil && r.Outcome != "admitted" {
		return fail(r.Outcome)
	}
	if errors.Is(e, context.DeadlineExceeded) {
		return fail("timeout")
	}
	if e != nil || r.Validate(i.Job) != nil || r.Outcome != "admitted" || r.ArchiveDigest != receipt.Digest {
		return fail("error")
	}
	if _, e = d.Uploads.Promote(receipt, d.ArtifactRoot); e != nil {
		return fail("error")
	}
	if e = d.Store.RecordArtifact(ctx, i, r); e != nil {
		return fail("error")
	}
	return d.Store.AdmittedArtifact(ctx, i)
}

// ResumeIngest retries an already exported attempt after controller loss. The
// backend reconciles any prior scanner VM first. Upload-service loss/expiry
// fails closed; it never reuses an interrupted builder or admits an orphan.
func (d Driver) ResumeIngest(parent context.Context, m provisioner.Machine, i storage.BuildIntent) (contracts.ArtifactResult, error) {
	if d.Store == nil || d.Uploads == nil || d.Backend == nil || !d.Backend.Controls().Ready() || i.Job.Validate(time.Now()) != nil || m.Lease.JobID != i.Job.Clone.JobID || m.Lease.CommandID != i.Job.Clone.LeaseID || m.Lease.DeploymentID != i.Job.Clone.DeploymentID || m.Lease.Template.Digest != i.Job.Clone.TemplateDigest || i.Job.ExpiresAt.After(m.Lease.ExpiresAt) {
		return contracts.ArtifactResult{}, ErrBuild
	}
	if result, e := d.Store.AdmittedArtifact(parent, i); e == nil {
		return result, nil
	}
	ctx, cancel := context.WithDeadline(parent, i.Job.ExpiresAt)
	defer cancel()
	persisted, e := d.Store.BuildExport(ctx, i)
	if e != nil {
		return contracts.ArtifactResult{}, e
	}
	fail := func() (contracts.ArtifactResult, error) {
		failure := contracts.ArtifactResult{Version: 1, JobID: i.Job.Clone.JobID, DeploymentID: i.Job.Clone.DeploymentID, Attempt: i.Job.Clone.Attempt, Generation: i.Job.Clone.Generation, PolicyHash: i.Job.PolicyHash, Outcome: "error"}
		fresh, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		recordErr := d.Store.RecordBuildFailure(fresh, i, failure)
		cleanErr := d.Backend.Cleanup(fresh, m, i.Job)
		return contracts.ArtifactResult{}, errors.Join(ErrBuild, recordErr, cleanErr)
	}
	receipt, e := d.Uploads.Receipt(persisted.ObjectID)
	if e != nil || receipt != persisted {
		return fail()
	}
	fresh, stop := context.WithTimeout(context.Background(), 20*time.Second)
	e = d.Backend.Cleanup(fresh, m, i.Job)
	stop()
	if e != nil {
		return contracts.ArtifactResult{}, e
	}
	scan, stopScan := context.WithTimeout(ctx, time.Duration(i.Job.Policy.ScanSeconds)*time.Second)
	r, e := d.Backend.Ingest(scan, i.Job, receipt)
	stopScan()
	if e != nil || r.Validate(i.Job) != nil || r.Outcome != "admitted" || r.ArchiveDigest != receipt.Digest {
		return fail()
	}
	if _, e = d.Uploads.Promote(receipt, d.ArtifactRoot); e != nil {
		return fail()
	}
	if e = d.Store.RecordArtifact(ctx, i, r); e != nil {
		return contracts.ArtifactResult{}, e
	}
	return d.Store.AdmittedArtifact(ctx, i)
}
