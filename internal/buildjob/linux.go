//go:build linux

package buildjob

import (
	"context"
	"crypto/rand"
	"dev-orchestrator/internal/artifacts"
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/provisioner"
	"fmt"
	"time"
)

// LinuxAdapter requires independently configured pinned builder/scanner
// backends. Callers reserve capacity for the sequential VM stages before use.
type LinuxAdapter struct {
	Builder         provisioner.BuildBackend
	Scanner         provisioner.IngestBackend
	ScannerTemplate provisioner.Template
}

func (a LinuxAdapter) Controls() provisioner.Controls {
	if a.Builder == nil || a.Scanner == nil || !a.Builder.Controls().Ready() || !a.Scanner.Controls().Ready() || !contracts.ValidDigest(a.ScannerTemplate.Digest) {
		return provisioner.Controls{}
	}
	return a.Builder.Controls()
}
func (a LinuxAdapter) Build(ctx context.Context, m provisioner.Machine, j contracts.BuildJob, g UploadGrant) error {
	m.Clone = &j.Clone
	if e := a.Builder.AuthorizeBuild(ctx, m, contracts.BuildAuthorization{Job: j, ObjectID: g.ID, Token: g.Token}); e != nil {
		return e
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		r, done, e := a.Builder.BuildResult(ctx, m, j)
		if e != nil {
			return e
		}
		if done {
			if r.Outcome != "exported" {
				return fmt.Errorf("%w: %s", ErrBuild, r.Reason)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func (a LinuxAdapter) Cleanup(ctx context.Context, m provisioner.Machine, j contracts.BuildJob) error {
	m.Clone = &j.Clone
	r, e := a.Builder.Cleanup(ctx, m)
	if e != nil || !r.VMAbsent || !r.ArtifactsAbsent || !r.StartFenced {
		return provisioner.ErrCleanup
	}
	return nil
}
func (a LinuxAdapter) Ingest(ctx context.Context, j contracts.BuildJob, r artifacts.Receipt) (result contracts.ArtifactResult, err error) {
	if e := a.Scanner.CleanupIngests(ctx, j); e != nil {
		return result, e
	}
	var id [16]byte
	var proof [32]byte
	if _, e := rand.Read(id[:]); e != nil {
		return result, e
	}
	if _, e := rand.Read(proof[:]); e != nil {
		return result, e
	}
	id[6] = id[6]&15 | 64
	id[8] = id[8]&63 | 128
	job := fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])
	expiry := time.Now().Add(time.Duration(j.Policy.ScanSeconds) * time.Second)
	if j.ExpiresAt.Before(expiry) {
		expiry = j.ExpiresAt
	}
	m := provisioner.Machine{Lease: provisioner.Lease{JobID: job, CommandID: job, DeploymentID: j.Clone.DeploymentID, Template: a.ScannerTemplate, ProfileID: "build-small-v1", CreatedAt: time.Now(), ExpiresAt: expiry}, Budget: provisioner.SmallBudget(), OwnershipProof: fmt.Sprintf("%x", proof), Ingest: &contracts.IngestJob{Build: j, ObjectID: r.ObjectID, Bytes: r.Bytes, ArchiveDigest: r.Digest}}
	defer func() {
		fresh, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		clean, e := a.Scanner.Cleanup(fresh, m)
		if e != nil || !clean.VMAbsent || !clean.ArtifactsAbsent || !clean.StartFenced {
			err = provisioner.ErrCleanup
		}
	}()
	if e := a.Scanner.Create(ctx, m); e != nil {
		return result, e
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		r, done, e := a.Scanner.IngestResult(ctx, m)
		if e != nil {
			return result, e
		}
		if done {
			return r, nil
		}
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-ticker.C:
		}
	}
}
