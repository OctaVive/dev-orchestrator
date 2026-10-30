// Package clonejob integrates an authorized clone attempt with a reserved VM.
// Scheduling/reservation and the complete deployment controller remain M12.
package clonejob

import (
	"context"
	"errors"
	"time"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/provisioner"
	"dev-orchestrator/internal/storage"
)

var ErrClone = errors.New("clone attempt failed")

type Driver struct {
	Store   *storage.Store
	Backend provisioner.CloneBackend
}

// Execute requires an externally reserved, fresh Machine. Success retains the
// same guest for M07; its owner must Release it after handoff/use. Every failure
// releases through the provisioner and reports uncertain cleanup explicitly.
func (d Driver) Execute(ctx context.Context, m provisioner.Machine, i storage.CloneIntent) (contracts.CloneResult, error) {
	if d.Store == nil || d.Backend == nil || !d.Backend.Controls().Ready() || m.Lease.JobID != i.Job.JobID || m.Lease.CommandID != i.Job.LeaseID || m.Lease.DeploymentID != i.Job.DeploymentID || m.Lease.Template.Digest != i.Job.TemplateDigest || i.Job.ExpiresAt.After(m.Lease.ExpiresAt) {
		return contracts.CloneResult{}, ErrClone
	}
	m.Clone = &i.Job
	if e := d.Store.BeginClone(ctx, i); e != nil {
		return contracts.CloneResult{}, e
	}
	deadline := time.Now().Add(time.Duration(i.Job.Policy.Limits.Seconds) * time.Second)
	if i.Job.ExpiresAt.Before(deadline) {
		deadline = i.Job.ExpiresAt
	}
	ctx, stopClone := context.WithDeadline(ctx, deadline)
	defer stopClone()
	lastSHA := ""
	terminalRecorded := false
	cleanup := func(err error) (contracts.CloneResult, error) {
		if !terminalRecorded {
			r := contracts.NewCloneResult(i.Job)
			r.SHA = lastSHA
			r.Outcome = "error"
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				r.Outcome = "timeout"
			} else if ctx.Err() != nil {
				r.Outcome = "cancelled"
			} else if !time.Now().Before(i.Job.ExpiresAt) {
				r.Outcome = "timeout"
			}
			fresh, stop := context.WithTimeout(context.Background(), 5*time.Second)
			_ = d.Store.RecordClone(fresh, i, r)
			stop()
		}
		if e := d.Release(m, i.Job); e != nil {
			return contracts.CloneResult{}, e
		}
		return contracts.CloneResult{}, err
	}
	admission, cancel := context.WithTimeout(ctx, 20*time.Second)
	e := d.Backend.Create(admission, m)
	cancel()
	if e != nil {
		return cleanup(e)
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	next := 0
	for {
		frames, e := d.Backend.CloneResults(ctx, m)
		if e != nil {
			return cleanup(e)
		}
		for next < len(frames) {
			r := frames[next]
			if e = d.Store.RecordClone(ctx, i, r); e != nil {
				return cleanup(e)
			}
			next++
			lastSHA = r.SHA
			terminalRecorded = r.Outcome != "resolved"
			if r.Outcome == "success" {
				accepted, e := d.Store.CloneReady(ctx, i.Job)
				if e != nil {
					return cleanup(e)
				}
				return accepted, nil
			}
			if r.Outcome != "resolved" {
				return cleanup(ErrClone)
			}
		}
		select {
		case <-ctx.Done():

			return cleanup(ctx.Err())
		case <-ticker.C:
		}
	}
}
func (d Driver) Release(m provisioner.Machine, j contracts.CloneJob) error {
	m.Clone = &j
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	r, e := d.Backend.Cleanup(ctx, m)
	if e != nil || !r.VMAbsent || !r.ArtifactsAbsent || !r.StartFenced {
		return provisioner.ErrCleanup
	}
	return nil
}
