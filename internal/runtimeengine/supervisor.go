package runtimeengine

import (
	"context"
	"time"

	"dev-orchestrator/internal/runtimeagent"
)

type TargetAuthority interface {
	Valid(context.Context, string, string) error
	CurrentTarget(context.Context, runtimeagent.Command) error
}
type Supervisor struct {
	Ledger                *runtimeagent.Ledger
	Factory               *Factory
	Authority             TargetAuthority
	WorkerID, Incarnation string
}

// Reconcile never adopts objects by labels or deletes foreign resources. Unsafe
// or revoked owned targets lose ingress and stop; uncertain cleanup stays charged.
func (s *Supervisor) Reconcile(ctx context.Context) error {
	if s.Ledger == nil || s.Factory == nil || s.Authority == nil || !s.Ledger.Identity(s.WorkerID, s.Incarnation) {
		return runtimeagent.ErrDenied
	}
	return s.Ledger.Dispatch(ctx, func() error {
		owners, err := s.Ledger.ResourceOwners(ctx)
		if err != nil {
			return err
		}
		leaseValid := s.Authority.Valid(ctx, s.WorkerID, s.Incarnation) == nil
		incident := false
		for _, original := range owners {
			cleanup := original
			cleanup.Operation = "stop"
			cleanup.Target = original.ID
			cleanup.Spec = nil
			current, err := s.Ledger.OriginalTarget(ctx, original.ID)
			if err != nil {
				// A pending/uncertain create or canary never resumes effects after restart.
				// Stop known exact IDs and retain its reservation and incident for recovery.
				bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
				_ = s.Factory.Quarantine(bounded, cleanup)
				cancel()
				incident = true
				continue
			}
			stopped, err := s.Ledger.TargetStopped(ctx, current.ID)
			if err != nil {
				return err
			}
			authorized := leaseValid && !stopped && s.Authority.CurrentTarget(ctx, current) == nil
			if authorized {
				_, inspectErr := s.Factory.Inspect(ctx, cleanup)
				exited, err := s.Factory.StoppedServices(ctx, current)
				if inspectErr == nil && err == nil && len(exited) == 0 {
					continue
				}
				if err == nil && len(exited) > 0 {
					restarted := true
					check := func() error {
						if s.Authority.Valid(ctx, s.WorkerID, s.Incarnation) != nil || s.Authority.CurrentTarget(ctx, current) != nil {
							return runtimeagent.ErrDenied
						}
						stopped, err := s.Ledger.TargetStopped(ctx, current.ID)
						if err != nil || stopped {
							return runtimeagent.ErrDenied
						}
						return ctx.Err()
					}
					for _, service := range exited {
						allowed, err := s.Ledger.ConsumeRestart(ctx, current, service)
						if err != nil || !allowed || s.Factory.RestartOwned(ctx, current, service, check) != nil {
							restarted = false
							break
						}
					}
					if restarted {
						continue
					}
				}
			}

			if s.Ledger.FenceStop(ctx, current.ID) != nil {
				return runtimeagent.ErrLedger
			}
			bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
			err = s.Factory.Quarantine(bounded, cleanup)
			cancel()
			if err != nil {
				incident = true
			}
		}
		if incident {
			return runtimeagent.ErrUncertain
		}
		return nil
	})
}
