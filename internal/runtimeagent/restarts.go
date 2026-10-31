package runtimeagent

import (
	"context"
	"database/sql"
	"errors"

	"dev-orchestrator/internal/policy"
)

// RegisterRestarts precedes engine mutation and binds each allowance to the
// immutable original create. A completed retry never resets the consumed count.
func (l *Ledger) RegisterRestarts(ctx context.Context, c Command) error {
	if c.Spec == nil || c.Operation != "create" {
		return ErrDenied
	}
	return l.transaction(ctx, func(tx *sql.Tx) error {
		var app, hash string
		if tx.QueryRowContext(ctx, "SELECT app,spec_hash FROM commands WHERE id=? AND operation='create'", c.ID).Scan(&app, &hash) != nil || app != c.AppID || hash != c.SpecHash {
			return ErrDenied
		}
		for _, service := range c.Spec.Services {
			if !policy.ValidName(service.Name) || service.RestartAttempts < 0 || service.RestartAttempts > 3 {
				return ErrDenied
			}
			var maximum int
			err := tx.QueryRowContext(ctx, "SELECT maximum FROM restart_budgets WHERE owner=? AND service=?", c.ID, service.Name).Scan(&maximum)
			if err == nil {
				if maximum != service.RestartAttempts {
					return ErrConflict
				}
				continue
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return ErrLedger
			}
			if _, err = tx.ExecContext(ctx, "INSERT INTO restart_budgets VALUES(?,?,?,0)", c.ID, service.Name, service.RestartAttempts); err != nil {
				return ErrLedger
			}
		}
		return nil
	})
}

// ConsumeRestart commits before start. A crash/lost response consumes an attempt
// conservatively; neither process nor daemon restart can replenish it.
func (l *Ledger) ConsumeRestart(ctx context.Context, c Command, service string) (bool, error) {
	if c.Operation != "create" || !policy.ValidName(service) {
		return false, ErrDenied
	}
	admitted := false
	err := l.transaction(ctx, func(tx *sql.Tx) error {
		var outcome []byte
		if tx.QueryRowContext(ctx, "SELECT outcome FROM commands WHERE id=? AND state='done'", c.ID).Scan(&outcome) != nil {
			return ErrConflict
		}
		var completed Result
		if decodeResult(outcome, &completed) != nil || completed.CommandID != c.ID || completed.Code != "ok" {
			return ErrConflict
		}
		var n int
		if tx.QueryRowContext(ctx, `SELECT count(*) FROM targets t JOIN commands c ON c.id=t.id JOIN fences f ON f.app=c.app AND f.generation=c.generation AND f.deployment=c.deployment AND f.spec_hash=c.spec_hash WHERE t.id=? AND t.stopped=0 AND c.state='done' AND c.app=? AND c.deployment=? AND c.generation=? AND c.spec_hash=?`, c.ID, c.AppID, c.DeploymentID, c.Generation, c.SpecHash).Scan(&n) != nil {
			return ErrLedger
		}
		if n != 1 {
			return ErrConflict
		}
		r, err := tx.ExecContext(ctx, "UPDATE restart_budgets SET used=used+1 WHERE owner=? AND service=? AND used<maximum", c.ID, service)
		if err != nil {
			return ErrLedger
		}
		count, err := r.RowsAffected()
		if err != nil {
			return ErrLedger
		}
		admitted = count == 1
		return nil
	})
	return admitted, err
}
