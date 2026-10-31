package runtimeagent

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"time"
)

// Poller has no inbound listener, arbitrary URL or execution surface. A success
// acknowledges the supplied result and may deliver one new signed command.
type Poller interface {
	Poll(context.Context, string, string, *Result) (*Command, error)
}
type Reconciler interface{ Reconcile(context.Context) error }

func (l *Ledger) PendingResult(ctx context.Context) (Result, bool, error) {
	var raw []byte
	err := l.db.QueryRowContext(ctx, "SELECT outcome FROM runtime_outbox ORDER BY rowid LIMIT 1").Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return Result{}, false, nil
	}
	var result Result
	if err != nil || len(raw) > 64<<10 || decodeResult(raw, &result) != nil {
		return Result{}, false, ErrLedger
	}
	return result, true, nil
}
func (l *Ledger) AcknowledgeResult(ctx context.Context, result Result) error {
	raw, err := encodeResult(result)
	if err != nil {
		return ErrLedger
	}
	r, err := l.db.ExecContext(ctx, "DELETE FROM runtime_outbox WHERE command=? AND outcome=?", result.CommandID, raw)
	if err != nil {
		return ErrLedger
	}
	n, err := r.RowsAffected()
	if err != nil || n != 1 {
		return ErrConflict
	}
	return nil
}

// Serve preserves completed/uncertain results before polling. A lost response
// never drops the local result, and duplicate controller delivery cannot repeat
// an admitted effect. Invalid commands remain denied without execution intent.
// Reconciliation is mandatory for a process service, including while idle or
// disconnected; it must quarantine/stop or explicitly report uncertainty.
func (a *Agent) Serve(ctx context.Context, poller Poller, reconciler Reconciler) error {
	if poller == nil || reconciler == nil {
		return ErrDenied
	}
	delay := 100 * time.Millisecond
	var lastDenied string
	wait := func() bool {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		}
	}
	for ctx.Err() == nil {
		// A reconciliation incident does not suppress delivery of already durable
		// results. It blocks new command execution for this iteration.
		incident := reconciler.Reconcile(ctx) != nil
		result, pending, err := a.config.Ledger.PendingResult(ctx)
		if err != nil {
			return err
		}
		var outgoing *Result
		if pending {
			outgoing = &result
		}
		command, err := poller.Poll(ctx, a.config.WorkerID, a.config.Incarnation, outgoing)
		if err != nil {
			if delay < 5*time.Second {
				delay *= 2
				if delay > 5*time.Second {
					delay = 5 * time.Second
				}
			}
			if !wait() {
				break
			}
			continue
		}
		if pending && a.config.Ledger.AcknowledgeResult(ctx, result) != nil {
			return ErrLedger
		}
		delay = 100 * time.Millisecond
		if command != nil && (!incident || command.Operation == "stop" || command.Operation == "remove") {
			result, executeErr := a.Execute(ctx, *command)
			if executeErr != nil && result.CommandID == "" && lastDenied != command.ID {
				os.Stderr.WriteString("runtime_command_preflight_denied\n")
				lastDenied = command.ID
			}
		}
		if command == nil || incident {
			if !wait() {
				break
			}
		}
	}
	return ctx.Err()
}
