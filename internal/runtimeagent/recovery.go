package runtimeagent

import (
	"context"
	"database/sql"

	"dev-orchestrator/internal/contracts"
)

// RecoverPendingResults is called once after process enrollment/ledger checks,
// before polling. A dead process's intent is never resumed: publish uncertainty
// durably, even if the crash preceded the first saved engine resource. Known
// resources are independently quarantined by Supervisor; charges remain intact.
func (l *Ledger) RecoverPendingResults(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.transaction(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, "SELECT id,operation FROM commands WHERE state='pending' ORDER BY rowid LIMIT 1025")
		if err != nil {
			return ErrLedger
		}
		type pending struct{ id, operation string }
		var commands []pending
		for rows.Next() {
			var c pending
			if rows.Scan(&c.id, &c.operation) != nil || !contracts.ValidJobID(c.id) {
				rows.Close()
				return ErrLedger
			}
			commands = append(commands, c)
		}
		err = rows.Err()
		rows.Close()
		if err != nil || len(commands) > 1024 {
			return ErrLedger
		}
		for _, c := range commands {
			raw, err := encodeResult(Result{CommandID: c.id, Code: "uncertain"})
			if err != nil {
				return ErrLedger
			}
			if _, err = tx.ExecContext(ctx, "UPDATE commands SET state='uncertain',outcome=? WHERE id=? AND state='pending'", raw, c.id); err != nil {
				return ErrLedger
			}
			if c.operation == "create" {
				if _, err = tx.ExecContext(ctx, "UPDATE targets SET stopped=1 WHERE id=?", c.id); err != nil {
					return ErrLedger
				}
			}
			if _, err = tx.ExecContext(ctx, "INSERT INTO runtime_outbox VALUES(?,?) ON CONFLICT(command) DO NOTHING", c.id, raw); err != nil {
				return ErrLedger
			}
		}
		return nil
	})
}
