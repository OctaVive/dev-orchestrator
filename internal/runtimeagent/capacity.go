package runtimeagent

import (
	"context"
	"database/sql"
	"errors"

	"dev-orchestrator/internal/contracts"
)

type CandidateUsage struct {
	Memory          int64
	CPUMillis, PIDs int
}

func (u CandidateUsage) valid() bool {
	return u.Memory > 0 && u.Memory <= 8<<30 && u.CPUMillis > 0 && u.CPUMillis <= 4000 && u.PIDs > 0 && u.PIDs <= 512
}

// ReserveCandidate accounts for overlapping candidates/canaries under one app's
// hard parent cgroup. Reservation commits before any image/network/start effect.
func (l *Ledger) ReserveCandidate(ctx context.Context, c Command, want, max CandidateUsage) error {
	if !want.valid() || !max.valid() || !contracts.ValidJobID(c.ID) || !contracts.ValidJobID(c.AppID) {
		return ErrDenied
	}
	return l.transaction(ctx, func(tx *sql.Tx) error {
		var old CandidateUsage
		var app string
		err := tx.QueryRowContext(ctx, "SELECT app,memory,cpu,pids FROM candidate_capacity WHERE owner=?", c.ID).Scan(&app, &old.Memory, &old.CPUMillis, &old.PIDs)
		if err == nil {
			if old != want || app != c.AppID {
				return ErrConflict
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return ErrLedger
		}
		var memory int64
		var cpu, pids int
		if tx.QueryRowContext(ctx, "SELECT coalesce(sum(memory),0),coalesce(sum(cpu),0),coalesce(sum(pids),0) FROM candidate_capacity WHERE app=?", c.AppID).Scan(&memory, &cpu, &pids) != nil {
			return ErrLedger
		}
		if want.Memory > max.Memory-memory || want.CPUMillis > max.CPUMillis-cpu || want.PIDs > max.PIDs-pids {
			return ErrUnsupported
		}
		var commandApp string
		if tx.QueryRowContext(ctx, "SELECT app FROM commands WHERE id=? AND state='pending'", c.ID).Scan(&commandApp) != nil || commandApp != c.AppID {
			return ErrDenied
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO candidate_capacity VALUES(?,?,?,?,?)", c.ID, c.AppID, want.Memory, want.CPUMillis, want.PIDs); err != nil {
			return ErrLedger
		}
		return nil
	})
}

// ReleaseCandidate is called only after independently confirmed engine cleanup.
// No timer, failed import or process restart releases an uncertain reservation.
func (l *Ledger) ReleaseCandidate(ctx context.Context, owner string) error {
	if !contracts.ValidJobID(owner) {
		return ErrDenied
	}
	return l.transaction(ctx, func(tx *sql.Tx) error {
		var count int
		if tx.QueryRowContext(ctx, "SELECT count(*) FROM resources WHERE owner=?", owner).Scan(&count) != nil || count != 0 {
			return ErrUncertain
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM candidate_capacity WHERE owner=?", owner); err != nil {
			return ErrLedger
		}
		return nil
	})
}

// ResourceOwners is bounded; an unexpectedly large ledger becomes an incident.
func (l *Ledger) ResourceOwners(ctx context.Context) ([]Command, error) {
	rows, err := l.db.QueryContext(ctx, "SELECT s.body FROM command_specs s WHERE EXISTS(SELECT 1 FROM resources r WHERE r.owner=s.command) ORDER BY s.command LIMIT 1025")
	if err != nil {
		return nil, ErrLedger
	}
	defer rows.Close()
	var commands []Command
	for rows.Next() {
		var raw []byte
		if rows.Scan(&raw) != nil {
			return nil, ErrLedger
		}
		c, err := DecodeBytes(raw)
		if err != nil || c.WorkerID != l.worker || c.Incarnation != l.incarnation {
			return nil, ErrLedger
		}
		commands = append(commands, c)
	}
	if rows.Err() != nil || len(commands) > 1024 {
		return nil, ErrLedger
	}
	return commands, nil
}
