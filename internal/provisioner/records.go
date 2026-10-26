package provisioner

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const leaseColumns = `job_id,command_id,controller_id,app_id,deployment_id,template_id,template_digest,profile_id,state,version,reason,created_at,expires_at,fingerprint,nonce_hash,ownership_proof`

type scanner interface{ Scan(...any) error }

func scanRecord(row scanner) (record, error) {
	var r record
	var created, expires int64
	err := row.Scan(&r.JobID, &r.CommandID, &r.ControllerID, &r.AppID, &r.DeploymentID, &r.Template.ID, &r.Template.Digest, &r.ProfileID, &r.State, &r.Version, &r.Reason, &created, &expires, &r.fingerprint, &r.nonceHash, &r.proof)
	r.CreatedAt, r.ExpiresAt = time.Unix(0, created).UTC(), time.Unix(0, expires).UTC()
	return r, err
}

func (l *Ledger) load(ctx context.Context, job string) (record, error) {
	r, err := scanRecord(l.db.QueryRowContext(ctx, "SELECT "+leaseColumns+" FROM leases WHERE job_id=?", job))
	if err != nil {
		return record{}, ledgerError(ctx, err)
	}
	return r, nil
}

func (l *Ledger) reserve(ctx context.Context, r record) (record, bool, error) {
	created := false
	err := l.write(ctx, func(c *sql.Conn) error {
		existing, err := scanRecord(c.QueryRowContext(ctx, "SELECT "+leaseColumns+" FROM leases WHERE job_id=?", r.JobID))
		if err == nil {
			if existing.ControllerID != r.ControllerID || existing.fingerprint != r.fingerprint {
				return ErrConflict
			}
			r = existing
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return ledgerError(ctx, err)
		}
		var active int
		if err := c.QueryRowContext(ctx, "SELECT count(*) FROM leases WHERE state!='CLEANED'").Scan(&active); err != nil {
			return ledgerError(ctx, err)
		}
		if active != 0 {
			return ErrCapacity
		}
		_, err = c.ExecContext(ctx, `INSERT INTO leases (`+leaseColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			r.JobID, r.CommandID, r.ControllerID, r.AppID, r.DeploymentID, r.Template.ID, r.Template.Digest, r.ProfileID, r.State, r.Version, r.Reason, r.CreatedAt.UnixNano(), r.ExpiresAt.UnixNano(), r.fingerprint, r.nonceHash, r.proof)
		if err != nil {
			return ledgerError(ctx, err)
		}
		if err := insertEvent(ctx, c, r, r.CreatedAt); err != nil {
			return err
		}
		created = true
		return nil
	})
	if err != nil {
		return record{}, false, err
	}
	return r, created, nil
}

func transitionAllowed(from, to State) bool {
	switch from {
	case Reserved:
		return to == Starting || to == CleanupPending
	case Starting:
		return to == Active || to == CleanupPending
	case Active:
		return to == CleanupPending
	case CleanupFailed:
		return to == CleanupPending
	case CleanupPending:
		return to == CleanupFailed || to == Cleaned
	default:
		return false
	}
}

func (l *Ledger) advance(ctx context.Context, r record, to State, reason string, clock func() time.Time) (record, error) {
	if !transitionAllowed(r.State, to) {
		return record{}, ErrConflict
	}
	err := l.write(ctx, func(c *sql.Conn) error {
		now := clock().UTC()
		// Recheck after acquiring the writer lock; a stalled metadata writer
		// must not activate a lease using a stale pre-lock deadline check.
		if (to == Starting || to == Active) && !now.Before(r.ExpiresAt) {
			return ErrConflict
		}
		result, err := c.ExecContext(ctx, "UPDATE leases SET state=?,version=version+1,reason=? WHERE job_id=? AND state=? AND version=?", to, reason, r.JobID, r.State, r.Version)
		if err != nil {
			return ledgerError(ctx, err)
		}
		n, err := result.RowsAffected()
		if err != nil || n != 1 {
			return ErrConflict
		}
		r.State, r.Version, r.Reason = to, r.Version+1, reason
		return insertEvent(ctx, c, r, now)
	})
	if err != nil {
		return record{}, err
	}
	return r, nil
}

func insertEvent(ctx context.Context, c *sql.Conn, r record, now time.Time) error {
	_, err := c.ExecContext(ctx, "INSERT INTO events(job_id,version,state,reason,created_at) VALUES (?,?,?,?,?)", r.JobID, r.Version, r.State, r.Reason, now.UnixNano())
	if err != nil {
		return ledgerError(ctx, err)
	}
	return nil
}

func (l *Ledger) occupied(ctx context.Context) ([]record, error) {
	rows, err := l.db.QueryContext(ctx, "SELECT "+leaseColumns+" FROM leases WHERE state!='CLEANED' LIMIT 2")
	if err != nil {
		return nil, ledgerError(ctx, err)
	}
	defer rows.Close()
	result := make([]record, 0)
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, ErrLedger
		}
		result = append(result, r)
	}
	if rows.Err() != nil || len(result) > 1 {
		return nil, ErrLedger
	}
	return result, nil
}

func (l *Ledger) guardFresh(ctx context.Context, now time.Time) (bool, error) {
	var stamp int64
	if err := l.db.QueryRowContext(ctx, "SELECT heartbeat_at FROM guard WHERE id=1").Scan(&stamp); err != nil {
		return false, ledgerError(ctx, err)
	}
	return stamp > 0 && now.UnixNano() >= stamp && now.Sub(time.Unix(0, stamp)) <= 10*time.Second, nil
}

func (l *Ledger) heartbeat(ctx context.Context, now time.Time) error {
	_, err := l.db.ExecContext(ctx, "UPDATE guard SET heartbeat_at=? WHERE id=1", now.UnixNano())
	if err != nil {
		return ledgerError(ctx, err)
	}
	return nil
}
