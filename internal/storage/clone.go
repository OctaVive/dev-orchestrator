package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/domain"
)

type CloneIntent struct {
	Job             contracts.CloneJob
	ExpectedVersion int64
	Actor           Actor
	CorrelationID   string
}

func (i CloneIntent) valid() bool {
	return i.Job.Validate(time.Now()) == nil && i.ExpectedVersion > 0 && validIDs(i.Actor.ID, i.CorrelationID) && (i.Actor.Kind == "controller" || i.Actor.Kind == "worker")
}
func cloneJobHash(j contracts.CloneJob) string {
	b, _ := json.Marshal(j)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// BeginClone binds an authorized intent to the current deployment and source.
// Callers must reserve the VM lease before invoking their host adapter.
func (s *Store) BeginClone(ctx context.Context, i CloneIntent) error {
	if !i.valid() {
		return ErrInvalidInput
	}
	return s.write(ctx, func(c *sql.Conn) error {
		d, e := scanDeployment(c.QueryRowContext(ctx, "SELECT "+deploymentColumns+" FROM deployments WHERE id=?", i.Job.DeploymentID))
		if e != nil {
			return databaseError(ctx, e)
		}
		if d.State != domain.Cloning || d.Version != i.ExpectedVersion || d.Generation != i.Job.Generation || d.Attempt != i.Job.Attempt {
			return ErrConflict
		}
		var repo, branch string
		if e = c.QueryRowContext(ctx, `SELECT r.canonical_url,b.ref_name FROM git_branches b JOIN git_repositories r ON r.id=b.repository_id WHERE b.id=?`, d.BranchID).Scan(&repo, &branch); e != nil {
			return databaseError(ctx, e)
		}
		if repo != i.Job.RepositoryURL || branch != i.Job.Branch {
			return ErrConflict
		}
		var existing string
		e = c.QueryRowContext(ctx, "SELECT job_hash FROM clone_attempts WHERE job_id=?", i.Job.JobID).Scan(&existing)
		if e == nil {
			if existing == cloneJobHash(i.Job) {
				return nil
			}
			return ErrConflict
		}
		if e != sql.ErrNoRows {
			return databaseError(ctx, e)
		}
		now := time.Now().UTC().UnixNano()
		_, e = c.ExecContext(ctx, `INSERT INTO clone_attempts(job_id,deployment_id,attempt,generation,expected_version,lease_id,policy_hash,template_digest,job_hash,expires_at,outcome,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,'pending',?,?)`, i.Job.JobID, d.ID, i.Job.Attempt, i.Job.Generation, i.ExpectedVersion, i.Job.LeaseID, i.Job.PolicyHash, i.Job.TemplateDigest, cloneJobHash(i.Job), i.Job.ExpiresAt.UnixNano(), now, now)
		return dbCloneError(ctx, e)
	})
}
func dbCloneError(ctx context.Context, e error) error {
	if e == nil {
		return nil
	}
	return databaseError(ctx, e)
}

// RecordClone atomically persists resolution/result, audit and its outbox.
// No network operations occur under the SQLite transaction. Late results deny,
// even when they repeat a previously valid result after cancellation or expiry.
func (s *Store) RecordClone(ctx context.Context, i CloneIntent, r contracts.CloneResult) error {
	if !i.valid() || r.Validate(i.Job) != nil {
		return ErrInvalidInput
	}
	return s.write(ctx, func(c *sql.Conn) error {
		var hash, outcome string
		var sha sql.NullString
		var expected, expiry int64
		e := c.QueryRowContext(ctx, `SELECT job_hash,outcome,commit_sha,expected_version,expires_at FROM clone_attempts WHERE job_id=?`, i.Job.JobID).Scan(&hash, &outcome, &sha, &expected, &expiry)
		if e != nil {
			return databaseError(ctx, e)
		}
		if hash != cloneJobHash(i.Job) || time.Now().UnixNano() >= expiry {
			return ErrConflict
		}
		d, e := scanDeployment(c.QueryRowContext(ctx, "SELECT "+deploymentColumns+" FROM deployments WHERE id=?", i.Job.DeploymentID))
		if e != nil {
			return databaseError(ctx, e)
		}
		if d.State != domain.Cloning || d.Generation != i.Job.Generation || d.Attempt != i.Job.Attempt || d.Version != expected {
			return ErrConflict
		}
		if sha.Valid && sha.String != r.SHA {
			return ErrConflict
		}
		if outcome == r.Outcome {
			var data string
			if e = c.QueryRowContext(ctx, "SELECT result_json FROM clone_attempts WHERE job_id=?", i.Job.JobID).Scan(&data); e != nil {
				return databaseError(ctx, e)
			}
			b, _ := json.Marshal(r)
			if data == string(b) {
				return nil
			}
			return ErrConflict
		}
		if outcome != "pending" && outcome != "resolved" {
			return ErrConflict
		}
		if outcome == "pending" && (r.Outcome == "success" || r.SHA != "" && r.Outcome != "resolved") {
			return ErrConflict
		}
		if outcome == "resolved" && r.Outcome == "resolved" {
			return ErrConflict
		}
		now := time.Now().UTC()
		var commit any
		if r.SHA != "" {
			commit = r.SHA
		}
		payload, _ := json.Marshal(r)
		_, e = c.ExecContext(ctx, `UPDATE clone_attempts SET commit_sha=?,outcome=?,result_json=?,expected_version=expected_version+1,updated_at=? WHERE job_id=?`, commit, r.Outcome, string(payload), now.UnixNano(), i.Job.JobID)
		if e != nil {
			return databaseError(ctx, e)
		}
		_, e = c.ExecContext(ctx, `UPDATE deployments SET commit_sha=COALESCE(?,commit_sha),version=version+1,updated_at=? WHERE id=?`, commit, now.UnixNano(), d.ID)
		if e != nil {
			return databaseError(ctx, e)
		}
		if commit != nil {
			_, e = c.ExecContext(ctx, "UPDATE git_branches SET last_observed_sha=?,checked_at=? WHERE id=?", commit, now.UnixNano(), d.BranchID)
			if e != nil {
				return databaseError(ctx, e)
			}
		}
		id, e := newID()
		if e != nil {
			return e
		}
		eventType := "clone." + r.Outcome
		_, e = c.ExecContext(ctx, "INSERT INTO clone_events(id,job_id,event_type,payload,created_at) VALUES(?,?,?,?,?)", id, r.JobID, eventType, string(payload), now.UnixNano())
		if e != nil {
			return databaseError(ctx, e)
		}
		_, e = c.ExecContext(ctx, `INSERT INTO audit_events(id,actor_kind,actor_id,action,target_type,target_id,correlation_id,sanitized_metadata,created_at) VALUES(?,?,?,?,'deployment',?,?,?,?)`, id, i.Actor.Kind, i.Actor.ID, eventType, d.ID, i.CorrelationID, string(payload), now.UnixNano())
		if e != nil {
			return databaseError(ctx, e)
		}
		_, e = c.ExecContext(ctx, "INSERT INTO clone_outbox(event_id,created_at) VALUES(?,?)", id, now.UnixNano())
		return dbCloneError(ctx, e)
	})
}

type CloneMessage struct {
	ID      int64
	EventID string
	Type    string
	Result  contracts.CloneResult
}

func (s *Store) PendingCloneOutbox(ctx context.Context, limit int) ([]CloneMessage, error) {
	if limit < 1 || limit > 100 {
		return nil, ErrInvalidInput
	}
	rows, e := s.db.QueryContext(ctx, `SELECT o.id,e.id,e.event_type,e.payload FROM clone_outbox o JOIN clone_events e ON e.id=o.event_id WHERE o.delivered_at IS NULL ORDER BY o.id LIMIT ?`, limit)
	if e != nil {
		return nil, databaseError(ctx, e)
	}
	defer rows.Close()
	var list []CloneMessage
	for rows.Next() {
		var m CloneMessage
		var payload string
		if e = rows.Scan(&m.ID, &m.EventID, &m.Type, &payload); e != nil {
			return nil, databaseError(ctx, e)
		}
		if json.Unmarshal([]byte(payload), &m.Result) != nil {
			return nil, ErrIntegrity
		}
		list = append(list, m)
	}
	return list, dbCloneError(ctx, rows.Err())
}
func (s *Store) MarkCloneDelivered(ctx context.Context, id int64) error {
	if id < 1 {
		return ErrInvalidInput
	}
	r, e := s.db.ExecContext(ctx, "UPDATE clone_outbox SET delivered_at=COALESCE(delivered_at,max(created_at,?)) WHERE id=?", time.Now().UnixNano(), id)
	if e != nil {
		return databaseError(ctx, e)
	}
	n, e := r.RowsAffected()
	if e != nil {
		return databaseError(ctx, e)
	}
	if n != 1 {
		return ErrNotFound
	}
	return nil
}

// CloneReady is the durable prerequisite for M07 handoff. It never transitions
// state or claims that a guest assertion proves source trustworthiness.
func (s *Store) CloneReady(ctx context.Context, j contracts.CloneJob) (contracts.CloneResult, error) {
	if j.Validate(time.Now()) != nil {
		return contracts.CloneResult{}, ErrInvalidInput
	}
	var payload string
	e := s.db.QueryRowContext(ctx, `SELECT a.result_json FROM clone_attempts a JOIN deployments d ON d.id=a.deployment_id WHERE a.job_id=? AND a.job_hash=? AND a.outcome='success' AND d.state='CLONING' AND d.version=a.expected_version AND d.generation=a.generation AND d.attempt=a.attempt AND d.commit_sha=a.commit_sha AND a.expires_at>?`, j.JobID, cloneJobHash(j), time.Now().UnixNano()).Scan(&payload)
	if e != nil {
		return contracts.CloneResult{}, databaseError(ctx, e)
	}
	return contracts.DecodeCloneResult(strings.NewReader(payload), j)
}
