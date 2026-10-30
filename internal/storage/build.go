package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"dev-orchestrator/internal/artifacts"
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/domain"
)

type BuildIntent struct {
	Job           contracts.BuildJob
	Actor         Actor
	CorrelationID string
}

func (i BuildIntent) valid() bool {
	return i.Job.Validate(time.Now()) == nil && validIDs(i.Actor.ID, i.CorrelationID) && (i.Actor.Kind == "controller" || i.Actor.Kind == "worker")
}
func buildHash(j contracts.BuildJob) string { b, _ := json.Marshal(j); return contracts.Digest(b) }
func (s *Store) BeginBuild(ctx context.Context, i BuildIntent) error {
	if !i.valid() {
		return ErrInvalidInput
	}
	return s.write(ctx, func(c *sql.Conn) error {
		var existing string
		e := c.QueryRowContext(ctx, "SELECT job_hash FROM build_attempts WHERE job_id=?", i.Job.Clone.JobID).Scan(&existing)
		if e == nil {
			if existing != buildHash(i.Job) {
				return ErrConflict
			}
			return s.buildFence(ctx, c, i, "building")
		}
		if e != sql.ErrNoRows {
			return databaseError(ctx, e)
		}
		var payload string
		var version int64
		e = c.QueryRowContext(ctx, `SELECT a.result_json,d.version FROM clone_attempts a JOIN deployments d ON d.id=a.deployment_id WHERE a.job_id=? AND a.job_hash=? AND a.outcome='success' AND d.state='CLONING' AND d.version=a.expected_version AND d.generation=a.generation AND d.attempt=a.attempt AND d.commit_sha=a.commit_sha AND a.expires_at>?`, i.Job.Clone.JobID, cloneJobHash(i.Job.Clone), time.Now().UnixNano()).Scan(&payload, &version)
		if e != nil {
			return databaseError(ctx, e)
		}
		r, e := contracts.DecodeCloneResult(strings.NewReader(payload), i.Job.Clone)
		if e != nil || r.SHA != i.Job.SHA || r.ContextID != i.Job.ContextID {
			return ErrConflict
		}
		now := time.Now().UnixNano()
		job, _ := json.Marshal(i.Job)
		_, e = c.ExecContext(ctx, `INSERT INTO build_attempts(job_id,deployment_id,attempt,generation,job_hash,job_json,expires_at,expected_version,stage,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,'building',?,?)`, i.Job.Clone.JobID, i.Job.Clone.DeploymentID, i.Job.Clone.Attempt, i.Job.Clone.Generation, buildHash(i.Job), string(job), i.Job.ExpiresAt.UnixNano(), version+1, now, now)
		if e != nil {
			return databaseError(ctx, e)
		}
		_, e = s.advanceTx(ctx, c, Transition{DeploymentID: i.Job.Clone.DeploymentID, ExpectedState: domain.Cloning, ExpectedVersion: version, ExpectedGeneration: i.Job.Clone.Generation, To: domain.Building, Reason: ReasonStarted, Actor: i.Actor, CorrelationID: i.CorrelationID})
		if e != nil {
			return e
		}
		return buildEvent(ctx, c, i, "build.started", []byte(`{}`))
	})
}
func (s *Store) buildFence(ctx context.Context, c *sql.Conn, i BuildIntent, stage string) error {
	var n int
	e := c.QueryRowContext(ctx, `SELECT count(*) FROM build_attempts a JOIN deployments d ON d.id=a.deployment_id WHERE a.job_id=? AND a.job_hash=? AND a.stage=? AND a.expires_at>? AND d.version=a.expected_version AND d.attempt=a.attempt AND d.generation=a.generation AND d.state=?`, i.Job.Clone.JobID, buildHash(i.Job), stage, time.Now().UnixNano(), map[string]string{"building": "BUILDING", "scanning": "SCANNING", "admitted": "SCANNING"}[stage]).Scan(&n)
	if e != nil {
		return databaseError(ctx, e)
	}
	if n != 1 {
		return ErrConflict
	}
	return nil
}
func (s *Store) RecordBuildExport(ctx context.Context, i BuildIntent, r artifacts.Receipt) error {
	if !i.valid() || !contracts.ValidObjectID(r.ObjectID) || !contracts.ValidDigest(r.Digest) || r.Bytes < 1 || r.Bytes > i.Job.Policy.Limits.UploadBytes || r.Binding != (artifacts.Binding{JobID: i.Job.Clone.JobID, DeploymentID: i.Job.Clone.DeploymentID, Attempt: i.Job.Clone.Attempt, Generation: i.Job.Clone.Generation}) {
		return ErrInvalidInput
	}
	return s.write(ctx, func(c *sql.Conn) error {
		var stage, object, digest string
		var priorBytes sql.NullInt64
		var version int64
		e := c.QueryRowContext(ctx, "SELECT stage,COALESCE(object_id,''),COALESCE(archive_digest,''),expected_version,archive_bytes FROM build_attempts WHERE job_id=?", i.Job.Clone.JobID).Scan(&stage, &object, &digest, &version, &priorBytes)
		if e != nil {
			return databaseError(ctx, e)
		}
		if stage == "scanning" && object == r.ObjectID && digest == r.Digest && priorBytes.Valid && priorBytes.Int64 == r.Bytes {
			return s.buildFence(ctx, c, i, "scanning")
		}
		if e = s.buildFence(ctx, c, i, "building"); e != nil {
			return e
		}
		_, e = s.advanceTx(ctx, c, Transition{DeploymentID: i.Job.Clone.DeploymentID, ExpectedState: domain.Building, ExpectedVersion: version, ExpectedGeneration: i.Job.Clone.Generation, To: domain.Scanning, Reason: ReasonCompleted, Actor: i.Actor, CorrelationID: i.CorrelationID})
		if e != nil {
			return e
		}
		_, e = c.ExecContext(ctx, `UPDATE build_attempts SET stage='scanning',object_id=?,archive_digest=?,archive_bytes=?,expected_version=expected_version+1,updated_at=? WHERE job_id=?`, r.ObjectID, r.Digest, r.Bytes, time.Now().UnixNano(), i.Job.Clone.JobID)
		if e != nil {
			return databaseError(ctx, e)
		}
		b, _ := json.Marshal(struct {
			Digest string `json:"archive_digest"`
			Bytes  int64  `json:"bytes"`
		}{r.Digest, r.Bytes})
		return buildEvent(ctx, c, i, "build.exported", b)
	})
}
func (s *Store) RecordArtifact(ctx context.Context, i BuildIntent, r contracts.ArtifactResult) error {
	if r.Outcome != "admitted" {
		return s.RecordBuildFailure(ctx, i, r)
	}
	if !i.valid() || r.Validate(i.Job) != nil {
		return ErrInvalidInput
	}
	return s.write(ctx, func(c *sql.Conn) error {
		var stage, archive string
		var prior sql.NullString
		e := c.QueryRowContext(ctx, "SELECT stage,COALESCE(archive_digest,''),result_json FROM build_attempts WHERE job_id=?", i.Job.Clone.JobID).Scan(&stage, &archive, &prior)
		if e != nil {
			return databaseError(ctx, e)
		}
		b, _ := json.Marshal(r)
		if prior.Valid {
			if prior.String == string(b) && stage == "admitted" {
				return s.buildFence(ctx, c, i, "admitted")
			}
			return ErrConflict
		}
		expected := stage
		if expected != "building" && expected != "scanning" {
			return ErrConflict
		}
		if e = s.buildFence(ctx, c, i, expected); e != nil {
			return e
		}
		if r.Outcome == "admitted" && (stage != "scanning" || archive != r.ArchiveDigest) {
			return ErrConflict
		}
		_, e = c.ExecContext(ctx, "UPDATE build_attempts SET stage=?,result_json=?,updated_at=? WHERE job_id=?", r.Outcome, string(b), time.Now().UnixNano(), i.Job.Clone.JobID)
		if e != nil {
			return databaseError(ctx, e)
		}
		if r.Outcome == "admitted" {
			_, e = c.ExecContext(ctx, "UPDATE deployments SET image_digest=? WHERE id=?", r.ImageDigest, i.Job.Clone.DeploymentID)
			if e != nil {
				return databaseError(ctx, e)
			}
		}
		return buildEvent(ctx, c, i, "scan."+r.Outcome, b)
	})
}
func buildEvent(ctx context.Context, c *sql.Conn, i BuildIntent, kind string, b []byte) error {
	id, e := newID()
	if e != nil {
		return e
	}
	now := time.Now().UnixNano()
	_, e = c.ExecContext(ctx, "INSERT INTO build_events(id,job_id,event_type,payload,created_at) VALUES(?,?,?,?,?)", id, i.Job.Clone.JobID, kind, string(b), now)
	if e != nil {
		return databaseError(ctx, e)
	}
	_, e = c.ExecContext(ctx, `INSERT INTO audit_events(id,actor_kind,actor_id,action,target_type,target_id,correlation_id,sanitized_metadata,created_at) VALUES(?,?,?,?,'deployment',?,?,?,?)`, id, i.Actor.Kind, i.Actor.ID, kind, i.Job.Clone.DeploymentID, i.CorrelationID, string(b), now)
	if e != nil {
		return databaseError(ctx, e)
	}
	_, e = c.ExecContext(ctx, "INSERT INTO build_outbox(event_id,created_at) VALUES(?,?)", id, now)
	return dbCloneError(ctx, e)
}

// AdmittedArtifact is a policy-bound eligibility record, never deployment approval.
func (s *Store) AdmittedArtifact(ctx context.Context, i BuildIntent) (contracts.ArtifactResult, error) {
	if !i.valid() {
		return contracts.ArtifactResult{}, ErrInvalidInput
	}
	var result contracts.ArtifactResult
	e := s.write(ctx, func(c *sql.Conn) error {
		if e := s.buildFence(ctx, c, i, "admitted"); e != nil {
			return e
		}
		var data string
		if e := c.QueryRowContext(ctx, "SELECT result_json FROM build_attempts WHERE job_id=?", i.Job.Clone.JobID).Scan(&data); e != nil {
			return databaseError(ctx, e)
		}
		if json.Unmarshal([]byte(data), &result) != nil || result.Validate(i.Job) != nil {
			return ErrIntegrity
		}
		return nil
	})
	return result, e
}

// RecordBuildFailure records cleanup-triggering outcomes after a deadline or
// user cancellation. Expiry never grants authority to admit an artifact.
func (s *Store) RecordBuildFailure(ctx context.Context, i BuildIntent, r contracts.ArtifactResult) error {
	if r.Outcome == "admitted" || r.Validate(i.Job) != nil || !validIDs(i.Actor.ID, i.CorrelationID) || (i.Actor.Kind != "controller" && i.Actor.Kind != "worker") {
		return ErrInvalidInput
	}
	return s.write(ctx, func(c *sql.Conn) error {
		var stage, hash string
		var prior sql.NullString
		var version int64
		e := c.QueryRowContext(ctx, "SELECT stage,job_hash,result_json,expected_version FROM build_attempts WHERE job_id=?", i.Job.Clone.JobID).Scan(&stage, &hash, &prior, &version)
		if e != nil {
			return databaseError(ctx, e)
		}
		if hash != buildHash(i.Job) {
			return ErrConflict
		}
		b, _ := json.Marshal(r)
		if prior.Valid {
			if prior.String == string(b) {
				return nil
			}
			return ErrConflict
		}
		if stage != "building" && stage != "scanning" {
			return ErrConflict
		}
		d, e := scanDeployment(c.QueryRowContext(ctx, "SELECT "+deploymentColumns+" FROM deployments WHERE id=?", i.Job.Clone.DeploymentID))
		if e != nil {
			return databaseError(ctx, e)
		}
		if d.Attempt != i.Job.Clone.Attempt || d.Generation != i.Job.Clone.Generation {
			return ErrConflict
		}
		if d.State == domain.Building || d.State == domain.Scanning {
			if d.Version != version {
				return ErrConflict
			}
			reason := ReasonError
			if r.Outcome == "timeout" {
				reason = ReasonTimeout
			}
			if r.Outcome == "denied" {
				reason = ReasonPolicyDenied
			}
			if r.Outcome == "cancelled" {
				reason = ReasonCancelled
			}
			target := domain.Failed
			if r.Outcome == "cancelled" {
				target = domain.Cancelled
			}
			if _, e = s.advanceTx(ctx, c, Transition{DeploymentID: d.ID, ExpectedState: d.State, ExpectedVersion: d.Version, ExpectedGeneration: d.Generation, To: target, Reason: reason, Actor: i.Actor, CorrelationID: i.CorrelationID}); e != nil {
				return e
			}
		} else if d.State != domain.Cancelled && d.State != domain.Failed {
			return ErrConflict
		}
		_, e = c.ExecContext(ctx, "UPDATE build_attempts SET stage=?,result_json=?,updated_at=? WHERE job_id=?", r.Outcome, string(b), time.Now().UnixNano(), i.Job.Clone.JobID)
		if e != nil {
			return databaseError(ctx, e)
		}
		return buildEvent(ctx, c, i, "scan."+r.Outcome, b)
	})
}

type BuildMessage struct {
	ID      int64
	EventID string
	Type    string
	Payload json.RawMessage
}

func (s *Store) PendingBuildOutbox(ctx context.Context, limit int) ([]BuildMessage, error) {
	if limit < 1 || limit > 100 {
		return nil, ErrInvalidInput
	}
	rows, e := s.db.QueryContext(ctx, `SELECT o.id,e.id,e.event_type,e.payload FROM build_outbox o JOIN build_events e ON e.id=o.event_id WHERE o.delivered_at IS NULL ORDER BY o.id LIMIT ?`, limit)
	if e != nil {
		return nil, databaseError(ctx, e)
	}
	defer rows.Close()
	var list []BuildMessage
	for rows.Next() {
		var m BuildMessage
		var data string
		if e = rows.Scan(&m.ID, &m.EventID, &m.Type, &data); e != nil {
			return nil, databaseError(ctx, e)
		}
		m.Payload = json.RawMessage(data)
		list = append(list, m)
	}
	return list, dbCloneError(ctx, rows.Err())
}
func (s *Store) MarkBuildDelivered(ctx context.Context, id int64) error {
	if id < 1 {
		return ErrInvalidInput
	}
	r, e := s.db.ExecContext(ctx, "UPDATE build_outbox SET delivered_at=COALESCE(delivered_at,max(created_at,?)) WHERE id=?", time.Now().UnixNano(), id)
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

// BuildExport is the durable crash-recovery boundary. It returns no credential
// or host path and does not turn a pending export into an admitted artifact.
func (s *Store) BuildExport(ctx context.Context, i BuildIntent) (artifacts.Receipt, error) {
	if !i.valid() {
		return artifacts.Receipt{}, ErrInvalidInput
	}
	var receipt artifacts.Receipt
	e := s.write(ctx, func(c *sql.Conn) error {
		if e := s.buildFence(ctx, c, i, "scanning"); e != nil {
			return e
		}
		var object, digest string
		if e := c.QueryRowContext(ctx, "SELECT object_id,archive_digest,archive_bytes FROM build_attempts WHERE job_id=?", i.Job.Clone.JobID).Scan(&object, &digest, &receipt.Bytes); e != nil {
			return databaseError(ctx, e)
		}
		receipt.ObjectID = object
		receipt.Digest = digest
		receipt.Binding = artifacts.Binding{JobID: i.Job.Clone.JobID, DeploymentID: i.Job.Clone.DeploymentID, Attempt: i.Job.Clone.Attempt, Generation: i.Job.Clone.Generation}
		return nil
	})
	return receipt, e
}
