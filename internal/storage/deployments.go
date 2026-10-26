package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"dev-orchestrator/internal/domain"
)

var (
	idPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	keyPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
)

type Deployment struct {
	ID          string
	AppID       string
	BranchID    string
	SubmittedBy string
	State       domain.State
	Generation  int64
	Version     int64
	Attempt     int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// CreateDeployment is a persistence intent, not a raw browser request. Hash the
// full approved request deterministically before calling; do not store secrets
// or runtime environment values in event metadata or idempotency keys.
type CreateDeployment struct {
	ID             string
	AppID          string
	BranchID       string
	SubmittedBy    string
	IdempotencyKey string
	RequestHash    string
	CorrelationID  string
}

type Actor struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// Reason is a closed vocabulary, never repository output or free-text errors.
type Reason string

const (
	ReasonRequested        Reason = "requested"
	ReasonValidated        Reason = "validated"
	ReasonStarted          Reason = "started"
	ReasonCompleted        Reason = "completed"
	ReasonPolicyDenied     Reason = "policy_denied"
	ReasonTimeout          Reason = "timeout"
	ReasonError            Reason = "error"
	ReasonCancelled        Reason = "cancelled"
	ReasonRollbackVerified Reason = "rollback_verified"
)

func validReason(r Reason) bool {
	switch r {
	case ReasonRequested, ReasonValidated, ReasonStarted, ReasonCompleted, ReasonPolicyDenied, ReasonTimeout, ReasonError, ReasonCancelled, ReasonRollbackVerified:
		return true
	default:
		return false
	}
}

type Transition struct {
	DeploymentID       string
	ExpectedState      domain.State
	ExpectedVersion    int64
	ExpectedGeneration int64
	To                 domain.State
	Reason             Reason
	Actor              Actor
	CorrelationID      string
}

// Event is the only payload written to the state outbox/audit path. It has no
// arbitrary metadata map, repository URL, command, environment or log body.
type Event struct {
	ID            string       `json:"id"`
	Type          string       `json:"type"`
	DeploymentID  string       `json:"deployment_id"`
	AppID         string       `json:"app_id"`
	Sequence      int64        `json:"sequence"`
	Generation    int64        `json:"generation"`
	Attempt       int64        `json:"attempt"`
	FromState     domain.State `json:"from_state,omitempty"`
	ToState       domain.State `json:"to_state"`
	Reason        Reason       `json:"reason_code"`
	Actor         Actor        `json:"actor"`
	CorrelationID string       `json:"correlation_id"`
	CreatedAt     time.Time    `json:"created_at"`
}

const deploymentColumns = `id,app_id,branch_id,submitted_by,state,generation,version,attempt,created_at,updated_at`

func scanDeployment(row *sql.Row) (Deployment, error) {
	var d Deployment
	var created, updated int64
	err := row.Scan(&d.ID, &d.AppID, &d.BranchID, &d.SubmittedBy, &d.State, &d.Generation, &d.Version, &d.Attempt, &created, &updated)
	d.CreatedAt = time.Unix(0, created).UTC()
	d.UpdatedAt = time.Unix(0, updated).UTC()
	return d, err
}

// Create atomically reserves an application generation and records SUBMITTED,
// its first event, audit entry and outbox message. Same-key/same-intent retries
// return the original deployment with created=false and no duplicate event.
func (s *Store) Create(ctx context.Context, intent CreateDeployment) (deployment Deployment, created bool, err error) {
	if !validIDs(intent.ID, intent.AppID, intent.BranchID, intent.SubmittedBy, intent.CorrelationID) ||
		!keyPattern.MatchString(intent.IdempotencyKey) || !hashPattern.MatchString(intent.RequestHash) {
		return Deployment{}, false, ErrInvalidInput
	}
	err = s.write(ctx, func(conn *sql.Conn) error {
		var existingHash, existingID, author, branch string
		err := conn.QueryRowContext(ctx, `SELECT id,request_hash,submitted_by,branch_id FROM deployments WHERE app_id=? AND idempotency_key=?`,
			intent.AppID, intent.IdempotencyKey).Scan(&existingID, &existingHash, &author, &branch)
		if err == nil {
			if existingHash != intent.RequestHash || author != intent.SubmittedBy || branch != intent.BranchID {
				return ErrConflict
			}
			deployment, err = scanDeployment(conn.QueryRowContext(ctx, "SELECT "+deploymentColumns+" FROM deployments WHERE id=?", existingID))
			if err != nil {
				return databaseError(ctx, err)
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return databaseError(ctx, err)
		}
		now := time.Now().UTC()
		var generation int64
		err = conn.QueryRowContext(ctx, `UPDATE applications SET deployment_generation=deployment_generation+1,version=version+1,updated_at=?
            WHERE id=? AND state='enabled' AND deployment_generation<9007199254740991 RETURNING deployment_generation`,
			now.UnixNano(), intent.AppID).Scan(&generation)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrConflict // Absent, disabled, deleted or generation exhausted.
		}
		if err != nil {
			return databaseError(ctx, err)
		}
		_, err = conn.ExecContext(ctx, `INSERT INTO deployments
            (id,app_id,branch_id,submitted_by,state,generation,idempotency_key,request_hash,created_at,updated_at)
            VALUES (?,?,?,?,'SUBMITTED',?,?,?,?,?)`, intent.ID, intent.AppID, intent.BranchID, intent.SubmittedBy,
			generation, intent.IdempotencyKey, intent.RequestHash, now.UnixNano(), now.UnixNano())
		if err != nil {
			return databaseError(ctx, err)
		}
		deployment = Deployment{ID: intent.ID, AppID: intent.AppID, BranchID: intent.BranchID, SubmittedBy: intent.SubmittedBy,
			State: domain.Submitted, Generation: generation, Version: 1, Attempt: 1, CreatedAt: now, UpdatedAt: now}
		e := Event{Type: "deployment.submitted", DeploymentID: intent.ID, AppID: intent.AppID, Sequence: 1, Generation: generation,
			Attempt: 1, ToState: domain.Submitted, Reason: ReasonRequested, Actor: Actor{Kind: "user", ID: intent.SubmittedBy},
			CorrelationID: intent.CorrelationID, CreatedAt: now}
		if err := recordEvent(ctx, conn, &e); err != nil {
			return err
		}
		created = true
		return nil
	})
	if err != nil {
		return Deployment{}, false, err
	}
	return deployment, created, nil
}

func (s *Store) Deployment(ctx context.Context, id string) (Deployment, error) {
	if !validIDs(id) {
		return Deployment{}, ErrInvalidInput
	}
	d, err := scanDeployment(s.db.QueryRowContext(ctx, "SELECT "+deploymentColumns+" FROM deployments WHERE id=?", id))
	if err != nil {
		return Deployment{}, databaseError(ctx, err)
	}
	return d, nil
}

// Advance applies a compare-and-swap to one deployment's state/version/generation.
// It does not authorize actors, verify health, switch routes or decide whether
// rollback is safe. The controller must establish those facts before this call.
func (s *Store) Advance(ctx context.Context, change Transition) (Event, error) {
	if err := validateTransition(change); err != nil {
		return Event{}, err
	}
	var event Event
	err := s.write(ctx, func(conn *sql.Conn) error {
		var err error
		event, err = s.advanceTx(ctx, conn, change)
		return err
	})
	if err != nil {
		return Event{}, err
	}
	return event, nil
}

func validateTransition(change Transition) error {
	if !validIDs(change.DeploymentID, change.Actor.ID, change.CorrelationID) ||
		change.ExpectedVersion < 1 || change.ExpectedGeneration < 1 || !validReason(change.Reason) ||
		(change.Actor.Kind != "user" && change.Actor.Kind != "controller" && change.Actor.Kind != "worker") {
		return ErrInvalidInput
	}
	if !domain.CanTransition(change.ExpectedState, change.To) ||
		(change.To == domain.RolledBack) != (change.Reason == ReasonRollbackVerified) {
		return ErrInvalidState
	}
	return nil
}

func (s *Store) advanceTx(ctx context.Context, conn *sql.Conn, change Transition) (Event, error) {
	current, err := scanDeployment(conn.QueryRowContext(ctx, "SELECT "+deploymentColumns+" FROM deployments WHERE id=?", change.DeploymentID))
	if err != nil {
		return Event{}, databaseError(ctx, err)
	}
	if current.State != change.ExpectedState || current.Version != change.ExpectedVersion || current.Generation != change.ExpectedGeneration {
		return Event{}, ErrConflict
	}
	now := time.Now().UTC()
	result, err := conn.ExecContext(ctx, `UPDATE deployments SET state=?,version=version+1,updated_at=? WHERE id=? AND state=? AND version=? AND generation=?`,
		change.To, now.UnixNano(), change.DeploymentID, change.ExpectedState, change.ExpectedVersion, change.ExpectedGeneration)
	if err != nil {
		return Event{}, databaseError(ctx, err)
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return Event{}, ErrConflict
	}
	event := Event{Type: "deployment." + strings.ToLower(string(change.To)), DeploymentID: current.ID, AppID: current.AppID,
		Sequence: current.Version + 1, Generation: current.Generation, Attempt: current.Attempt, FromState: current.State,
		ToState: change.To, Reason: change.Reason, Actor: change.Actor, CorrelationID: change.CorrelationID, CreatedAt: now}
	if err := recordEvent(ctx, conn, &event); err != nil {
		return Event{}, err
	}
	return event, nil
}

func recordEvent(ctx context.Context, conn *sql.Conn, event *Event) error {
	id, err := newID()
	if err != nil {
		return ErrDatabase
	}
	event.ID = id
	payload, err := json.Marshal(event)
	if err != nil || len(payload) > 4096 {
		return ErrInvalidInput
	}
	var from any
	if event.FromState != "" {
		from = string(event.FromState)
	}
	_, err = conn.ExecContext(ctx, `INSERT INTO deployment_events
        (id,deployment_id,app_id,sequence,generation,attempt,event_type,from_state,to_state,reason_code,actor_kind,actor_id,correlation_id,created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, event.DeploymentID, event.AppID, event.Sequence, event.Generation, event.Attempt,
		event.Type, from, event.ToState, event.Reason, event.Actor.Kind, event.Actor.ID, event.CorrelationID, event.CreatedAt.UnixNano())
	if err != nil {
		return databaseError(ctx, err)
	}
	_, err = conn.ExecContext(ctx, `INSERT INTO audit_events
        (id,deployment_event_id,actor_kind,actor_id,action,target_type,target_id,correlation_id,sanitized_metadata,created_at) VALUES (?,?,?,?,?,'deployment',?,?,?,?)`,
		id, id, event.Actor.Kind, event.Actor.ID, event.Type, event.DeploymentID, event.CorrelationID, string(payload), event.CreatedAt.UnixNano())
	if err != nil {
		return databaseError(ctx, err)
	}
	_, err = conn.ExecContext(ctx, `INSERT INTO outbox (event_id,event_type,aggregate_id,payload,created_at) VALUES (?,?,?,?,?)`,
		id, event.Type, event.DeploymentID, string(payload), event.CreatedAt.UnixNano())
	if err != nil {
		return databaseError(ctx, err)
	}
	return nil
}

func validIDs(ids ...string) bool {
	for _, id := range ids {
		if !idPattern.MatchString(id) {
			return false
		}
	}
	return true
}

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
