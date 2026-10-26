package storage

import (
	"context"
	"encoding/json"
	"time"
)

// Events returns a bounded immutable event page, ordered by deployment version.
// The caller must first authorize access to the deployment.
func (s *Store) Events(ctx context.Context, deploymentID string, afterSequence int64, limit int) ([]Event, error) {
	if !validIDs(deploymentID) || afterSequence < 0 || limit < 1 || limit > 100 {
		return nil, ErrInvalidInput
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,event_type,deployment_id,app_id,sequence,generation,attempt,
        COALESCE(from_state,''),to_state,reason_code,actor_kind,actor_id,correlation_id,created_at
        FROM deployment_events WHERE deployment_id=? AND sequence>? ORDER BY sequence LIMIT ?`, deploymentID, afterSequence, limit)
	if err != nil {
		return nil, databaseError(ctx, err)
	}
	defer rows.Close()
	result := make([]Event, 0)
	for rows.Next() {
		var event Event
		var created int64
		if err := rows.Scan(&event.ID, &event.Type, &event.DeploymentID, &event.AppID, &event.Sequence, &event.Generation,
			&event.Attempt, &event.FromState, &event.ToState, &event.Reason, &event.Actor.Kind, &event.Actor.ID, &event.CorrelationID, &created); err != nil {
			return nil, databaseError(ctx, err)
		}
		event.CreatedAt = time.Unix(0, created).UTC()
		result = append(result, event)
	}
	if err := rows.Err(); err != nil {
		return nil, databaseError(ctx, err)
	}
	return result, nil
}

type OutboxMessage struct {
	ID    int64
	Event Event
}

// PendingOutbox is an ordered, at-least-once queue for a single dispatcher.
// Consumers must deduplicate by Event.ID. It does not claim or send messages.
func (s *Store) PendingOutbox(ctx context.Context, limit int) ([]OutboxMessage, error) {
	if limit < 1 || limit > 100 {
		return nil, ErrInvalidInput
	}
	rows, err := s.db.QueryContext(ctx, "SELECT id,payload FROM outbox WHERE delivered_at IS NULL ORDER BY id LIMIT ?", limit)
	if err != nil {
		return nil, databaseError(ctx, err)
	}
	defer rows.Close()
	result := make([]OutboxMessage, 0)
	for rows.Next() {
		var message OutboxMessage
		var payload string
		if err := rows.Scan(&message.ID, &payload); err != nil {
			return nil, databaseError(ctx, err)
		}
		if err := json.Unmarshal([]byte(payload), &message.Event); err != nil {
			return nil, ErrIntegrity
		}
		result = append(result, message)
	}
	if err := rows.Err(); err != nil {
		return nil, databaseError(ctx, err)
	}
	return result, nil
}

// MarkDelivered acknowledges a durably handled message. Repeating an ack is
// harmless; failed handlers must leave it pending. There is no exactly-once
// claim: a crash between delivery and ack causes redelivery with the same ID.
func (s *Store) MarkDelivered(ctx context.Context, id int64) error {
	if id < 1 {
		return ErrInvalidInput
	}
	result, err := s.db.ExecContext(ctx, `UPDATE outbox SET delivered_at=COALESCE(delivered_at,max(created_at,?)) WHERE id=?`, time.Now().UTC().UnixNano(), id)
	if err != nil {
		return databaseError(ctx, err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return databaseError(ctx, err)
	}
	if n != 1 {
		return ErrNotFound
	}
	return nil
}
