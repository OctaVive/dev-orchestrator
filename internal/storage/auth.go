package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"dev-orchestrator/internal/domain"
)

var ErrAuthInactive = errors.New("identity or session is not active")

// Credential is service-private authentication material, never an API response.
type Credential struct {
	ID           string
	Username     string
	PasswordHash string `json:"-"`
	AuthEpoch    int64
	Disabled     bool
	Role         domain.Role
}

const credentialColumns = `u.id,u.username,u.password_hash,u.auth_epoch,u.disabled_at,
    CASE WHEN EXISTS(SELECT 1 FROM user_roles r WHERE r.user_id=u.id AND r.role_id='admin') THEN 'admin'
         WHEN EXISTS(SELECT 1 FROM user_roles r WHERE r.user_id=u.id AND r.role_id='user') THEN 'user' ELSE '' END`

func scanCredential(row *sql.Row) (Credential, error) {
	var c Credential
	var disabled sql.NullInt64
	err := row.Scan(&c.ID, &c.Username, &c.PasswordHash, &c.AuthEpoch, &disabled, &c.Role)
	c.Disabled = disabled.Valid
	return c, err
}

func (s *Store) Credential(ctx context.Context, username string) (Credential, error) {
	c, err := scanCredential(s.db.QueryRowContext(ctx, "SELECT "+credentialColumns+" FROM users u WHERE username=?", username))
	if err != nil {
		return Credential{}, databaseError(ctx, err)
	}
	return c, nil
}

func (s *Store) SetupAllowed(ctx context.Context) (bool, error) {
	var closed int
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users) OR EXISTS(SELECT 1 FROM audit_events WHERE action='auth.setup_completed')`).Scan(&closed)
	if err != nil {
		return false, databaseError(ctx, err)
	}
	return closed == 0, nil
}

// BootstrapAdmin serializes first-user creation and a permanent audit marker.
// Removing users later does not reopen setup. No default credentials exist.
func (s *Store) BootstrapAdmin(ctx context.Context, username, hash, correlation string, now time.Time) (Credential, error) {
	if !validIDs(correlation) || username == "" || username != strings.ToLower(username) || !strings.HasPrefix(hash, "$argon2id$") || now.IsZero() {
		return Credential{}, ErrInvalidInput
	}
	var result Credential
	err := s.write(ctx, func(conn *sql.Conn) error {
		var closed int
		if err := conn.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users) OR EXISTS(SELECT 1 FROM audit_events WHERE action='auth.setup_completed')`).Scan(&closed); err != nil {
			return databaseError(ctx, err)
		}
		if closed != 0 {
			return ErrConflict
		}
		id, err := newID()
		if err != nil {
			return ErrDatabase
		}
		if _, err := conn.ExecContext(ctx, `INSERT INTO users(id,username,password_hash,created_at,updated_at) VALUES (?,?,?,?,?)`, id, username, hash, now.UnixNano(), now.UnixNano()); err != nil {
			return databaseError(ctx, err)
		}
		if _, err := conn.ExecContext(ctx, "INSERT INTO user_roles(user_id,role_id) VALUES (?,'admin')", id); err != nil {
			return databaseError(ctx, err)
		}
		if err := authAudit(ctx, conn, "auth.setup_completed", id, "user", id, correlation, "setup", now); err != nil {
			return err
		}
		result = Credential{ID: id, Username: username, PasswordHash: hash, AuthEpoch: 1, Role: domain.Admin}
		return nil
	})
	if err != nil {
		return Credential{}, err
	}
	return result, nil
}

type SessionIdentity struct {
	SessionID     string
	UserID        string
	Username      string
	Role          domain.Role
	CreatedAt     time.Time
	IdleExpiresAt time.Time
	ExpiresAt     time.Time
}

type IssueSession struct {
	Credential        Credential
	TokenHash         string
	PreviousTokenHash string
	CorrelationID     string
	Now               time.Time
}

func (s *Store) IssueSession(ctx context.Context, in IssueSession) (SessionIdentity, error) {
	if !validIDs(in.Credential.ID, in.CorrelationID) || !hashPattern.MatchString(in.TokenHash) ||
		in.PreviousTokenHash != "" && (!hashPattern.MatchString(in.PreviousTokenHash) || in.PreviousTokenHash == in.TokenHash) || in.Now.IsZero() {
		return SessionIdentity{}, ErrInvalidInput
	}
	var result SessionIdentity
	err := s.write(ctx, func(conn *sql.Conn) error {
		current, err := scanCredential(conn.QueryRowContext(ctx, "SELECT "+credentialColumns+" FROM users u WHERE id=?", in.Credential.ID))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAuthInactive
		}
		if err != nil {
			return databaseError(ctx, err)
		}
		if current.Disabled || current.PasswordHash != in.Credential.PasswordHash || current.AuthEpoch != in.Credential.AuthEpoch ||
			(current.Role != domain.Admin && current.Role != domain.User) {
			return ErrAuthInactive
		}
		id, err := newID()
		if err != nil {
			return ErrDatabase
		}
		idle, absolute := in.Now.Add(30*time.Minute), in.Now.Add(12*time.Hour)
		_, err = conn.ExecContext(ctx, `INSERT INTO sessions
            (id,token_hash,user_id,kind,mfa_level,auth_epoch,created_at,last_seen_at,idle_expires_at,absolute_expires_at)
            VALUES (?,?,?,'portal',0,?,?,?,?,?)`, id, in.TokenHash, current.ID, current.AuthEpoch,
			in.Now.UnixNano(), in.Now.UnixNano(), idle.UnixNano(), absolute.UnixNano())
		if err != nil {
			return databaseError(ctx, err)
		}
		if in.PreviousTokenHash != "" {
			if _, err := conn.ExecContext(ctx, "UPDATE sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL", in.Now.UnixNano(), in.PreviousTokenHash); err != nil {
				return databaseError(ctx, err)
			}
		}
		if err := authAudit(ctx, conn, "auth.login_succeeded", current.ID, "session", id, in.CorrelationID, "password", in.Now); err != nil {
			return err
		}
		result = SessionIdentity{SessionID: id, UserID: current.ID, Username: current.Username, Role: current.Role,
			CreatedAt: in.Now.UTC(), IdleExpiresAt: idle.UTC(), ExpiresAt: absolute.UTC()}
		return nil
	})
	if err != nil {
		return SessionIdentity{}, err
	}
	return result, nil
}

// ResolveSession rechecks account/role/epoch and expiry on every request. It
// never accepts client roles or pending-MFA sessions and has no positive cache.
func (s *Store) ResolveSession(ctx context.Context, tokenHash string, now time.Time) (SessionIdentity, error) {
	if !hashPattern.MatchString(tokenHash) || now.IsZero() {
		return SessionIdentity{}, ErrAuthInactive
	}
	var result SessionIdentity
	err := s.write(ctx, func(conn *sql.Conn) error {
		var created, absolute, idle int64
		err := conn.QueryRowContext(ctx, `SELECT s.id,u.id,u.username,
            CASE WHEN EXISTS(SELECT 1 FROM user_roles r WHERE r.user_id=u.id AND r.role_id='admin') THEN 'admin'
                 WHEN EXISTS(SELECT 1 FROM user_roles r WHERE r.user_id=u.id AND r.role_id='user') THEN 'user' ELSE '' END,
            s.created_at,s.absolute_expires_at,min(s.absolute_expires_at,max(s.idle_expires_at,?))
            FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.kind='portal'
            AND s.revoked_at IS NULL AND u.disabled_at IS NULL AND s.auth_epoch=u.auth_epoch
            AND s.created_at<=? AND s.idle_expires_at>? AND s.absolute_expires_at>?`,
			now.Add(30*time.Minute).UnixNano(), tokenHash, now.UnixNano(), now.UnixNano(), now.UnixNano()).Scan(
			&result.SessionID, &result.UserID, &result.Username, &result.Role, &created, &absolute, &idle)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAuthInactive
		}
		if err != nil {
			return databaseError(ctx, err)
		}
		if result.Role != domain.Admin && result.Role != domain.User {
			return ErrAuthInactive
		}
		_, err = conn.ExecContext(ctx, "UPDATE sessions SET last_seen_at=max(last_seen_at,?),idle_expires_at=? WHERE id=?", now.UnixNano(), idle, result.SessionID)
		if err != nil {
			return databaseError(ctx, err)
		}
		result.CreatedAt, result.ExpiresAt, result.IdleExpiresAt = time.Unix(0, created).UTC(), time.Unix(0, absolute).UTC(), time.Unix(0, idle).UTC()
		return nil
	})
	if err != nil {
		return SessionIdentity{}, err
	}
	return result, nil
}

func (s *Store) RevokeSession(ctx context.Context, tokenHash, correlation string, now time.Time) error {
	if !hashPattern.MatchString(tokenHash) || !validIDs(correlation) || now.IsZero() {
		return ErrInvalidInput
	}
	return s.write(ctx, func(conn *sql.Conn) error {
		var id, user string
		var revoked sql.NullInt64
		err := conn.QueryRowContext(ctx, "SELECT id,user_id,revoked_at FROM sessions WHERE token_hash=?", tokenHash).Scan(&id, &user, &revoked)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAuthInactive
		}
		if err != nil {
			return databaseError(ctx, err)
		}
		if revoked.Valid {
			return nil
		}
		if _, err := conn.ExecContext(ctx, "UPDATE sessions SET revoked_at=? WHERE id=?", now.UnixNano(), id); err != nil {
			return databaseError(ctx, err)
		}
		return authAudit(ctx, conn, "auth.logout", user, "session", id, correlation, "revoked", now)
	})
}

// RecordLoginFailure stores no submitted username, IP, password or token.
// Service admission limits bound how often this is called.
func (s *Store) RecordLoginFailure(ctx context.Context, correlation string, now time.Time) error {
	if !validIDs(correlation) || now.IsZero() {
		return ErrInvalidInput
	}
	return s.write(ctx, func(conn *sql.Conn) error {
		return authAudit(ctx, conn, "auth.login_failed", "", "session", "", correlation, "invalid_credentials", now)
	})
}

func (s *Store) RecordSetupFailure(ctx context.Context, correlation string, now time.Time) error {
	if !validIDs(correlation) || now.IsZero() {
		return ErrInvalidInput
	}
	return s.write(ctx, func(conn *sql.Conn) error {
		return authAudit(ctx, conn, "auth.setup_failed", "", "infrastructure", "", correlation, "invalid_credentials", now)
	})
}

func authAudit(ctx context.Context, conn *sql.Conn, action, actor, targetType, target, correlation, reason string, now time.Time) error {
	id, err := newID()
	if err != nil {
		return ErrDatabase
	}
	kind := "user"
	var actorValue, targetValue any
	if actor == "" {
		kind = "anonymous"
	} else {
		actorValue = actor
	}
	if target != "" {
		targetValue = target
	}
	metadata, _ := json.Marshal(struct {
		Reason string `json:"reason"`
	}{reason})
	_, err = conn.ExecContext(ctx, `INSERT INTO audit_events
        (id,actor_kind,actor_id,action,target_type,target_id,correlation_id,sanitized_metadata,created_at) VALUES (?,?,?,?,?,?,?,?,?)`,
		id, kind, actorValue, action, targetType, targetValue, correlation, string(metadata), now.UnixNano())
	if err != nil {
		return databaseError(ctx, err)
	}
	return nil
}
