package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"dev-orchestrator/internal/domain"
)

func authFixture(t *testing.T) (*Store, Credential, time.Time) {
	t.Helper()
	s, _ := testStore(t)
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	c, err := s.BootstrapAdmin(context.Background(), "admin", "$argon2id$storage-fixture-not-a-real-password-hash", correlationID, now)
	if err != nil {
		t.Fatal(err)
	}
	return s, c, now
}

func issue(t *testing.T, s *Store, c Credential, now time.Time, hash, previous string) SessionIdentity {
	t.Helper()
	identity, err := s.IssueSession(context.Background(), IssueSession{Credential: c, TokenHash: hash, PreviousTokenHash: previous, Now: now, CorrelationID: correlationID})
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func TestBootstrapOneTimeAndPermanentMarker(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if allowed, err := s.SetupAllowed(ctx); err != nil || !allowed {
		t.Fatal("fresh setup unavailable", err)
	}
	results := make(chan error, 8)
	for range 8 {
		go func() {
			_, err := s.BootstrapAdmin(ctx, "admin", "$argon2id$storage-fixture", correlationID, time.Now())
			results <- err
		}()
	}
	winners := 0
	for range 8 {
		if err := <-results; err == nil {
			winners++
		} else if !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
	}
	if winners != 1 || scalar(t, s, "SELECT count(*) FROM users") != 1 || scalar(t, s, "SELECT count(*) FROM user_roles") != 1 {
		t.Fatal("bootstrap race created multiple admins")
	}
	execSQL(t, s, "DELETE FROM user_roles")
	execSQL(t, s, "DELETE FROM users")
	if allowed, err := s.SetupAllowed(ctx); err != nil || allowed {
		t.Fatal("deleting users reopened bootstrap", err)
	}
	if _, err := s.BootstrapAdmin(ctx, "other", "$argon2id$fixture", correlationID, time.Now()); !errors.Is(err, ErrConflict) {
		t.Fatal("setup marker bypassed", err)
	}
}

func TestAuthAuditFailureIsAtomic(t *testing.T) {
	s, _ := testStore(t)
	ctx, now := context.Background(), time.Now().UTC()
	execSQL(t, s, "CREATE TRIGGER fail_auth BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'test-failure'); END")
	if _, err := s.BootstrapAdmin(ctx, "admin", "$argon2id$fixture", correlationID, now); err == nil {
		t.Fatal("bootstrap ignored failed audit")
	}
	if scalar(t, s, "SELECT count(*) FROM users") != 0 || scalar(t, s, "SELECT count(*) FROM user_roles") != 0 {
		t.Fatal("bootstrap partially committed")
	}
	execSQL(t, s, "DROP TRIGGER fail_auth")
	c, err := s.BootstrapAdmin(ctx, "admin", "$argon2id$fixture", correlationID, now)
	if err != nil {
		t.Fatal(err)
	}
	one, two := strings.Repeat("a", 64), strings.Repeat("b", 64)
	issue(t, s, c, now, one, "")
	execSQL(t, s, "CREATE TRIGGER fail_auth BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'test-failure'); END")
	if _, err := s.IssueSession(ctx, IssueSession{Credential: c, TokenHash: two, PreviousTokenHash: one, CorrelationID: correlationID, Now: now}); err == nil {
		t.Fatal("session issuance ignored failed audit")
	}
	if scalar(t, s, "SELECT count(*) FROM sessions") != 1 {
		t.Fatal("failed login created session")
	}
	if _, err := s.ResolveSession(ctx, one, now); err != nil {
		t.Fatal("failed login revoked old session", err)
	}
	if err := s.RevokeSession(ctx, one, correlationID, now); err == nil {
		t.Fatal("logout ignored failed audit")
	}
	if _, err := s.ResolveSession(ctx, one, now); err != nil {
		t.Fatal("failed logout partially revoked", err)
	}
	execSQL(t, s, "DROP TRIGGER fail_auth")
	issue(t, s, c, now, two, one)
	if _, err := s.ResolveSession(ctx, one, now); !errors.Is(err, ErrAuthInactive) {
		t.Fatal("old session still active after rotation")
	}
	if err := s.RevokeSession(ctx, two, correlationID, now); err != nil {
		t.Fatal(err)
	}
	count := scalar(t, s, "SELECT count(*) FROM audit_events")
	if err := s.RevokeSession(ctx, two, correlationID, now); err != nil || scalar(t, s, "SELECT count(*) FROM audit_events") != count {
		t.Fatal("logout retry duplicated audit", err)
	}
}

func TestSessionIdleAndAbsoluteExpiry(t *testing.T) {
	for _, mode := range []string{"idle", "absolute"} {
		t.Run(mode, func(t *testing.T) {
			s, c, now := authFixture(t)
			hash := strings.Repeat("a", 64)
			identity := issue(t, s, c, now, hash, "")
			if identity.Role != domain.Admin || !identity.ExpiresAt.Equal(now.Add(12*time.Hour)) {
				t.Fatal("unexpected session policy")
			}
			if mode == "absolute" {
				for elapsed := 10 * time.Minute; elapsed < 12*time.Hour; elapsed += 10 * time.Minute {
					if _, err := s.ResolveSession(context.Background(), hash, now.Add(elapsed)); err != nil {
						t.Fatal("active session expired early", err)
					}
				}
				now = now.Add(12 * time.Hour)
			} else {
				now = now.Add(30 * time.Minute)
			}
			if _, err := s.ResolveSession(context.Background(), hash, now); !errors.Is(err, ErrAuthInactive) {
				t.Fatal("expired session accepted", err)
			}
		})
	}
}

func TestSessionRechecksIdentityAndRoles(t *testing.T) {
	for _, mode := range []string{"disabled", "epoch", "no-role", "pending", "revoked", "role-change"} {
		t.Run(mode, func(t *testing.T) {
			s, c, now := authFixture(t)
			hash := strings.Repeat("a", 64)
			issue(t, s, c, now, hash, "")
			switch mode {
			case "disabled":
				execSQL(t, s, "UPDATE users SET disabled_at=0")
			case "epoch":
				execSQL(t, s, "UPDATE users SET auth_epoch=auth_epoch+1")
			case "no-role":
				execSQL(t, s, "DELETE FROM user_roles")
			case "pending":
				execSQL(t, s, "UPDATE sessions SET kind='pending_mfa'")
			case "revoked":
				execSQL(t, s, "UPDATE sessions SET revoked_at=0")
			case "role-change":
				execSQL(t, s, "UPDATE user_roles SET role_id='user'")
			}
			identity, err := s.ResolveSession(context.Background(), hash, now)
			if mode == "role-change" {
				if err != nil || identity.Role != domain.User {
					t.Fatal("cached stale admin role", err)
				}
			} else if !errors.Is(err, ErrAuthInactive) {
				t.Fatal("inactive session accepted", err)
			}
		})
	}
}

func TestIssueRechecksPasswordAndAuditContainsNoCredentials(t *testing.T) {
	s, c, now := authFixture(t)
	if _, err := s.Credential(context.Background(), "absent"); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing account not reported")
	}
	execSQL(t, s, "UPDATE users SET password_hash='$argon2id$changed'")
	if _, err := s.IssueSession(context.Background(), IssueSession{Credential: c, TokenHash: strings.Repeat("a", 64), CorrelationID: correlationID, Now: now}); !errors.Is(err, ErrAuthInactive) {
		t.Fatal("stale verified password issued session", err)
	}
	if err := s.RecordLoginFailure(context.Background(), correlationID, now); err != nil {
		t.Fatal(err)
	}
	var metadata string
	if err := s.db.QueryRow("SELECT sanitized_metadata FROM audit_events WHERE action='auth.login_failed'").Scan(&metadata); err != nil || metadata != `{"reason":"invalid_credentials"}` {
		t.Fatal("unexpected failure audit", err)
	}
}
