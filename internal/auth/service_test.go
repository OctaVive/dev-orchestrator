package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"dev-orchestrator/internal/domain"
	"dev-orchestrator/internal/storage"
)

const testPassword = "Maple-river-Orbit-792!"
const testCorrelation = "11111111-1111-4111-8111-111111111111"

func freshService(t *testing.T, setup bool) (*Service, *storage.Store) {
	t.Helper()
	store, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	config := SetupConfig{}
	if setup {
		config = SetupConfig{TokenHash: sha256.Sum256([]byte(strings.Repeat("a", 64))), ExpiresAt: time.Now().Add(10 * time.Minute)}
	}
	s, err := NewService(store, config)
	if err != nil {
		t.Fatal(err)
	}
	return s, store
}

func bootstrap(t *testing.T, s *Service) {
	t.Helper()
	if err := s.Bootstrap(context.Background(), strings.Repeat("a", 64), "Admin", testPassword, "127.0.0.1", testCorrelation); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordPolicyAndHashes(t *testing.T) {
	for _, password := range []string{"", "short", "password123456", "Password123!@#", "correct horse battery staple", strings.Repeat("a", 1025), "strong-password\x00bad", "😀😀😀", strings.Repeat(" ", 20)} {
		if validNewPassword(password) {
			t.Fatal("weak/invalid password accepted")
		}
	}
	if !validNewPassword(testPassword) || !validNewPassword(strings.Repeat("longphrase-", 50)) {
		t.Fatal("valid long password rejected")
	}
	a, err := hashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	b, err := hashPassword(testPassword)
	if err != nil || a == b || !strings.HasPrefix(a, "$argon2id$v=19$m=65536,t=3,p=1$") {
		t.Fatal("hash profile or salt uniqueness incorrect")
	}
	if !verifyPassword(a, testPassword, b) || verifyPassword(a, "wrong", b) {
		t.Fatal("password verification incorrect")
	}
	for _, encoded := range []string{"plaintext", "$argon2id$v=19$m=999999999,t=999,p=255$AA$AA", "$argon2id$v=19$m=65536,t=3,p=1$bad$bad"} {
		if verifyPassword(encoded, testPassword, b) {
			t.Fatal("invalid hash accepted")
		}
	}
}

func TestServiceSetupLoginRotationLogout(t *testing.T) {
	s, store := freshService(t, true)
	ctx := context.Background()
	if err := s.Bootstrap(ctx, "wrong", "admin", testPassword, "127.0.0.1", testCorrelation); !errors.Is(err, ErrCredentials) {
		t.Fatal("wrong setup token accepted", err)
	}
	if err := s.Bootstrap(ctx, strings.Repeat("a", 64), "admin", testPassword, "203.0.113.1", testCorrelation); !errors.Is(err, ErrSetupClosed) {
		t.Fatal("remote setup accepted", err)
	}
	bootstrap(t, s)
	if available, err := s.SetupAvailable(ctx); err != nil || available {
		t.Fatal("setup stayed open", err)
	}
	if err := s.Bootstrap(ctx, strings.Repeat("a", 64), "other", testPassword, "127.0.0.1", testCorrelation); !errors.Is(err, ErrSetupClosed) {
		t.Fatal("setup token replay accepted", err)
	}
	first, err := s.Login(ctx, "ADMIN", testPassword, strings.Repeat("f", 64), "127.0.0.1", testCorrelation)
	if err != nil || first.Identity.Role != domain.Admin || !validToken(first.Token) || first.Token == strings.Repeat("f", 64) {
		t.Fatal("login/fixation protection failed", err)
	}
	if !ValidCSRF(first.Token, CSRF(first.Token)) || ValidCSRF(first.Token, CSRF(strings.Repeat("f", 64))) {
		t.Fatal("CSRF token is not session-bound")
	}
	second, err := s.Login(ctx, "admin", testPassword, first.Token, "127.0.0.1", testCorrelation)
	if err != nil || first.Token == second.Token {
		t.Fatal("session rotation failed", err)
	}
	if _, err := s.Resolve(ctx, first.Token); !errors.Is(err, ErrCredentials) {
		t.Fatal("rotated token still active")
	}
	if _, err := s.Resolve(ctx, second.Token); err != nil {
		t.Fatal(err)
	}
	if err := s.Logout(ctx, second.Token, testCorrelation); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Resolve(ctx, second.Token); !errors.Is(err, ErrCredentials) {
		t.Fatal("logout did not revoke server-side session")
	}
	credential, err := store.Credential(ctx, "admin")
	if err != nil || strings.Contains(credential.PasswordHash, testPassword) || !strings.HasPrefix(credential.PasswordHash, "$argon2id$") {
		t.Fatal("password not hashed", err)
	}
}

func TestGenericLoginFailuresRateLimitAndRecovery(t *testing.T) {
	s, _ := freshService(t, true)
	bootstrap(t, s)
	for _, name := range []string{"admin", "absent"} {
		if _, err := s.Login(context.Background(), name, "wrong", "", "127.0.0.1", testCorrelation); !errors.Is(err, ErrCredentials) {
			t.Fatal("login failure leaks account distinction", err)
		}
	}
	now := time.Now()
	s.now = func() time.Time { return now }
	for range 4 { // One previous failure + four = five attempts for admin.
		_, _ = s.Login(context.Background(), "admin", "wrong", "", "127.0.0.1", testCorrelation)
	}
	if _, err := s.Login(context.Background(), "admin", testPassword, "", "127.0.0.2", testCorrelation); !errors.Is(err, ErrRateLimited) {
		t.Fatal("account limit bypassed by changing IP", err)
	}
	now = now.Add(6 * time.Minute)
	if _, err := s.Login(context.Background(), "admin", testPassword, "", "127.0.0.1", testCorrelation); err != nil {
		t.Fatal("temporary throttle became permanent lockout", err)
	}
}

func TestExpiryCapacityAndDatabaseFailure(t *testing.T) {
	s, store := freshService(t, true)
	bootstrap(t, s)
	now := time.Now()
	s.now = func() time.Time { return now }
	result, err := s.Login(context.Background(), "admin", testPassword, "", "127.0.0.1", testCorrelation)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(30 * time.Minute)
	if _, err := s.Resolve(context.Background(), result.Token); !errors.Is(err, ErrCredentials) {
		t.Fatal("idle expiry not enforced", err)
	}
	s.work <- struct{}{}
	s.work <- struct{}{}
	if _, err := s.Login(context.Background(), "admin", testPassword, "", "127.0.0.1", testCorrelation); !errors.Is(err, ErrBusy) {
		t.Fatal("KDF capacity is unbounded", err)
	}
	s.release()
	s.release()
	store.Close()
	if _, err := s.Resolve(context.Background(), result.Token); !errors.Is(err, ErrUnavailable) {
		t.Fatal("database outage did not fail closed", err)
	}
}

func TestLimiterBoundsAndConcurrency(t *testing.T) {
	l := newLimiter()
	now := time.Now()
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for range 30 {
		wg.Go(func() {
			if l.allow("admin", "127.0.0.1", now) {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if allowed != 5 {
		t.Fatal("concurrent rate limit bypass", allowed)
	}
	l = newLimiter()
	for i := range 20 {
		if !l.allow(strings.Repeat("x", i+1), "127.0.0.1", now) {
			t.Fatal("IP limit denied before threshold")
		}
	}
	if l.allow("another-account", "127.0.0.1", now) {
		t.Fatal("IP limit bypassed by changing account")
	}
	l = newLimiter()
	for i := range 100 {
		if !l.allow(fmt.Sprint("user", i), fmt.Sprint("127.0.0.", i+1), now) {
			t.Fatal("global limiter denied before threshold")
		}
	}
	if l.allow("other", "127.0.0.200", now) {
		t.Fatal("global limiter bypassed")
	}
	l = newLimiter()
	l.maxKeys = 3
	if !l.allow("one", "127.0.0.1", now) || l.allow("two", "127.0.0.2", now) || len(l.buckets) != 3 {
		t.Fatal("rate limiter memory bound/cache churn failure")
	}
	if !l.allow("two", "127.0.0.2", now.Add(5*time.Minute)) {
		t.Fatal("expired rate buckets not reclaimed")
	}
}

func TestSetupExpiryPolicyAndCancelledAdmission(t *testing.T) {
	s, store := freshService(t, true)
	if err := s.Bootstrap(context.Background(), strings.Repeat("a", 64), "admin", "weak", "127.0.0.1", testCorrelation); !errors.Is(err, ErrPasswordPolicy) {
		t.Fatal("weak setup password accepted", err)
	}
	s.now = func() time.Time { return s.setup.ExpiresAt }
	if available, err := s.SetupAvailable(context.Background()); err != nil || available {
		t.Fatal("expired setup available", err)
	}
	if err := s.Bootstrap(context.Background(), strings.Repeat("a", 64), "admin", testPassword, "127.0.0.1", testCorrelation); !errors.Is(err, ErrSetupClosed) {
		t.Fatal("expired token accepted", err)
	}
	for _, config := range []SetupConfig{
		{ExpiresAt: time.Now().Add(time.Minute)},
		{TokenHash: sha256.Sum256([]byte("fixture")), ExpiresAt: time.Now().Add(time.Hour)},
		{TokenHash: sha256.Sum256([]byte("fixture")), ExpiresAt: time.Now().Add(-time.Minute)},
	} {
		if _, err := NewService(store, config); !errors.Is(err, ErrUnavailable) {
			t.Fatal("invalid setup configuration accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.acquire(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("cancelled KDF admitted")
	}
	if _, err := s.Resolve(context.Background(), "bad"); !errors.Is(err, ErrCredentials) {
		t.Fatal("malformed session token accepted")
	}
}
