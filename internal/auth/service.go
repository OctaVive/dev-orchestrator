package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"dev-orchestrator/internal/storage"
)

var (
	ErrCredentials    = errors.New("invalid credentials")
	ErrSetupClosed    = errors.New("setup is unavailable")
	ErrPasswordPolicy = errors.New("password does not satisfy policy")
	ErrRateLimited    = errors.New("authentication rate limit exceeded")
	ErrBusy           = errors.New("authentication capacity unavailable")
	ErrUnavailable    = errors.New("authentication service unavailable")
)

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

type SetupConfig struct {
	TokenHash [32]byte
	ExpiresAt time.Time
}

type Service struct {
	store *storage.Store
	setup SetupConfig
	dummy string
	work  chan struct{}
	login *limiter
	boot  *limiter
	now   func() time.Time
}

func NewService(store *storage.Store, setup SetupConfig) (*Service, error) {
	if store == nil || (setup.TokenHash == [32]byte{}) != setup.ExpiresAt.IsZero() {
		return nil, ErrUnavailable
	}
	if !setup.ExpiresAt.IsZero() && (!setup.ExpiresAt.After(time.Now()) || setup.ExpiresAt.After(time.Now().Add(15*time.Minute))) {
		return nil, ErrUnavailable
	}
	random, err := randomToken()
	if err != nil {
		return nil, ErrUnavailable
	}
	dummy, err := hashPassword(random)
	if err != nil {
		return nil, ErrUnavailable
	}
	return &Service{store: store, setup: setup, dummy: dummy, work: make(chan struct{}, 2), login: newLimiter(), boot: newLimiter(), now: time.Now}, nil
}

func (s *Service) SetupAvailable(ctx context.Context) (bool, error) {
	if s.setup.TokenHash == [32]byte{} || !s.now().Before(s.setup.ExpiresAt) {
		return false, nil
	}
	ok, err := s.store.SetupAllowed(ctx)
	if err != nil {
		return false, ErrUnavailable
	}
	return ok, nil
}

func (s *Service) Bootstrap(ctx context.Context, token, username, password, ip, correlation string) error {
	available, err := s.SetupAvailable(ctx)
	if err != nil || !available {
		if err != nil {
			return err
		}
		return ErrSetupClosed
	}
	address, err := netip.ParseAddr(ip)
	if err != nil || !address.IsLoopback() {
		return ErrSetupClosed
	}
	if !s.boot.allow("bootstrap", address.Unmap().String(), s.now()) {
		return ErrRateLimited
	}
	supplied := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(supplied[:], s.setup.TokenHash[:]) != 1 {
		if err := s.store.RecordSetupFailure(ctx, correlation, s.now().UTC()); err != nil {
			return ErrUnavailable
		}
		return ErrCredentials
	}
	username = strings.ToLower(username)
	if !usernamePattern.MatchString(username) || !validNewPassword(password) {
		return ErrPasswordPolicy
	}
	if err := s.acquire(ctx); err != nil {
		return err
	}
	defer s.release()
	hash, err := hashPassword(password)
	if err != nil {
		return ErrUnavailable
	}
	// Recheck expiry after expensive KDF work.
	if !s.now().Before(s.setup.ExpiresAt) {
		return ErrSetupClosed
	}
	_, err = s.store.BootstrapAdmin(ctx, username, hash, correlation, s.now().UTC())
	if errors.Is(err, storage.ErrConflict) {
		return ErrSetupClosed
	}
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

type LoginResult struct {
	Identity storage.SessionIdentity
	Token    string `json:"-"`
}

func (s *Service) Login(ctx context.Context, username, password, previousToken, ip, correlation string) (LoginResult, error) {
	username = strings.ToLower(username)
	address, err := netip.ParseAddr(ip)
	if err != nil || !usernamePattern.MatchString(username) || len(password) < 1 || len(password) > 1024 || !utf8.ValidString(password) || strings.ContainsRune(password, 0) {
		return LoginResult{}, ErrCredentials
	}
	if !s.login.allow(username, address.Unmap().String(), s.now()) {
		return LoginResult{}, ErrRateLimited
	}
	if err := s.acquire(ctx); err != nil {
		return LoginResult{}, err
	}
	defer s.release()
	credential, err := s.store.Credential(ctx, username)
	missing := errors.Is(err, storage.ErrNotFound)
	if err != nil && !missing {
		return LoginResult{}, ErrUnavailable
	}
	encoded := credential.PasswordHash
	if missing {
		encoded = s.dummy
	}
	valid := verifyPassword(encoded, password, s.dummy)
	if !valid || missing || credential.Disabled || credential.Role == "" {
		if err := s.store.RecordLoginFailure(ctx, correlation, s.now().UTC()); err != nil {
			return LoginResult{}, ErrUnavailable
		}
		return LoginResult{}, ErrCredentials
	}
	token, err := randomToken()
	if err != nil {
		return LoginResult{}, ErrUnavailable
	}
	previousHash := ""
	if validToken(previousToken) {
		previousHash = tokenHash(previousToken)
	}
	identity, err := s.store.IssueSession(ctx, storage.IssueSession{Credential: credential, TokenHash: tokenHash(token),
		PreviousTokenHash: previousHash, CorrelationID: correlation, Now: s.now().UTC()})
	if errors.Is(err, storage.ErrAuthInactive) {
		return LoginResult{}, ErrCredentials
	}
	if err != nil {
		return LoginResult{}, ErrUnavailable
	}
	return LoginResult{Identity: identity, Token: token}, nil
}

func (s *Service) Resolve(ctx context.Context, token string) (storage.SessionIdentity, error) {
	if !validToken(token) {
		return storage.SessionIdentity{}, ErrCredentials
	}
	identity, err := s.store.ResolveSession(ctx, tokenHash(token), s.now().UTC())
	if errors.Is(err, storage.ErrAuthInactive) {
		return storage.SessionIdentity{}, ErrCredentials
	}
	if err != nil {
		return storage.SessionIdentity{}, ErrUnavailable
	}
	return identity, nil
}

func (s *Service) Logout(ctx context.Context, token, correlation string) error {
	if !validToken(token) {
		return ErrCredentials
	}
	err := s.store.RevokeSession(ctx, tokenHash(token), correlation, s.now().UTC())
	if errors.Is(err, storage.ErrAuthInactive) {
		return ErrCredentials
	}
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *Service) acquire(ctx context.Context) error {
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	select {
	case s.work <- struct{}{}:
		return nil
	default:
		return ErrBusy
	}
}

func (s *Service) release() { <-s.work }

func validToken(token string) bool {
	if len(token) != 64 {
		return false
	}
	_, err := hex.DecodeString(token)
	return err == nil && token == strings.ToLower(token)
}

func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// CSRF is a session-bound token returned only in same-origin API JSON. The
// HttpOnly session cookie remains secret; the returned HMAC cannot reveal it.
func CSRF(token string) string {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte("dev-orchestrator/csrf/v1"))
	return hex.EncodeToString(mac.Sum(nil))
}

func ValidCSRF(token, supplied string) bool {
	return len(supplied) == 64 && hmac.Equal([]byte(CSRF(token)), []byte(supplied))
}

// CorrelationID is generated server-side; untrusted headers cannot select audit identities.
func CorrelationID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6], b[8] = b[6]&15|64, b[8]&63|128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
