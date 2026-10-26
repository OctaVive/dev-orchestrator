// Package httpapi exposes only PH1 authentication and an admin status probe.
// There are no build, Docker, proxy or deployment execution endpoints.
package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"

	"dev-orchestrator/internal/auth"
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/domain"
	"dev-orchestrator/internal/storage"
)

const SessionCookie = "__Host-portal_session"

type handler struct {
	service   *auth.Service
	validator *contracts.Validator
	origin    string
	host      string
	bootstrap bool
	challenge [32]byte
	nonceName string
	now       func() time.Time
}

// NewPortalHandler never exposes setup, even when the service has setup enabled.
func NewPortalHandler(service *auth.Service, origin string) (http.Handler, error) {
	return newHandler(service, origin, false)
}

// NewSetupHandler is a separate, loopback-only operator listener, not a path
// to forward through the public gateway. Its origin must be localhost/loopback.
func NewSetupHandler(service *auth.Service, origin string) (http.Handler, error) {
	return newHandler(service, origin, true)
}

func newHandler(service *auth.Service, origin string, bootstrap bool) (http.Handler, error) {
	u, err := url.Parse(origin)
	if service == nil || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" ||
		u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Host != strings.ToLower(u.Host) || strings.ContainsAny(origin, "\r\n\\") {
		return nil, errors.New("API requires one exact HTTPS origin")
	}
	if bootstrap {
		ip, err := netip.ParseAddr(u.Hostname())
		if u.Hostname() != "localhost" && (err != nil || !ip.IsLoopback()) {
			return nil, errors.New("setup requires a loopback HTTPS origin")
		}
	}
	v, err := contracts.NewValidator()
	if err != nil {
		return nil, err
	}
	h := &handler{service: service, validator: v, origin: origin, host: u.Host, bootstrap: bootstrap, now: time.Now, nonceName: "__Host-orch_login_nonce"}
	if bootstrap {
		h.nonceName = "__Host-orch_setup_nonce"
	}
	if _, err := rand.Read(h.challenge[:]); err != nil {
		return nil, errors.New("API entropy unavailable")
	}
	mux := http.NewServeMux()
	if bootstrap {
		mux.HandleFunc("GET /api/v1/setup/csrf", h.csrfChallenge)
		mux.HandleFunc("POST /api/v1/setup", h.setup)
	} else {
		mux.HandleFunc("GET /api/v1/auth/csrf", h.csrfChallenge)
		mux.HandleFunc("POST /api/v1/auth/login", h.login)
		mux.Handle("GET /api/v1/auth/session", h.requireSession(http.HandlerFunc(h.session)))
		mux.Handle("POST /api/v1/auth/logout", h.requireSession(http.HandlerFunc(h.logout)))
		mux.Handle("GET /api/v1/admin/status", h.requireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, struct {
				ExecutionEnabled bool `json:"deployment_execution_enabled"`
			}{false})
		})))
		// Unknown management operations still cannot bypass login/role/CSRF.
		// No placeholder job submission is persisted or executed.
		mux.Handle("/api/v1/", h.requireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.fail(w, r, http.StatusNotFound, "not_found", "Not found")
		})))
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		h.fail(w, r, http.StatusNotFound, "not_found", "Not found")
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		id, err := auth.CorrelationID()
		if err != nil {
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), correlationKey{}, id))
		w.Header().Set("X-Correlation-ID", id)
		if r.TLS == nil {
			h.fail(w, r, http.StatusBadRequest, "tls_required", "HTTPS is required")
			return
		}
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		if !strings.EqualFold(r.Host, h.host) || r.URL.IsAbs() || r.URL.RawPath != "" || strings.ContainsAny(r.URL.Path, "\\") || path.Clean(r.URL.Path) != r.URL.Path {
			h.fail(w, r, http.StatusBadRequest, "invalid_host", "Invalid request authority or path")
			return
		}
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" || len(r.Header.Values("Origin")) > 1 ||
			r.Header.Get("Origin") != "" && r.Header.Get("Origin") != h.origin {
			h.fail(w, r, http.StatusForbidden, "origin_denied", "Request origin denied")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions && r.Header.Get("Origin") != h.origin {
			h.fail(w, r, http.StatusForbidden, "origin_denied", "Request origin denied")
			return
		}
		if bootstrap {
			ip, err := peerIP(r)
			if err != nil || !ip.IsLoopback() {
				h.fail(w, r, http.StatusNotFound, "not_found", "Not found")
				return
			}
			available, err := h.service.SetupAvailable(r.Context())
			if err != nil {
				h.authError(w, r, err)
				return
			}
			if !available {
				h.fail(w, r, http.StatusNotFound, "not_found", "Not found")
				return
			}
		} else if r.URL.Path == "/api/v1/setup" || strings.HasPrefix(r.URL.Path, "/api/v1/setup/") {
			h.fail(w, r, http.StatusNotFound, "not_found", "Not found")
			return
		}
		mux.ServeHTTP(w, r)
	}), nil
}

type correlationKey struct{}
type sessionKey struct{}
type sessionContext struct {
	identity storage.SessionIdentity
	token    string
}

func (h *handler) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := oneCookie(r, SessionCookie)
		if !ok {
			h.authError(w, r, auth.ErrCredentials)
			return
		}
		identity, err := h.service.Resolve(r.Context(), token)
		if err != nil {
			h.authError(w, r, err)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions && !validCSRFHeader(r, token) {
			h.fail(w, r, http.StatusForbidden, "csrf_denied", "CSRF verification failed")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, sessionContext{identity, token})))
	})
}

func (h *handler) requireAdmin(next http.Handler) http.Handler {
	return h.requireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := r.Context().Value(sessionKey{}).(sessionContext)
		p := domain.Principal{UserID: s.identity.UserID, Role: s.identity.Role, Authenticated: true}
		if !p.CanManage() {
			h.fail(w, r, http.StatusForbidden, "permission_denied", "Permission denied")
			return
		}
		next.ServeHTTP(w, r)
	}))
}

func (h *handler) login(w http.ResponseWriter, r *http.Request) {
	if !h.validChallenge(r) {
		h.fail(w, r, http.StatusForbidden, "csrf_denied", "CSRF verification failed")
		return
	}
	credentials, ok := h.credentials(w, r)
	if !ok {
		return
	}
	ip, err := peerIP(r)
	if err != nil {
		h.fail(w, r, http.StatusBadRequest, "invalid_peer", "Invalid connection")
		return
	}
	previous, _ := oneCookie(r, SessionCookie)
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == SessionCookie {
			count++
		}
	}
	if count > 1 {
		h.fail(w, r, http.StatusBadRequest, "invalid_request", "Ambiguous session cookie")
		return
	}
	result, err := h.service.Login(r.Context(), credentials.Username, credentials.Password, previous, ip.String(), correlation(r))
	if err != nil {
		h.authError(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: result.Token, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Expires: result.Identity.ExpiresAt, MaxAge: 12 * 60 * 60})
	h.clearNonce(w)
	h.identity(w, result.Identity, result.Token)
}

func (h *handler) setup(w http.ResponseWriter, r *http.Request) {
	if !h.validChallenge(r) {
		h.fail(w, r, http.StatusForbidden, "csrf_denied", "CSRF verification failed")
		return
	}
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") || len(values[0]) != len("Bearer ")+64 {
		h.authError(w, r, auth.ErrCredentials)
		return
	}
	credentials, ok := h.credentials(w, r)
	if !ok {
		return
	}
	ip, _ := peerIP(r) // Outer setup guard already verified it.
	err := h.service.Bootstrap(r.Context(), strings.TrimPrefix(values[0], "Bearer "), credentials.Username, credentials.Password, ip.String(), correlation(r))
	if err != nil {
		h.authError(w, r, err)
		return
	}
	h.clearNonce(w)
	writeJSON(w, http.StatusCreated, struct {
		Created bool `json:"created"`
	}{true})
}

func (h *handler) session(w http.ResponseWriter, r *http.Request) {
	s := r.Context().Value(sessionKey{}).(sessionContext)
	h.identity(w, s.identity, s.token)
}

func (h *handler) identity(w http.ResponseWriter, identity storage.SessionIdentity, token string) {
	writeJSON(w, http.StatusOK, sessionResponse{User: userResponse{identity.UserID, identity.Username, identity.Role},
		CSRF: auth.CSRF(token), ExpiresAt: identity.ExpiresAt})
}

type userResponse struct {
	ID       string      `json:"id"`
	Username string      `json:"username"`
	Role     domain.Role `json:"role"`
}

type sessionResponse struct {
	User      userResponse `json:"user"`
	CSRF      string       `json:"csrf_token"`
	ExpiresAt time.Time    `json:"expires_at"`
}

func (h *handler) logout(w http.ResponseWriter, r *http.Request) {
	s := r.Context().Value(sessionKey{}).(sessionContext)
	if err := h.service.Logout(r.Context(), s.token, correlation(r)); err != nil {
		h.authError(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0)})
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) credentials(w http.ResponseWriter, r *http.Request) (contracts.Credentials, bool) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		h.fail(w, r, http.StatusUnsupportedMediaType, "json_required", "JSON content type required")
		return contracts.Credentials{}, false
	}
	c, err := h.validator.DecodeCredentials(r.Body)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, contracts.ErrTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		h.fail(w, r, status, "invalid_request", "Invalid authentication request")
		return contracts.Credentials{}, false
	}
	return c, true
}

func (h *handler) authError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, auth.ErrCredentials):
		h.fail(w, r, http.StatusUnauthorized, "invalid_credentials", "Invalid credentials or session")
	case errors.Is(err, auth.ErrSetupClosed):
		h.fail(w, r, http.StatusNotFound, "not_found", "Not found")
	case errors.Is(err, auth.ErrPasswordPolicy):
		h.fail(w, r, http.StatusBadRequest, "password_policy", "Use at least 15 characters, at most 1024 UTF-8 bytes, and avoid common passwords")
	case errors.Is(err, auth.ErrRateLimited):
		w.Header().Set("Retry-After", "300")
		h.fail(w, r, http.StatusTooManyRequests, "rate_limited", "Try again later")
	default:
		h.fail(w, r, http.StatusServiceUnavailable, "auth_unavailable", "Authentication unavailable")
	}
}

func (h *handler) fail(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	writeJSON(w, status, struct {
		Code          string `json:"code"`
		Message       string `json:"message"`
		CorrelationID string `json:"correlation_id"`
	}{code, message, correlation(r)})
}

func correlation(r *http.Request) string {
	id, _ := r.Context().Value(correlationKey{}).(string)
	return id
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func peerIP(r *http.Request) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, err
	}
	ip, err := netip.ParseAddr(host)
	return ip.Unmap(), err // Forwarded/X-Forwarded-For are deliberately ignored.
}

func oneCookie(r *http.Request, name string) (string, bool) {
	var value string
	count := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == name {
			value, count = cookie.Value, count+1
		}
	}
	return value, count == 1
}

func validCSRFHeader(r *http.Request, token string) bool {
	values := r.Header.Values("X-CSRF-Token")
	return len(values) == 1 && auth.ValidCSRF(token, values[0])
}

// TLSConfig is reused by both operator and portal listeners. Proxying to this
// service must also use TLS; forwarded scheme headers cannot bypass this.
func TLSConfig() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS13} }
