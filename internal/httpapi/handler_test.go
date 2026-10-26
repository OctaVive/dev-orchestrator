package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dev-orchestrator/internal/auth"
	"dev-orchestrator/internal/storage"
)

const portalOrigin = "https://portal.example.test"
const operatorOrigin = "https://localhost:9443"
const password = "Maple-river-Orbit-792!"

type apiFixture struct {
	portal  http.Handler
	setup   http.Handler
	store   *storage.Store
	path    string
	service *auth.Service
}

func newAPI(t *testing.T) apiFixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "api.db")
	store, err := storage.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	service, err := auth.NewService(store, auth.SetupConfig{TokenHash: sha256.Sum256([]byte(strings.Repeat("a", 64))), ExpiresAt: time.Now().Add(10 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	portal, err := NewPortalHandler(service, portalOrigin)
	if err != nil {
		t.Fatal(err)
	}
	setup, err := NewSetupHandler(service, operatorOrigin)
	if err != nil {
		t.Fatal(err)
	}
	return apiFixture{portal: portal, setup: setup, store: store, path: path, service: service}
}

func request(h http.Handler, method, origin, path, body string, cookies []*http.Cookie, csrf string, edit func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, origin+path, strings.NewReader(body))
	// A real origin-form request has authority in r.Host, not r.URL.Host.
	// httptest retains Scheme/Host when constructed with an absolute target.
	r.URL.Scheme, r.URL.Host = "", ""
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("Content-Type", "application/json")
	if method != http.MethodGet {
		r.Header.Set("Origin", origin)
	}
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	if edit != nil {
		edit(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func challenge(t *testing.T, h http.Handler, origin, path string) (*http.Cookie, string) {
	t.Helper()
	w := request(h, http.MethodGet, origin, path, "", nil, "", nil)
	if w.Code != 200 {
		t.Fatalf("challenge status=%d body=%s", w.Code, w.Body.String())
	}
	var body struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.CSRF == "" {
		t.Fatal("missing challenge", err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].Domain != "" {
		t.Fatal("unsafe challenge cookie")
	}
	return cookies[0], body.CSRF
}

func (a apiFixture) bootstrap(t *testing.T) {
	t.Helper()
	c, csrf := challenge(t, a.setup, operatorOrigin, "/api/v1/setup/csrf")
	w := request(a.setup, "POST", operatorOrigin, "/api/v1/setup", `{"username":"admin","password":"`+password+`"}`, []*http.Cookie{c}, csrf, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
	})
	if w.Code != 201 {
		t.Fatalf("bootstrap status=%d body=%s", w.Code, w.Body.String())
	}
}

func (a apiFixture) login(t *testing.T, previous *http.Cookie) (*http.Cookie, string) {
	t.Helper()
	c, csrf := challenge(t, a.portal, portalOrigin, "/api/v1/auth/csrf")
	cookies := []*http.Cookie{c}
	if previous != nil {
		cookies = append(cookies, previous)
	}
	w := request(a.portal, "POST", portalOrigin, "/api/v1/auth/login", `{"username":"admin","password":"`+password+`"}`, cookies, csrf, nil)
	if w.Code != 200 {
		t.Fatalf("login status=%d body=%s", w.Code, w.Body.String())
	}
	var session *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == SessionCookie {
			session = c
		}
	}
	var body struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || session == nil || body.CSRF == "" {
		t.Fatal("missing login session/CSRF", err)
	}
	if strings.Contains(w.Body.String(), session.Value) || strings.Contains(w.Body.String(), password) {
		t.Fatal("login JSON leaked session cookie or password")
	}
	if !session.HttpOnly || !session.Secure || session.Path != "/" || session.Domain != "" || session.SameSite != http.SameSiteLaxMode || session.MaxAge != 43200 {
		t.Fatal("unsafe session cookie")
	}
	return session, body.CSRF
}

func fixtureSQL(t *testing.T, path, query string, args ...any) {
	t.Helper()
	// Test-only fixture mutation, never a management HTTP/production SQL escape hatch.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

func TestOperatorSetupIsSeparateAndOneTime(t *testing.T) {
	a := newAPI(t)
	for _, path := range []string{"/api/v1/setup", "/api/v1/setup/csrf"} {
		if got := request(a.portal, "GET", portalOrigin, path, "", nil, "", nil).Code; got != 404 {
			t.Fatal("public portal exposes operator setup", got)
		}
	}
	w := request(a.setup, "GET", operatorOrigin, "/api/v1/setup/csrf", "", nil, "", func(r *http.Request) {
		r.RemoteAddr = "203.0.113.10:4444"
		r.Header.Set("X-Forwarded-For", "127.0.0.1")
	})
	if w.Code != 404 {
		t.Fatal("forged loopback headers bypassed setup guard")
	}
	a.bootstrap(t)
	if got := request(a.setup, "GET", operatorOrigin, "/api/v1/setup/csrf", "", nil, "", nil).Code; got != 404 {
		t.Fatal("bootstrap did not close permanently", got)
	}
}

func TestSessionCSRFAndLogout(t *testing.T) {
	a := newAPI(t)
	a.bootstrap(t)
	cookie, csrf := a.login(t, nil)
	db, err := sql.Open("sqlite", a.path)
	if err != nil {
		t.Fatal(err)
	}
	var storedToken, storedPassword string
	if err := db.QueryRow("SELECT s.token_hash,u.password_hash FROM sessions s JOIN users u ON u.id=s.user_id").Scan(&storedToken, &storedPassword); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()
	sum := sha256.Sum256([]byte(cookie.Value))
	if storedToken != hex.EncodeToString(sum[:]) || storedToken == cookie.Value || strings.Contains(storedPassword, password) || !strings.HasPrefix(storedPassword, "$argon2id$") {
		t.Fatal("raw password or session token persisted")
	}
	get := func() *httptest.ResponseRecorder {
		return request(a.portal, "GET", portalOrigin, "/api/v1/auth/session", "", []*http.Cookie{cookie}, "", nil)
	}
	w := get()
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("session/read headers incorrect", w.Code)
	}
	for _, token := range []string{"", "wrong"} {
		if w := request(a.portal, "POST", portalOrigin, "/api/v1/auth/logout", "", []*http.Cookie{cookie}, token, nil); w.Code != 403 {
			t.Fatal("logout missing CSRF accepted", w.Code)
		}
	}
	if get().Code != 200 {
		t.Fatal("rejected logout revoked session")
	}
	w = request(a.portal, "POST", portalOrigin, "/api/v1/auth/logout", "", []*http.Cookie{cookie}, csrf, nil)
	if w.Code != 204 || get().Code != 401 {
		t.Fatal("logout did not revoke server-side session", w.Code)
	}
	if cookies := w.Result().Cookies(); len(cookies) != 1 || cookies[0].MaxAge != -1 || !cookies[0].Secure {
		t.Fatal("logout did not clear cookie securely")
	}
}

func TestSessionFixationAndRotation(t *testing.T) {
	a := newAPI(t)
	a.bootstrap(t)
	first, _ := a.login(t, &http.Cookie{Name: SessionCookie, Value: strings.Repeat("f", 64)})
	if first.Value == strings.Repeat("f", 64) {
		t.Fatal("client selected session token")
	}
	second, _ := a.login(t, first)
	if first.Value == second.Value {
		t.Fatal("login did not rotate token")
	}
	if request(a.portal, "GET", portalOrigin, "/api/v1/auth/session", "", []*http.Cookie{first}, "", nil).Code != 401 {
		t.Fatal("old session remained usable")
	}
}

func TestBackendRoleGateAndForgedClaims(t *testing.T) {
	a := newAPI(t)
	a.bootstrap(t)
	path := "/api/v1/apps/11111111-1111-4111-8111-111111111111/deployments"
	if w := request(a.portal, "POST", portalOrigin, path, `{}`, nil, "", func(r *http.Request) {
		r.Header.Set("X-Role", "admin")
		r.Header.Set("X-User-ID", "admin")
	}); w.Code != 401 {
		t.Fatal("anonymous management access allowed", w.Code)
	}
	cookie, csrf := a.login(t, nil)
	if w := request(a.portal, "GET", portalOrigin, "/api/v1/admin/status", "", []*http.Cookie{cookie}, "", nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"deployment_execution_enabled":false`) {
		t.Fatal("admin status unavailable or execution enabled", w.Code)
	}
	fixtureSQL(t, a.path, "UPDATE user_roles SET role_id='user'")
	for _, methodPath := range [][2]string{{"GET", "/api/v1/admin/status"}, {"POST", path}} {
		w := request(a.portal, methodPath[0], portalOrigin, methodPath[1], `{}`, []*http.Cookie{cookie}, csrf, func(r *http.Request) { r.Header.Set("X-Role", "admin") })
		if w.Code != 403 {
			t.Fatal("regular user bypassed backend role gate", w.Code)
		}
	}
	if w := request(a.portal, "GET", portalOrigin, "/api/v1/auth/session", "", []*http.Cookie{cookie}, "", nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"role":"user"`) {
		t.Fatal("role change not reflected immediately", w.Code)
	}
}

func TestOriginTLSHostAndCookieConfusionFailClosed(t *testing.T) {
	a := newAPI(t)
	a.bootstrap(t)
	cookie, csrf := a.login(t, nil)
	cases := []struct {
		name string
		edit func(*http.Request)
		code int
	}{
		{"plaintext", func(r *http.Request) { r.TLS = nil; r.Header.Set("X-Forwarded-Proto", "https") }, 400},
		{"wrong-host", func(r *http.Request) { r.Host = "evil.example" }, 400},
		{"cross-origin", func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }, 403},
		{"missing-origin", func(r *http.Request) { r.Header.Del("Origin") }, 403},
		{"null-origin", func(r *http.Request) { r.Header.Set("Origin", "null") }, 403},
		{"duplicate-origin", func(r *http.Request) { r.Header.Add("Origin", portalOrigin) }, 403},
		{"cross-site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
		{"duplicate-session", func(r *http.Request) { r.AddCookie(cookie) }, 401},
		{"duplicate-csrf", func(r *http.Request) { r.Header.Add("X-CSRF-Token", csrf) }, 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if w := request(a.portal, "POST", portalOrigin, "/api/v1/auth/logout", "", []*http.Cookie{cookie}, csrf, tc.edit); w.Code != tc.code {
				t.Fatalf("got %d, want %d", w.Code, tc.code)
			}
		})
	}
}

func TestLoginCSRFStrictBodyGenericFailuresAndThrottle(t *testing.T) {
	a := newAPI(t)
	a.bootstrap(t)
	cookie, csrf := challenge(t, a.portal, portalOrigin, "/api/v1/auth/csrf")
	base := `{"username":"admin","password":"` + password + `"}`
	if w := request(a.portal, "POST", portalOrigin, "/api/v1/auth/login", base, nil, "", nil); w.Code != 403 {
		t.Fatal("login CSRF allowed")
	}
	for _, body := range []string{
		`{"username":"admin","username":"other","password":"x"}`,
		`{"username":"admin","password":"x","role":"admin"}`,
		`{"Username":"admin","password":"x"}`,
		base + ` {}`,
	} {
		if w := request(a.portal, "POST", portalOrigin, "/api/v1/auth/login", body, []*http.Cookie{cookie}, csrf, nil); w.Code != 400 {
			t.Fatal("ambiguous or overprivileged login body accepted", w.Code)
		}
	}
	if w := request(a.portal, "POST", portalOrigin, "/api/v1/auth/login", strings.Repeat("x", 8193), []*http.Cookie{cookie}, csrf, nil); w.Code != 413 {
		t.Fatal("oversized body accepted", w.Code)
	}
	if w := request(a.portal, "POST", portalOrigin, "/api/v1/auth/login", base, []*http.Cookie{cookie}, csrf, func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") }); w.Code != 415 {
		t.Fatal("non-JSON login accepted", w.Code)
	}
	for _, user := range []string{"admin", "absent"} {
		w := request(a.portal, "POST", portalOrigin, "/api/v1/auth/login", `{"username":"`+user+`","password":"wrong"}`, []*http.Cookie{cookie}, csrf, nil)
		if w.Code != 401 || !strings.Contains(w.Body.String(), `"code":"invalid_credentials"`) || strings.Contains(w.Body.String(), user) {
			t.Fatal("login error disclosed account/input", w.Code, w.Body.String())
		}
	}
	for range 4 {
		_ = request(a.portal, "POST", portalOrigin, "/api/v1/auth/login", `{"username":"admin","password":"wrong"}`, []*http.Cookie{cookie}, csrf, nil)
	}
	w := request(a.portal, "POST", portalOrigin, "/api/v1/auth/login", base, []*http.Cookie{cookie}, csrf, nil)
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatal("login not rate limited", w.Code)
	}
}

func TestSessionDisableEpochAndDatabaseOutage(t *testing.T) {
	for _, mode := range []string{"disabled", "epoch", "expired", "database-outage"} {
		t.Run(mode, func(t *testing.T) {
			a := newAPI(t)
			a.bootstrap(t)
			cookie, _ := a.login(t, nil)
			code := 401
			switch mode {
			case "disabled":
				fixtureSQL(t, a.path, "UPDATE users SET disabled_at=0")
			case "epoch":
				fixtureSQL(t, a.path, "UPDATE users SET auth_epoch=auth_epoch+1")
			case "expired":
				fixtureSQL(t, a.path, "UPDATE sessions SET last_seen_at=created_at,idle_expires_at=created_at,absolute_expires_at=created_at")
			case "database-outage":
				a.store.Close()
				code = 503
			}
			w := request(a.portal, "GET", portalOrigin, "/api/v1/auth/session", "", []*http.Cookie{cookie}, "", nil)
			if w.Code != code {
				t.Fatal("inactive/unavailable auth failed open", w.Code)
			}
		})
	}
}

func TestChallengeMACExpiryAndConstructorValidation(t *testing.T) {
	now := time.Now()
	h := &handler{nonceName: "__Host-test", now: func() time.Time { return now }}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", portalOrigin, nil)
	h.csrfChallenge(w, r)
	cookie := w.Result().Cookies()[0]
	r.AddCookie(cookie)
	r.Header.Set("X-CSRF-Token", auth.CSRF(cookie.Value))
	if !h.validChallenge(r) {
		t.Fatal("valid signed challenge rejected")
	}
	now = now.Add(5 * time.Minute)
	if h.validChallenge(r) {
		t.Fatal("expired challenge accepted")
	}
	now = now.Add(-5 * time.Minute)
	forged := *cookie
	replacement := "a"
	if cookie.Value[0] == 'a' {
		replacement = "b"
	}
	forged.Value = replacement + cookie.Value[1:]
	r = httptest.NewRequest("GET", portalOrigin, nil)
	r.AddCookie(&forged)
	r.Header.Set("X-CSRF-Token", auth.CSRF(forged.Value))
	if h.validChallenge(r) {
		t.Fatal("attacker-controlled cookie/CSRF pair bypassed MAC")
	}
	if _, err := NewPortalHandler(nil, portalOrigin); err == nil {
		t.Fatal("nil auth service accepted")
	}
	a := newAPI(t)
	// Constructors reject cleartext and off-origin path/query configurations.
	for _, bad := range []string{"http://portal.example.test", portalOrigin + "/path", portalOrigin + "?x=1"} {
		if _, err := newHandler(a.service, bad, false); err == nil {
			t.Fatal("invalid API origin accepted")
		}
	}
	if _, err := NewSetupHandler(a.service, portalOrigin); err == nil {
		t.Fatal("public setup origin accepted")
	}
	if TLSConfig().MinVersion != tls.VersionTLS13 {
		t.Fatal("TLS minimum weakened")
	}
}
