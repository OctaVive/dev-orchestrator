package httpapi

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTLSBrowserSessionWorkflow(t *testing.T) {
	a := newAPI(t)
	a.bootstrap(t)
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	h, err := NewPortalHandler(a.service, origin)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = h
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = TLSConfig()
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	client.Timeout = 10 * time.Second
	client.Jar, _ = cookiejar.New(nil)
	get := func(path string) *http.Response {
		t.Helper()
		response, err := client.Get(origin + path)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	response := get("/api/v1/auth/csrf")
	var pre struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&pre); err != nil || response.StatusCode != 200 || response.TLS.Version != tls.VersionTLS13 {
		t.Fatal("TLS challenge failed", err)
	}
	response.Body.Close()
	post := func(path, body, csrf string) *http.Response {
		t.Helper()
		request, _ := http.NewRequest("POST", origin+path, strings.NewReader(body))
		request.Header.Set("Origin", origin)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-CSRF-Token", csrf)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	response = post("/api/v1/auth/login", `{"username":"admin","password":"`+password+`"}`, pre.CSRF)
	var session sessionResponse
	if err := json.NewDecoder(response.Body).Decode(&session); err != nil || response.StatusCode != 200 || session.CSRF == "" {
		t.Fatal("TLS login failed", err)
	}
	response.Body.Close()
	response = get("/api/v1/auth/session")
	if response.StatusCode != 200 {
		t.Fatal("secure cookie session did not work", response.StatusCode)
	}
	response.Body.Close()
	response = post("/api/v1/auth/logout", "", session.CSRF)
	if response.StatusCode != 204 {
		t.Fatal("TLS logout failed", response.StatusCode)
	}
	response.Body.Close()
	response = get("/api/v1/auth/session")
	if response.StatusCode != 401 {
		t.Fatal("TLS logout left session active", response.StatusCode)
	}
	response.Body.Close()
	transport := client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.MinVersion, transport.TLSClientConfig.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	defer transport.CloseIdleConnections()
	legacy := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	if response, err := legacy.Get(origin + "/api/v1/auth/session"); err == nil {
		response.Body.Close()
		t.Fatal("TLS 1.2 was accepted")
	}
}
