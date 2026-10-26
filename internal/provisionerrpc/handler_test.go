package provisionerrpc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/provisioner"
)

const controller = "11111111-1111-4111-8111-111111111111"
const job = "22222222-2222-4222-8222-222222222222"

type issuer struct {
	cert   *x509.Certificate
	key    ed25519.PrivateKey
	pem    []byte
	serial int64
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-only controller CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(7 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &issuer{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), serial: 1}
}
func (c *issuer) leaf(t *testing.T, uri string, server bool, duration time.Duration) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c.serial++
	template := &x509.Certificate{SerialNumber: big.NewInt(c.serial), Subject: pkix.Name{CommonName: "controller"}, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(duration), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if uri != "" {
		u, err := url.Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		template.URIs = []*url.URL{u}
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = []string{"localhost"}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, c.cert, public, c.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}, cert
}
func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func manager(t *testing.T) *provisioner.Manager {
	t.Helper()
	l, err := provisioner.OpenLedger(context.Background(), filepath.Join(t.TempDir(), "host.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	m, err := provisioner.NewManager(l, provisioner.UnconfiguredBackend{}, provisioner.Config{Templates: []provisioner.Template{{ID: "build-linux-v1", Digest: "sha256:" + strings.Repeat("a", 64)}}})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestRealMutualTLSAndControllerOnlyAdmission(t *testing.T) {
	ca := newIssuer(t)
	serverPair, _ := ca.leaf(t, "", true, 6*time.Hour)
	legit, legitLeaf := ca.leaf(t, "spiffe://dev-orchestrator/controller/"+controller, false, 6*time.Hour)
	worker, workerLeaf := ca.leaf(t, "spiffe://dev-orchestrator/worker/"+controller, false, 6*time.Hour)
	unpinned, _ := ca.leaf(t, "spiffe://dev-orchestrator/controller/"+controller, false, 6*time.Hour)
	expired, _ := ca.leaf(t, "spiffe://dev-orchestrator/controller/"+controller, false, -time.Second)
	foreignCA := newIssuer(t)
	foreign, _ := foreignCA.leaf(t, "spiffe://dev-orchestrator/controller/"+controller, false, 6*time.Hour)
	m := manager(t)
	server := httptest.NewUnstartedServer(nil)
	h, err := NewHandler(m, server.Listener.Addr().String(), controller, []string{fingerprint(legitLeaf), fingerprint(workerLeaf)})
	if err != nil {
		t.Fatal(err)
	}
	var wall atomic.Int64
	wall.Store(time.Now().UnixNano())
	h.(*handler).now = func() time.Time { return time.Unix(0, wall.Load()) }
	config, err := ServerTLSConfig(ca.pem)
	if err != nil {
		t.Fatal(err)
	}
	config.Certificates = []tls.Certificate{serverPair}
	server.TLS = config
	server.Config.Handler = h
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	client := func(pair *tls.Certificate) *http.Client {
		cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
		if pair != nil {
			cfg.Certificates = []tls.Certificate{*pair}
		}
		transport := &http.Transport{TLSClientConfig: cfg}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: 5 * time.Second}
	}
	for name, pair := range map[string]*tls.Certificate{"no-cert": nil, "untrusted-ca": &foreign, "expired": &expired} {
		t.Run(name, func(t *testing.T) {
			response, err := client(pair).Get(server.URL + "/internal/v1/capabilities")
			if err == nil {
				response.Body.Close()
				t.Fatal("mTLS handshake accepted invalid client", response.StatusCode)
			}
		})
	}
	for name, pair := range map[string]*tls.Certificate{"worker-with-pin": &worker, "controller-without-pin": &unpinned} {
		t.Run(name, func(t *testing.T) {
			response, err := client(pair).Get(server.URL + "/internal/v1/capabilities")
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != 403 {
				t.Fatal("wrong service identity allowed", response.StatusCode)
			}
		})
	}
	good := client(&legit)
	response, err := good.Get(server.URL + "/internal/v1/capabilities")
	if err != nil {
		t.Fatal(err)
	}
	var caps provisioner.Capabilities
	if err := json.NewDecoder(response.Body).Decode(&caps); err != nil || response.StatusCode != 200 || caps.ExecutionEnabled || response.TLS.Version != tls.VersionTLS13 {
		t.Fatal("disabled backend advertised execution", err)
	}
	response.Body.Close()
	call := func(path, body string, edit func(*http.Request)) *http.Response {
		t.Helper()
		r, _ := http.NewRequest("POST", server.URL+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if edit != nil {
			edit(r)
		}
		response, err := good.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	r := contracts.BuildLeaseRequest{SchemaVersion: 1, CommandID: "33333333-3333-4333-8333-333333333333", JobID: job, AppID: "44444444-4444-4444-8444-444444444444",
		DeploymentID: "55555555-5555-4555-8555-555555555555", TemplateID: "build-linux-v1", ProfileID: "build-small-v1", Nonce: strings.Repeat("b", 64), ExpiresAt: time.Now().Add(5 * time.Minute)}
	encoded, _ := json.Marshal(r)
	response = call("/internal/v1/build-leases", string(encoded), nil)
	if response.StatusCode != 503 {
		t.Fatal("production backend accepted VM execution", response.StatusCode)
	}
	response.Body.Close()
	if _, err := m.Get(context.Background(), controller, job); err == nil {
		t.Fatal("disabled backend reserved a job")
	}
	for _, test := range []struct {
		body   string
		status int
	}{
		{strings.TrimSuffix(string(encoded), "}") + `,"xml":"<domain/>"}`, 400},
		{strings.Repeat(" ", contracts.MaxBuildLeaseBytes+1), 413},
	} {
		response = call("/internal/v1/build-leases", test.body, nil)
		if response.StatusCode != test.status {
			t.Fatal("unsafe request accepted", response.StatusCode)
		}
		response.Body.Close()
	}
	for _, edit := range []func(*http.Request){func(r *http.Request) { r.Header.Set("Origin", "https://portal.example.test") }, func(r *http.Request) { r.Header.Set("Cookie", "__Host-portal_session=not-a-controller") }, func(r *http.Request) {
		r.Host = "evil.example"
		r.Header.Set("X-Forwarded-Host", server.Listener.Addr().String())
	}} {
		response = call("/internal/v1/build-leases", string(encoded), edit)
		if response.StatusCode != 403 {
			t.Fatal("browser/header authority bypass", response.StatusCode)
		}
		response.Body.Close()
	}
	response = call("/internal/v1/build-leases/"+job+"/release", `{"host_path":"/"}`, nil)
	if response.StatusCode != 400 {
		t.Fatal("release accepted host parameters")
	}
	response.Body.Close()
	wall.Store(time.Now().Add(7 * time.Hour).UnixNano())
	response, err = good.Get(server.URL + "/internal/v1/capabilities")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("reused TLS connection bypassed certificate expiry")
	}
}

func TestCertificatePolicyRejectsLongLifetimeAndCommonNameFallback(t *testing.T) {
	ca := newIssuer(t)
	for _, test := range []struct {
		uri      string
		duration time.Duration
	}{{"spiffe://dev-orchestrator/controller/" + controller, 48 * time.Hour}, {"", 6 * time.Hour}, {"spiffe://dev-orchestrator/controller/" + controller + "?role=admin", 6 * time.Hour}} {
		_, leaf := ca.leaf(t, test.uri, false, test.duration)
		h, err := NewHandler(manager(t), "localhost:9444", controller, []string{fingerprint(leaf)})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("GET", "/internal/v1/capabilities", nil)
		r.Host = "localhost:9444"
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, ca.cert}}}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("certificate policy bypass", w.Code)
		}
	}
	if _, err := ServerTLSConfig(nil); err == nil {
		t.Fatal("empty CA accepted")
	}
}
