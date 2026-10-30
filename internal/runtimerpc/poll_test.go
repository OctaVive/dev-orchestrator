package runtimerpc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dev-orchestrator/internal/runtimeagent"
)

const id = "11111111-1111-4111-8111-111111111111"

func tlsFixture(t *testing.T) (Config, *tls.Config) {
	t.Helper()
	now := time.Now()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "M09 test CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	issue := func(serial int64, uri string, usage x509.ExtKeyUsage) tls.Certificate {
		p, k, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		u, _ := url.Parse(uri)
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"controller.test"}, URIs: []*url.URL{u}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		b, e := x509.CreateCertificate(rand.Reader, template, ca, p, key)
		if e != nil {
			t.Fatal(e)
		}
		leaf, _ := x509.ParseCertificate(b)
		return tls.Certificate{Certificate: [][]byte{b, der}, PrivateKey: k, Leaf: leaf}
	}
	server := issue(2, "spiffe://tap/runtime-controller", x509.ExtKeyUsageServerAuth)
	client := issue(3, "spiffe://tap/runtime-agent/"+id, x509.ExtKeyUsageClientAuth)
	sum := sha256.Sum256(server.Leaf.RawSubjectPublicKeyInfo)
	cfg := Config{ServerName: "controller.test", ControllerURI: "spiffe://tap/runtime-controller", ControllerSPKI: hex.EncodeToString(sum[:]), Roots: roots, Identity: client, Revocation: func(*x509.Certificate) error { return nil }}
	return cfg, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
}
func TestMTLSPollBoundaries(t *testing.T) {
	cfg, tlsConfig := tlsFixture(t)
	var mode atomic.Value
	mode.Store("idle")
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/runtime/v3/poll" || r.Method != "POST" || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			t.Error("invalid polling identity")
		}
		switch mode.Load().(string) {
		case "idle":
			w.WriteHeader(204)
		case "redirect":
			http.Redirect(w, r, "https://foreign.invalid", 307)
		case "duplicate":
			w.Write([]byte(`{"version":3,"version":3}`))
		case "oversize":
			w.Write([]byte(strings.Repeat(" ", 64<<10) + `{}`))
		case "command":
			w.Write([]byte(`{"version":3,"operation":"probe"}`))
		}
	}))
	server.TLS = tlsConfig
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	cfg.Origin = server.URL
	c, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if cmd, e := c.Poll(context.Background(), id, id, nil); e != nil || cmd != nil {
		t.Fatal("idle", e)
	}
	mode.Store("command")
	if cmd, e := c.Poll(context.Background(), id, id, nil); e != nil || cmd == nil || cmd.Operation != "probe" {
		t.Fatal("typed command", e)
	}
	for _, m := range []string{"redirect", "duplicate", "oversize"} {
		mode.Store(m)
		if _, e := c.Poll(context.Background(), id, id, nil); e != runtimeagent.ErrDenied {
			t.Fatal(m, e)
		}
	}
	for name, change := range map[string]func(*Config){"pin": func(c *Config) { c.ControllerSPKI = strings.Repeat("0", 64) }, "uri": func(c *Config) { c.ControllerURI = "spiffe://tap/relay" }, "name": func(c *Config) { c.ServerName = "wrong.test" }, "role": func(c *Config) { c.Identity = tls.Certificate{} }} {
		t.Run(name, func(t *testing.T) {
			bad := cfg
			change(&bad)
			c, e := New(bad)
			if e == nil {
				defer c.Close()
				_, e = c.Poll(context.Background(), id, id, nil)
			}
			if e != runtimeagent.ErrDenied {
				t.Fatal("TLS boundary accepted", e)
			}
		})
	}
}
func TestRevocationOnReusedTLSConnection(t *testing.T) {
	cfg, tlsCfg := tlsFixture(t)
	var revoked atomic.Bool
	cfg.Revocation = func(*x509.Certificate) error {
		if revoked.Load() {
			return runtimeagent.ErrDenied
		}
		return nil
	}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	s.TLS = tlsCfg
	s.StartTLS()
	defer s.Close()
	cfg.Origin = s.URL
	c, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if _, e := c.Poll(context.Background(), id, id, nil); e != nil {
		t.Fatal(e)
	}
	revoked.Store(true)
	if _, e := c.Poll(context.Background(), id, id, nil); e != runtimeagent.ErrDenied {
		t.Fatal("revoked reused connection", e)
	}
}
func TestRejectUnsafeOrigins(t *testing.T) {
	cfg, _ := tlsFixture(t)
	for _, origin := range []string{"http://controller.test", "https://user:secret@controller.test", "https://controller.test/path", "https://controller.test?secret=value", "https://controller.test#fragment"} {
		cfg.Origin = origin
		if c, e := New(cfg); e == nil {
			c.Close()
			t.Fatal("unsafe origin", origin)
		}
	}
}
