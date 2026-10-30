package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTestBroker(t *testing.T, p Policy, lease Lease) (*Broker, *x509.CertPool) {
	t.Helper()
	ca := testCA(t)
	if lease.Context == nil {
		lease.Context = context.Background()
	}
	if lease.Expires.IsZero() {
		lease.Expires = time.Now().Add(30 * time.Second)
	}
	if lease.PolicyHash == "" {
		lease.PolicyHash = p.Hash()
	}
	b, e := New(p, ca, net.DefaultResolver, func(netip.Addr) (Lease, bool) { return lease, true })
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	cert, _ := x509.ParseCertificate(ca.Certificate[0])
	roots.AddCert(cert)
	return b, roots
}
func connectBroker(t *testing.T, s *httptest.Server, roots *x509.CertPool) *tls.Conn {
	t.Helper()
	c, e := net.Dial("tcp", s.Listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	br := bufio.NewReader(c)
	for {
		line, e := br.ReadString('\n')
		if e != nil {
			c.Close()
			t.Fatal(e)
		}
		if line == "\r\n" {
			break
		}
	}
	tc := tls.Client(&bufferedConn{c, br}, &tls.Config{RootCAs: roots, ServerName: "example.com"})
	if e = tc.Handshake(); e != nil {
		c.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { tc.Close() })
	return tc
}
func upstreamFixture(t *testing.T, b *Broker, h http.Handler) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	ca := testCA(t)
	ca.Leaf, _ = x509.ParseCertificate(ca.Certificate[0])
	signer := &Broker{ca: ca}
	leaf, e := signer.certificate("example.com", time.Now().Add(time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	s := httptest.NewUnstartedServer(h)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}}
	s.StartTLS()
	t.Cleanup(s.Close)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Leaf)
	b.upstreamRoots = roots
	count := &atomic.Int32{}
	b.lookupIP = func(_ context.Context, network, host string) ([]netip.Addr, error) {
		if network != "ip" || host != "example.com." {
			t.Error("DNS lookup was not absolute", network, host)
			return nil, ErrDenied
		}
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	b.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		count.Add(1)
		if network != "tcp" || address != "8.8.8.8:443" {
			return nil, errors.New("not pinned")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", s.Listener.Addr().String())
	}
	return s, count
}
func TestInspectedUpstreamAndPinnedAddress(t *testing.T) {
	b, roots := newTestBroker(t, testPolicy(), Lease{})
	var requests atomic.Int32
	_, dials := upstreamFixture(t, b, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Host != "example.com" || r.Header.Get("Proxy-Authorization") != "" {
			t.Error("authority or proxy credential forwarding")
		}
		fmt.Fprint(w, "approved body")
	}))
	s := httptest.NewServer(b)
	defer s.Close()
	c := connectBroker(t, s, roots)
	fmt.Fprint(c, "GET /?private-fixture HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: secret-fixture\r\n\r\n")
	resp, e := http.ReadResponse(bufio.NewReader(c), nil)
	if e != nil {
		t.Fatal(e)
	}
	body, e := io.ReadAll(resp.Body)
	resp.Body.Close()
	if e != nil || string(body) != "approved body" || dials.Load() != 1 || requests.Load() != 1 {
		t.Fatalf("response=%q dials=%d requests=%d error=%v", body, dials.Load(), requests.Load(), e)
	}
	if _, e = c.Read(make([]byte, 1)); e == nil {
		t.Fatal("connection reused")
	}
}
func TestDNSFailuresNeverDial(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answers []netip.Addr
		err     error
	}{
		{"mixed", []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("::1")}, nil},
		{"mapped", []netip.Addr{netip.MustParseAddr("::ffff:8.8.8.8")}, nil},
		{"private", []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil},
		{"empty", nil, nil}, {"failure", nil, errors.New("sensitive-resolver-error")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, roots := newTestBroker(t, testPolicy(), Lease{})
			var dials atomic.Int32
			b.lookupIP = func(context.Context, string, string) ([]netip.Addr, error) { return tc.answers, tc.err }
			b.dial = func(context.Context, string, string) (net.Conn, error) { dials.Add(1); return nil, ErrDenied }
			s := httptest.NewServer(b)
			defer s.Close()
			c := connectBroker(t, s, roots)
			fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
			data, _ := io.ReadAll(c)
			if len(data) != 0 || dials.Load() != 0 {
				t.Fatal("denied DNS reached dial/client")
			}
		})
	}
}
func TestAuthorityAndTunnelDenials(t *testing.T) {
	for _, request := range []string{
		"GET / HTTP/1.1\r\nHost: wrong.example\r\n\r\n",
		"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
		"GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: example.com\r\nX-Large: " + strings.Repeat("x", 33000) + "\r\n\r\n",
	} {
		t.Run(request[:min(len(request), 20)], func(t *testing.T) {
			b, roots := newTestBroker(t, testPolicy(), Lease{})
			var lookups atomic.Int32
			b.lookupIP = func(context.Context, string, string) ([]netip.Addr, error) { lookups.Add(1); return nil, ErrDenied }
			s := httptest.NewServer(b)
			defer s.Close()
			c := connectBroker(t, s, roots)
			io.WriteString(c, request)
			io.ReadAll(c)
			if lookups.Load() != 0 {
				t.Fatal("invalid HTTP reached resolver")
			}
		})
	}
}
func TestUpstreamResponseAndCertificateDenials(t *testing.T) {
	for _, tc := range []struct {
		name            string
		status          int
		upgrade, badTLS bool
	}{{"redirect", 302, false, false}, {"upgrade", 101, true, false}, {"tls", 200, false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			b, roots := newTestBroker(t, testPolicy(), Lease{})
			upstreamFixture(t, b, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "https://private.example/secret")
				if tc.upgrade {
					w.Header().Set("Upgrade", "websocket")
				}
				w.WriteHeader(tc.status)
				io.WriteString(w, "secret-response")
			}))
			if tc.badTLS {
				b.upstreamRoots = x509.NewCertPool()
			}
			s := httptest.NewServer(b)
			defer s.Close()
			c := connectBroker(t, s, roots)
			fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
			data, _ := io.ReadAll(c)
			if len(data) > 0 {
				t.Fatalf("response leaked %q", data)
			}
		})
	}
}
func TestFreshResolutionPreventsRebinding(t *testing.T) {
	b, roots := newTestBroker(t, testPolicy(), Lease{})
	_, dials := upstreamFixture(t, b, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	var calls atomic.Int32
	b.lookupIP = func(context.Context, string, string) ([]netip.Addr, error) {
		if calls.Add(1) == 1 {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	s := httptest.NewServer(b)
	defer s.Close()
	for i := 0; i < 2; i++ {
		c := connectBroker(t, s, roots)
		fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
		data, _ := io.ReadAll(c)
		if i == 0 && !strings.Contains(string(data), "ok") {
			t.Fatal("first fetch failed")
		}
		if i == 1 && len(data) != 0 {
			t.Fatal("rebind allowed")
		}
	}
	if calls.Load() != 2 || dials.Load() != 1 {
		t.Fatal("rebind dial or reuse")
	}
}
func TestLeaseAndResourceLimits(t *testing.T) {
	for _, lease := range []Lease{{Expires: time.Now().Add(-time.Second)}, {PolicyHash: strings.Repeat("a", 64)}} {
		b, _ := newTestBroker(t, testPolicy(), lease)
		r := httptest.NewRequest("CONNECT", "http://example.com:443", nil)
		r.Host = "example.com:443"
		r.RequestURI = r.Host
		r.RemoteAddr = "192.0.2.2:1234"
		w := httptest.NewRecorder()
		b.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
	p := testPolicy()
	p.MaxConnections = 1
	b, roots := newTestBroker(t, p, Lease{Expires: time.Now().Add(2 * time.Second)})
	s := httptest.NewServer(b)
	defer s.Close()
	c := connectBroker(t, s, roots)
	r := httptest.NewRequest("CONNECT", "http://example.com:443", nil)
	r.Host = "example.com:443"
	r.RequestURI = r.Host
	r.RemoteAddr = "192.0.2.2:1234"
	w := httptest.NewRecorder()
	b.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("unbounded concurrency")
	}
	if _, e := c.Read(make([]byte, 1)); e == nil {
		t.Fatal("deadline did not close idle TLS")
	}
}
func TestDecisionMetadataExcludesSensitiveInput(t *testing.T) {
	b, roots := newTestBroker(t, testPolicy(), Lease{})
	decisions := make(chan string, 1)
	b.decision = func(reason, hash string) { decisions <- reason + hash }
	b.lookupIP = func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, errors.New("secret-upstream-error")
	}
	s := httptest.NewServer(b)
	defer s.Close()
	c := connectBroker(t, s, roots)
	fmt.Fprint(c, "POST /?secret-query HTTP/1.1\r\nHost: example.com\r\nAuthorization: secret-credential\r\nContent-Length: 11\r\n\r\nsecret-body")
	io.ReadAll(c)
	select {
	case d := <-decisions:
		if strings.Contains(d, "secret") || !strings.HasPrefix(d, "upstream_denied") {
			t.Fatal(d)
		}
	case <-time.After(time.Second):
		t.Fatal("no decision")
	}
}
