package egress

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func testCA(t *testing.T) tls.Certificate {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
func TestBrokerTLSAndRevocation(t *testing.T) {
	p := testPolicy()
	ca := testCA(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b, e := New(p, ca, net.DefaultResolver, func(netip.Addr) (Lease, bool) { return Lease{ctx, time.Now().Add(time.Minute), p.Hash()}, true })
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(b)
	defer server.Close()
	connect := func() net.Conn {
		t.Helper()
		c, e := net.Dial("tcp", server.Listener.Addr().String())
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		io.WriteString(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
		r := bufio.NewReader(c)
		for {
			line, e := r.ReadString('\n')
			if e != nil {
				t.Fatal(e)
			}
			if line == "\r\n" {
				break
			}
		}
		return c
	}
	roots := x509.NewCertPool()
	cert, _ := x509.ParseCertificate(ca.Certificate[0])
	roots.AddCert(cert)
	c := tls.Client(connect(), &tls.Config{RootCAs: roots, ServerName: "example.com"})
	defer c.Close()
	if e := c.Handshake(); e != nil {
		t.Fatal(e)
	}
	wrong := tls.Client(connect(), &tls.Config{RootCAs: roots, ServerName: "wrong.example"})
	defer wrong.Close()
	if wrong.Handshake() == nil {
		t.Fatal("SNI mismatch accepted")
	}
	cancel()
	buf := make([]byte, 1)
	if _, e := c.Read(buf); e == nil {
		t.Fatal("revoked session live")
	}
}
func TestBrokerAdmissionDeny(t *testing.T) {
	p := testPolicy()
	b, e := New(p, testCA(t), net.DefaultResolver, func(netip.Addr) (Lease, bool) { return Lease{}, false })
	if e != nil {
		t.Fatal(e)
	}
	for _, method := range []string{"GET", "CONNECT"} {
		r := httptest.NewRequest(method, "http://example.com/", nil)
		r.RemoteAddr = "192.0.2.2:1234"
		w := httptest.NewRecorder()
		b.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
}

func TestPolicyCopyRetainsLeaseHash(t *testing.T) {
	p := testPolicy()
	p.Deny = []netip.Prefix{}
	b, e := New(p, testCA(t), net.DefaultResolver, func(netip.Addr) (Lease, bool) { return Lease{}, false })
	if e != nil {
		t.Fatal(e)
	}
	if b.policy.Hash() != p.Hash() {
		t.Fatal("policy hash changed during copy")
	}
	p.Hosts[0] = "changed.example"
	if b.policy.Hosts[0] != "example.com" {
		t.Fatal("caller mutated policy")
	}
}
