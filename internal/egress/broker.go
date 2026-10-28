package egress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// Lease must originate in host-controlled state, keyed by the actual peer IP.
// Its context is cancelled on revocation; headers never select an identity.
type Lease struct {
	Context    context.Context
	Expires    time.Time
	PolicyHash string
}
type LookupLease func(netip.Addr) (Lease, bool)
type Broker struct {
	policy        Policy
	ca            tls.Certificate
	lookup        LookupLease
	resolver      *net.Resolver
	slots         chan struct{}
	lookupIP      func(context.Context, string, string) ([]netip.Addr, error)
	dial          func(context.Context, string, string) (net.Conn, error)
	upstreamRoots *x509.CertPool // nil uses system roots; test-only private field
	decision      func(string, string)
}

func New(p Policy, ca tls.Certificate, resolver *net.Resolver, lookup LookupLease) (*Broker, error) {
	return NewObserved(p, ca, resolver, lookup, nil)
}

// Observer receives only a fixed reason code and policy identity, never input
// URLs, headers, credentials, bodies, DNS names or raw transport errors.
func NewObserved(p Policy, ca tls.Certificate, resolver *net.Resolver, lookup LookupLease, observer func(string, string)) (*Broker, error) {
	if p.Validate() != nil || lookup == nil || resolver == nil || len(ca.Certificate) == 0 || ca.PrivateKey == nil {
		return nil, ErrDenied
	}
	cert, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 || time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
		return nil, ErrDenied
	}
	// Copy operator policy so mutation by the caller cannot change its identity.
	if p.Hosts != nil {
		hosts := make([]string, len(p.Hosts))
		copy(hosts, p.Hosts)
		p.Hosts = hosts
	}
	if p.Deny != nil {
		deny := make([]netip.Prefix, len(p.Deny))
		copy(deny, p.Deny)
		p.Deny = deny
	}
	ca.Leaf = cert
	return &Broker{policy: p, ca: ca, lookup: lookup, resolver: resolver, slots: make(chan struct{}, p.MaxConnections), lookupIP: resolver.LookupNetIP, dial: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, decision: observer}, nil
}

func (b *Broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reason := "admission_denied"
	defer func() {
		if b.decision != nil {
			b.decision(reason, b.policy.Hash())
		}
	}()
	deny := func() { http.Error(w, "egress denied", http.StatusForbidden) }
	host, err := b.policy.Authority(r.Host)
	peer, e := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil || e != nil || r.Method != "CONNECT" || r.RequestURI != r.Host || r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
		deny()
		return
	}
	lease, ok := b.lookup(peer.Addr().Unmap())
	if !ok || lease.Context == nil || lease.Context.Err() != nil || lease.PolicyHash != b.policy.Hash() || !time.Now().Before(lease.Expires) {
		deny()
		return
	}
	select {
	case b.slots <- struct{}{}:
		defer func() { <-b.slots }()
	default:
		deny()
		return
	}
	end := time.Now().Add(b.policy.Duration())
	if lease.Expires.Before(end) {
		end = lease.Expires
	}
	ctx, cancel := context.WithDeadline(lease.Context, end)
	defer cancel()
	reason = "client_denied"
	cert, err := b.certificate(host, end)
	if err != nil {
		deny()
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		deny()
		return
	}
	raw, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer raw.Close()
	raw.SetDeadline(end)
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	if _, err = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if rw.Flush() != nil {
		return
	}
	conn := tls.Server(&bufferedConn{raw, rw.Reader}, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello.ServerName != host {
			return nil, ErrDenied
		}
		return nil, nil
	}})
	if conn.HandshakeContext(ctx) != nil {
		return
	}
	reader := bufio.NewReaderSize(io.LimitReader(&pacedReader{r: conn, p: pacer{ctx: ctx, rate: b.policy.Rate()}}, b.policy.MaxBytes), 32768)
	var header bytes.Buffer
	for {
		line, e := reader.ReadSlice('\n')
		if e != nil || header.Len()+len(line) > 32768 {
			return
		}
		header.Write(line)
		if string(line) == "\r\n" {
			break
		}
	}
	reader = bufio.NewReader(io.MultiReader(bytes.NewReader(header.Bytes()), reader))
	// One inspected request per connection avoids authority-changing reuse.
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	defer req.Body.Close()
	authority := req.Host
	if authority == host {
		authority = net.JoinHostPort(host, "443")
	}
	if authority != net.JoinHostPort(host, "443") || req.Method == "CONNECT" || req.Header.Get("Upgrade") != "" || req.Header.Get("Connection") != "" || req.URL.IsAbs() || req.ContentLength > b.policy.MaxBytes {
		return
	}
	req.RequestURI = ""
	req.URL.Scheme = "https"
	req.URL.Host = net.JoinHostPort(host, "443")
	req.Close = true
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 32768, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, RootCAs: b.upstreamRoots}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		answers, err := b.lookupIP(ctx, "ip", host)
		if err != nil || len(answers) == 0 || len(answers) > 64 {
			return nil, ErrDenied
		}
		for _, a := range answers {
			if !b.policy.Public(a) {
				return nil, ErrDenied
			}
		}
		return b.dial(ctx, "tcp", net.JoinHostPort(answers[0].String(), "443"))
	}}
	defer tr.CloseIdleConnections()
	resp, err := tr.RoundTrip(req.WithContext(ctx))
	if err != nil {
		reason = "upstream_denied"
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 || resp.StatusCode == 101 || resp.Header.Get("Upgrade") != "" {
		reason = "response_denied"
		return
	}
	resp.Close = true
	// Limit the entire serialized response, including chunked framing.
	reason = "transfer_denied"
	if resp.Write(&budgetWriter{w: &pacedWriter{w: conn, p: pacer{ctx: ctx, rate: b.policy.Rate()}}, left: b.policy.MaxBytes}) == nil {
		reason = "allowed"
	}
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

type budgetWriter struct {
	w    io.Writer
	left int64
}

func (w *budgetWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.left {
		return 0, ErrDenied
	}
	n, e := w.w.Write(p)
	w.left -= int64(n)
	return n, e
}

var serialMu sync.Mutex

func (b *Broker) certificate(host string, end time.Time) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	if b.ca.Leaf.NotAfter.Before(end) {
		end = b.ca.Leaf.NotAfter
	}
	t := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Minute), NotAfter: end, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	// The caller supplies an isolated build-only signing key. Serialize signing
	// for implementations of crypto.Signer that do not support concurrent use.
	serialMu.Lock()
	defer serialMu.Unlock()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	der, err := x509.CreateCertificate(rand.Reader, t, b.ca.Leaf, &leafKey.PublicKey, b.ca.PrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, b.ca.Certificate[0]}, PrivateKey: leafKey}, nil
}
