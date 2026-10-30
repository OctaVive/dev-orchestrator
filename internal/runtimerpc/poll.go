// Package runtimerpc provides outbound-only, bounded runtime agent polling.
package runtimerpc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/runtimeagent"
)

type Config struct {
	Origin         string
	ServerName     string
	ControllerURI  string
	ControllerSPKI string
	Roots          *x509.CertPool
	Identity       tls.Certificate
	// Revocation must consult the locally refreshed controller trust/lease policy.
	Revocation func(*x509.Certificate) error
}
type Client struct {
	http       *http.Client
	origin     string
	revocation func(*x509.Certificate) error
}

func New(c Config) (*Client, error) {
	u, e := url.Parse(c.Origin)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || c.ServerName == "" || c.ControllerURI == "" || len(c.ControllerSPKI) != 64 || c.Roots == nil || len(c.Identity.Certificate) == 0 || c.Identity.PrivateKey == nil || c.Revocation == nil {
		return nil, runtimeagent.ErrDenied
	}
	if _, e := hex.DecodeString(c.ControllerSPKI); e != nil {
		return nil, runtimeagent.ErrDenied
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: c.Roots.Clone(), ServerName: c.ServerName, Certificates: []tls.Certificate{c.Identity}, VerifyConnection: func(cs tls.ConnectionState) error {
		if len(cs.VerifiedChains) == 0 || len(cs.PeerCertificates) == 0 {
			return runtimeagent.ErrDenied
		}
		leaf := cs.PeerCertificates[0]
		sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		if hex.EncodeToString(sum[:]) != c.ControllerSPKI || len(leaf.URIs) != 1 || leaf.URIs[0].String() != c.ControllerURI || c.Revocation(leaf) != nil {
			return runtimeagent.ErrDenied
		}
		return nil
	}}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: cfg, MaxConnsPerHost: 1, MaxIdleConns: 1, ResponseHeaderTimeout: 10 * time.Second}
	return &Client{http: &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return runtimeagent.ErrDenied }}, origin: u.Scheme + "://" + u.Host, revocation: c.Revocation}, nil
}

// Poll carries at most one bounded result and receives at most one command.
// Idle responses are 204; neither redirects nor arbitrary response URLs are used.
func (c *Client) Poll(ctx context.Context, worker, incarnation string, result *runtimeagent.Result) (*runtimeagent.Command, error) {
	if !contracts.ValidJobID(worker) || !contracts.ValidJobID(incarnation) {
		return nil, runtimeagent.ErrDenied
	}
	body := struct {
		WorkerID    string               `json:"worker_id"`
		Incarnation string               `json:"incarnation"`
		Result      *runtimeagent.Result `json:"result,omitempty"`
	}{worker, incarnation, result}
	b, e := json.Marshal(body)
	if e != nil || len(b) > 64<<10 {
		return nil, runtimeagent.ErrDenied
	}
	req, e := http.NewRequestWithContext(ctx, "POST", c.origin+"/runtime/v3/poll", bytes.NewReader(b))
	if e != nil {
		return nil, runtimeagent.ErrDenied
	}
	req.Header.Set("Content-Type", "application/json")
	res, e := c.http.Do(req)
	if e != nil {
		return nil, runtimeagent.ErrDenied
	}
	defer res.Body.Close()
	if !c.validPeer(res.TLS) {
		return nil, runtimeagent.ErrDenied
	}
	if res.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if res.StatusCode != http.StatusOK {
		return nil, runtimeagent.ErrDenied
	}
	cmd, e := runtimeagent.Decode(io.LimitReader(res.Body, contracts.MaxPlanBytes+1))
	if e != nil {
		return nil, runtimeagent.ErrDenied
	}
	return &cmd, nil
}
func (c *Client) Close() { c.http.CloseIdleConnections() }

func (c *Client) validPeer(state *tls.ConnectionState) bool {
	if state == nil || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 || c.revocation(state.PeerCertificates[0]) != nil {
		return false
	}
	now := time.Now()
	for _, chain := range state.VerifiedChains {
		for _, certificate := range chain {
			if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
				return false
			}
		}
	}
	return true
}
