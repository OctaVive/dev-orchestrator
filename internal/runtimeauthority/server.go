package runtimeauthority

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"dev-orchestrator/internal/artifacts"
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/runtimeagent"
)

type Server struct {
	state     State
	keys      map[string]ed25519.PublicKey
	downloads http.Handler
	active    chan struct{}
}

func NewServer(state State, keys map[string]ed25519.PublicKey, downloads http.Handler) (*Server, error) {
	if state == nil || len(keys) == 0 || downloads == nil {
		return nil, runtimeagent.ErrDenied
	}
	copied := map[string]ed25519.PublicKey{}
	for id, key := range keys {
		if len(key) != ed25519.PublicKeySize {
			return nil, runtimeagent.ErrDenied
		}
		copied[id] = append(ed25519.PublicKey(nil), key...)
	}
	return &Server{state, copied, downloads, make(chan struct{}, 16)}, nil
}
func peer(r *http.Request) (artifacts.RuntimePeer, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return artifacts.RuntimePeer{}, runtimeagent.ErrDenied
	}
	c := r.TLS.PeerCertificates[0]
	now := time.Now()
	if len(c.URIs) != 1 || len(c.Raw) == 0 || !strings.HasPrefix(c.URIs[0].String(), "spiffe://tap/runtime-agent/") {
		return artifacts.RuntimePeer{}, runtimeagent.ErrDenied
	}
	for _, chain := range r.TLS.VerifiedChains {
		for _, cert := range chain {
			if now.Before(cert.NotBefore) || !cert.NotAfter.After(now) {
				return artifacts.RuntimePeer{}, runtimeagent.ErrDenied
			}
		}
	}
	sum := sha256.Sum256(c.Raw)
	return artifacts.RuntimePeer{URI: c.URIs[0].String(), CertificateSHA256: hex.EncodeToString(sum[:])}, nil
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	deny := func() { http.Error(w, "denied", http.StatusForbidden) }
	if r.Method != "POST" || r.URL.RawQuery != "" {
		deny()
		return
	}
	p, err := peer(r)
	if err != nil {
		deny()
		return
	}
	select {
	case s.active <- struct{}{}:
		defer func() { <-s.active }()
	default:
		deny()
		return
	}
	requestContext := r.Context()
	ctx, cancel := context.WithTimeout(requestContext, 5*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	w.Header().Set("Cache-Control", "no-store")
	write := func(v any) {
		b, err := json.Marshal(v)
		if err != nil || len(b) > contracts.MaxPlanBytes {
			deny()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}
	switch r.URL.Path {
	case "/runtime/v1/lease":
		q, err := contracts.DecodeConfiguration[LeaseRequest](http.MaxBytesReader(w, r.Body, 4096))
		if err != nil {
			deny()
			return
		}
		until, err := s.state.RuntimeLease(ctx, p, q.WorkerID, q.Incarnation)
		if err != nil {
			deny()
			return
		}
		write(LeaseResponse{q.WorkerID, q.Incarnation, until})
	case "/runtime/v1/authorize":
		c, err := runtimeagent.Decode(http.MaxBytesReader(w, r.Body, contracts.MaxPlanBytes))
		if err != nil || c.Validate(time.Now(), c.WorkerID, c.Incarnation, s.keys) != nil || (c.Operation != "create" && c.Operation != "prepare") {
			deny()
			return
		}
		g, err := s.state.RuntimeGrant(ctx, p, c)
		if err != nil || !g.Matches(time.Now(), c) {
			deny()
			return
		}
		write(g)
	case "/runtime/v1/target":
		q, err := contracts.DecodeConfiguration[TargetRequest](http.MaxBytesReader(w, r.Body, 4096))
		if err != nil {
			deny()
			return
		}
		grant, err := s.state.RuntimeTargetGrant(ctx, p, q)
		if err != nil {
			deny()
			return
		}
		write(grant)
	case "/runtime/v3/poll":
		q, err := contracts.DecodeConfiguration[PollRequest](http.MaxBytesReader(w, r.Body, contracts.MaxPlanBytes))
		if err != nil {
			deny()
			return
		}
		c, err := s.state.RuntimePoll(ctx, p, q)
		if err != nil {
			deny()
			return
		}
		if c == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if c.Validate(time.Now(), q.WorkerID, q.Incarnation, s.keys) != nil {
			deny()
			return
		}
		write(c)
	case "/runtime/v1/artifact":
		// The artifact handler independently rechecks the exact peer/claim throughout
		// the stream and has its own 30-second transfer deadline.
		cancel()
		s.downloads.ServeHTTP(w, r.WithContext(requestContext))
	default:
		deny()
	}
}
