// Package provisionerrpc exposes the independent controller-only mTLS boundary.
// It never accepts portal sessions, browser origins, host paths or raw XML.
package provisionerrpc

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/provisioner"
)

var (
	controllerID   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	certificatePin = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ServerTLSConfig trusts ONLY the supplied client CA, not public web roots.
// The handler additionally requires a short-lived pinned controller certificate.
func ServerTLSConfig(clientCA []byte) (*tls.Config, error) {
	roots := x509.NewCertPool()
	if len(clientCA) > 1<<20 || !roots.AppendCertsFromPEM(clientCA) {
		return nil, errors.New("invalid controller CA")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, SessionTicketsDisabled: true}, nil
}

type handler struct {
	manager    *provisioner.Manager
	authority  string
	controller string
	uri        string
	pins       map[string]bool
	now        func() time.Time
	mux        *http.ServeMux
}

func NewHandler(manager *provisioner.Manager, authority, id string, pins []string) (http.Handler, error) {
	u, err := url.Parse("https://" + authority)
	if manager == nil || err != nil || u.Host != authority || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" ||
		authority == "" || strings.ContainsAny(authority, "\r\n\t \\") || !controllerID.MatchString(id) || len(pins) < 1 || len(pins) > 2 {
		return nil, errors.New("invalid provisioner RPC identity configuration")
	}
	h := &handler{manager: manager, authority: authority, controller: id, uri: "spiffe://dev-orchestrator/controller/" + id, pins: make(map[string]bool), now: time.Now, mux: http.NewServeMux()}
	for _, pin := range pins {
		if !certificatePin.MatchString(pin) {
			return nil, errors.New("invalid controller certificate pin")
		}
		h.pins[pin] = true
	}
	h.mux.HandleFunc("GET /internal/v1/capabilities", h.capabilities)
	h.mux.HandleFunc("POST /internal/v1/build-leases", h.create)
	h.mux.HandleFunc("GET /internal/v1/build-leases/{job}", h.get)
	h.mux.HandleFunc("POST /internal/v1/build-leases/{job}/release", h.release)
	h.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fail(w, http.StatusNotFound, "not_found") })
	return h, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if !h.authorized(r) {
		fail(w, http.StatusForbidden, "controller_identity_required")
		return
	}
	if !strings.EqualFold(r.Host, h.authority) || r.URL.IsAbs() || r.URL.RawPath != "" || path.Clean(r.URL.Path) != r.URL.Path ||
		r.Header.Get("Origin") != "" || len(r.Header.Values("Cookie")) != 0 {
		fail(w, http.StatusForbidden, "invalid_service_request")
		return
	}
	if r.Method == http.MethodPost {
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/json" {
			fail(w, http.StatusUnsupportedMediaType, "json_required")
			return
		}
	}
	h.mux.ServeHTTP(w, r)
}

func (h *handler) authorized(r *http.Request) bool {
	state := r.TLS
	if state == nil || state.Version < tls.VersionTLS13 || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return false
	}
	leaf := state.PeerCertificates[0]
	if !bytes.Equal(leaf.Raw, state.VerifiedChains[0][0].Raw) || leaf.IsCA || len(leaf.URIs) != 1 || leaf.URIs[0].String() != h.uri {
		return false
	}
	now := h.now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.NotAfter.Sub(leaf.NotBefore) > 24*time.Hour {
		return false
	}
	usage := false
	for _, value := range leaf.ExtKeyUsage {
		usage = usage || value == x509.ExtKeyUsageClientAuth
	}
	sum := sha256.Sum256(leaf.Raw)
	return usage && h.pins[hex.EncodeToString(sum[:])]
}

func (h *handler) capabilities(w http.ResponseWriter, r *http.Request) {
	caps, err := h.manager.Capabilities(r.Context())
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, caps)
}

func (h *handler) create(w http.ResponseWriter, r *http.Request) {
	lease, created, err := h.manager.Create(r.Context(), h.controller, r.Body)
	if err != nil {
		respondError(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, lease)
}

func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	lease, err := h.manager.Get(r.Context(), h.controller, r.PathValue("job"))
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, lease)
}

func (h *handler) release(w http.ResponseWriter, r *http.Request) {
	if err := contracts.DecodeEmptyObject(r.Body); err != nil {
		respondError(w, err)
		return
	}
	lease, err := h.manager.Release(r.Context(), h.controller, r.PathValue("job"))
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, lease)
}

func respondError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, provisioner.ErrNotFound):
		fail(w, 404, "not_found")
	case errors.Is(err, provisioner.ErrConflict), errors.Is(err, provisioner.ErrCapacity):
		fail(w, 409, "lease_conflict")
	case errors.Is(err, contracts.ErrTooLarge):
		fail(w, 413, "body_too_large")
	case errors.Is(err, provisioner.ErrInvalid), errors.Is(err, contracts.ErrMalformedJSON), errors.Is(err, contracts.ErrSchema), errors.Is(err, contracts.ErrCommandContext):
		fail(w, 400, "invalid_lease")
	case errors.Is(err, provisioner.ErrCleanup):
		fail(w, 503, "cleanup_unconfirmed")
	default:
		fail(w, 503, "provisioner_unavailable")
	}
}

func fail(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, struct {
		Code string `json:"code"`
	}{code})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
