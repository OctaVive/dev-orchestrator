package runtimeagent

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"time"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/policy"
)

// Inventory fields are measured by a trusted adapter; no command supplies them.
// A signed inventory is a worker assertion, not hardware remote attestation.
type Inventory struct {
	AppID        string          `json:"app_id"`
	BackendHash  string          `json:"backend_hash"`
	Version      int             `json:"version"`
	WorkerID     string          `json:"worker_id"`
	Incarnation  string          `json:"incarnation"`
	Challenge    string          `json:"challenge"`
	MeasuredAt   time.Time       `json:"measured_at"`
	ExpiresAt    time.Time       `json:"expires_at"`
	TemplateHash string          `json:"template_hash"`
	Kernel       string          `json:"kernel"`
	Engine       string          `json:"engine"`
	API          string          `json:"api"`
	DaemonID     string          `json:"daemon_id"`
	PolicyHash   string          `json:"policy_hash"`
	Controls     policy.Controls `json:"controls"`
	Signature    string          `json:"signature,omitempty"`
}

func (i Inventory) Ready(now time.Time, worker, incarnation string) error {
	if !contracts.ValidJobID(i.AppID) || !contracts.ValidDigest(i.BackendHash) || now.IsZero() || i.Version != 2 || i.WorkerID != worker || i.Incarnation != incarnation || !validIdentity(worker, incarnation) || !contracts.ValidDigest("sha256:"+i.Challenge) || !contracts.ValidDigest(i.TemplateHash) || i.PolicyHash != policy.Hash() || i.MeasuredAt.After(now) || now.Sub(i.MeasuredAt) > time.Minute || !i.ExpiresAt.After(now) || i.ExpiresAt.After(i.MeasuredAt.Add(time.Minute)) || i.ExpiresAt.Before(i.MeasuredAt) || i.Controls != policy.RequiredControls() {
		return ErrUnsupported
	}
	for _, s := range []string{i.Kernel, i.Engine, i.API, i.DaemonID} {
		if len(s) == 0 || len(s) > 128 || !policy.Text(s, 128) {
			return ErrUnsupported
		}
	}
	return nil
}
func (i Inventory) signingBytes() ([]byte, error) {
	i.Signature = ""
	b, e := json.Marshal(i)
	if e != nil {
		return nil, ErrDenied
	}
	return append([]byte("tap/runtime-inventory/v2\x00"), b...), nil
}
func (i *Inventory) Sign(key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return ErrDenied
	}
	b, e := i.signingBytes()
	if e != nil {
		return e
	}
	i.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, b))
	return nil
}
func (i Inventory) Verify(now time.Time, worker, incarnation, challenge string, key ed25519.PublicKey) error {
	if i.Ready(now, worker, incarnation) != nil || i.Challenge != challenge || len(key) != ed25519.PublicKeySize {
		return ErrDenied
	}
	s, e := base64.StdEncoding.Strict().DecodeString(i.Signature)
	b, _ := i.signingBytes()
	if e != nil || !ed25519.Verify(key, b, s) {
		return ErrDenied
	}
	return nil
}

// ReadyFor binds capability use to one durable app backend. Worker-wide reports
// cannot authorize execution in a different app's daemon.
func (i Inventory) ReadyFor(now time.Time, worker, incarnation, app string) error {
	if i.Ready(now, worker, incarnation) != nil || !contracts.ValidJobID(app) || i.AppID != app || !contracts.ValidDigest(i.BackendHash) {
		return ErrUnsupported
	}
	return nil
}

// VerifyFor is the controller entry for app-scoped reports. The backend hash
// must come from trusted enrollment, never from the report being verified.
func (i Inventory) VerifyFor(now time.Time, worker, incarnation, app, backendHash, challenge string, key ed25519.PublicKey) error {
	if i.ReadyFor(now, worker, incarnation, app) != nil || i.BackendHash != backendHash {
		return ErrDenied
	}
	return i.Verify(now, worker, incarnation, challenge, key)
}
