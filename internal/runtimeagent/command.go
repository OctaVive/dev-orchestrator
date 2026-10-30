// Package runtimeagent authorizes typed runtime commands. Legacy agent envelopes
// are never execution authorizations. All diagnostics are closed, value-free codes.
package runtimeagent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/policy"
)

var (
	ErrDenied      = errors.New("runtime_command_denied")
	ErrConflict    = errors.New("runtime_command_conflict")
	ErrLedger      = errors.New("runtime_ledger_unavailable")
	ErrUncertain   = errors.New("runtime_cleanup_uncertain")
	ErrUnsupported = errors.New("runtime_profile_unsupported")
)

const MaxGeneration int64 = 9007199254740991
const MaxLogs = 16 << 10

// Command is execution protocol v3; RuntimeSpecV2 retains its M08 meaning.
// Target is the original create command ID, never an arbitrary Docker object ID.
type Command struct {
	Version      int                      `json:"version"`
	Operation    string                   `json:"operation"`
	ID           string                   `json:"command_id"`
	WorkerID     string                   `json:"worker_id"`
	Incarnation  string                   `json:"incarnation"`
	AppID        string                   `json:"app_id"`
	DeploymentID string                   `json:"deployment_id"`
	Generation   int64                    `json:"generation"`
	Nonce        string                   `json:"nonce"`
	KeyID        string                   `json:"key_id"`
	ExpiresAt    string                   `json:"expires_at"`
	PolicyHash   string                   `json:"policy_hash"`
	SpecHash     string                   `json:"spec_hash"`
	Target       string                   `json:"target,omitempty"`
	Spec         *contracts.RuntimeSpecV2 `json:"spec,omitempty"`
	LogLimit     int                      `json:"log_limit,omitempty"`
	Signature    string                   `json:"signature,omitempty"`
}

func (c Command) SigningBytes() ([]byte, error) {
	c.Signature = ""
	b, err := json.Marshal(c)
	if err != nil || len(b) > contracts.MaxPlanBytes {
		return nil, ErrDenied
	}
	return append([]byte("tap/runtime-command/v3\x00"), b...), nil
}
func (c *Command) Sign(key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return ErrDenied
	}
	b, e := c.SigningBytes()
	if e != nil {
		return e
	}
	c.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, b))
	return nil
}
func (c Command) Hash() string {
	b, _ := c.SigningBytes()
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func Decode(r io.Reader) (Command, error) {
	c, e := contracts.DecodeConfiguration[Command](r)
	if e != nil {
		return Command{}, ErrDenied
	}
	return c, nil
}
func (c Command) Validate(now time.Time, worker, incarnation string, keys map[string]ed25519.PublicKey) error {
	if c.Version != 3 || !contracts.ValidJobID(c.ID) || !contracts.ValidJobID(c.AppID) || !contracts.ValidJobID(c.DeploymentID) || !contracts.ValidJobID(c.WorkerID) || c.WorkerID != worker || !contracts.ValidJobID(c.Incarnation) || c.Incarnation != incarnation || c.Generation < 1 || c.Generation > MaxGeneration || !contracts.ValidDigest("sha256:"+c.Nonce) || !policy.ValidName(c.KeyID) || c.PolicyHash != policy.Hash() || !contracts.ValidDigest(c.SpecHash) || now.IsZero() {
		return ErrDenied
	}
	expiry, e := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	// UTC canonical timestamps prevent multiple spellings in signed fixtures.
	if e != nil || expiry.UTC().Format(time.RFC3339Nano) != c.ExpiresAt || !expiry.After(now) || expiry.After(now.Add(5*time.Minute)) {
		return ErrDenied
	}
	switch c.Operation {
	case "probe":
		if c.Spec != nil || c.Target != "" || c.LogLimit != 0 {
			return ErrDenied
		}
	case "prepare", "create":
		if c.Spec == nil || c.Target != "" || c.LogLimit != 0 || c.Spec.AppID != c.AppID || c.Spec.DeploymentID != c.DeploymentID || c.SpecHash != policy.SpecHash(*c.Spec) {
			return ErrDenied
		}
	case "inspect", "stop", "remove", "logs":
		if c.Spec != nil || !contracts.ValidJobID(c.Target) {
			return ErrDenied
		}
		if c.Operation == "logs" {
			if c.LogLimit < 1 || c.LogLimit > MaxLogs {
				return ErrDenied
			}
		} else if c.LogLimit != 0 {
			return ErrDenied
		}
	default:
		return ErrDenied
	}
	key := keys[c.KeyID]
	sig, e := base64.StdEncoding.Strict().DecodeString(c.Signature)
	if e != nil || len(key) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return ErrDenied
	}
	b, e := c.SigningBytes()
	if e != nil || !ed25519.Verify(key, b, sig) {
		return ErrDenied
	}
	encoded, _ := json.Marshal(c)
	if len(encoded) > contracts.MaxPlanBytes {
		return ErrDenied
	}
	return nil
}

// DecodeBytes is useful for callers which already bounded the transport body.
func DecodeBytes(b []byte) (Command, error) { return Decode(bytes.NewReader(b)) }
