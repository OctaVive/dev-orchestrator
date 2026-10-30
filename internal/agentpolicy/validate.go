// Package agentpolicy is the mandatory policy gate for future M09 execution.
// It does not verify signatures or mutate an engine.
package agentpolicy

import (
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/policy"
	"encoding/base64"
	"io"
	"time"
)

type Context struct {
	WorkerID       string
	LastGeneration int64
	Now            time.Time
	Resolver       policy.Resolver
}

var validator, validatorError = contracts.NewValidator()

func Decode(r io.Reader, c Context) (contracts.AgentCommandV2, error) {
	if validatorError != nil {
		return contracts.AgentCommandV2{}, policy.ErrDenied
	}
	a, e := validator.DecodeAgentCommandV2Shape(r)
	if e != nil {
		return a, e
	}
	expiry, e := time.Parse(time.RFC3339Nano, a.ExpiresAt)
	sig, se := base64.StdEncoding.Strict().DecodeString(a.Signature)
	if e != nil || se != nil || len(sig) != 64 || a.SchemaVersion != 2 || !contracts.ValidJobID(a.CommandID) || !contracts.ValidJobID(c.WorkerID) || a.WorkerID != c.WorkerID || c.Now.IsZero() || c.LastGeneration < 0 || a.Generation <= c.LastGeneration || a.Generation > 9007199254740991 || !expiry.After(c.Now) || expiry.After(c.Now.Add(5*time.Minute)) || !contracts.ValidDigest("sha256:"+a.Nonce) || a.KeyID == "" || len(a.KeyID) > 63 || a.SpecHash != policy.SpecHash(a.Spec) {
		return contracts.AgentCommandV2{}, policy.ErrDenied
	}
	if e = policy.ValidateRuntime(a.Spec, c.Resolver); e != nil {
		return contracts.AgentCommandV2{}, e
	}
	return a, nil
}
