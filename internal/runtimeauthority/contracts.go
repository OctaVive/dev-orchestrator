// Package runtimeauthority defines the narrow trusted current-state boundary
// between runtime agents and a separately authenticated controller. Issuance is
// an explicit controller/operator action, never an HTTP approval operation.
package runtimeauthority

import (
	"context"
	"time"

	"dev-orchestrator/internal/artifacts"
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/policy"
	"dev-orchestrator/internal/runtimeagent"
)

type Image struct {
	Admission policy.Admission        `json:"admission"`
	Object    artifacts.RuntimeObject `json:"object"`
}
type Grant struct {
	OwnerID      string    `json:"owner_id,omitempty"`
	WorkerID     string    `json:"worker_id"`
	Incarnation  string    `json:"incarnation"`
	AppID        string    `json:"app_id"`
	DeploymentID string    `json:"deployment_id"`
	Generation   int64     `json:"generation"`
	SpecHash     string    `json:"spec_hash"`
	PolicyHash   string    `json:"policy_hash"`
	SourceSHA    string    `json:"source_sha"`
	ContextID    string    `json:"context_id"`
	ExpiresAt    time.Time `json:"expires_at"`
	Images       []Image   `json:"images"`
}

func (g Grant) Matches(now time.Time, c runtimeagent.Command) bool {
	if g.OwnerID != "" || c.Spec == nil || !g.ExpiresAt.After(now) || g.ExpiresAt.After(now.Add(5*time.Second)) || g.WorkerID != c.WorkerID || g.Incarnation != c.Incarnation || g.AppID != c.AppID || g.DeploymentID != c.DeploymentID || g.Generation != c.Generation || g.SpecHash != c.SpecHash || g.PolicyHash != c.PolicyHash || g.PolicyHash != policy.Hash() || g.SourceSHA != c.Spec.SHA || g.ContextID != c.Spec.ContextID || len(g.Images) < 1 || len(g.Images) > 5 {
		return false
	}
	seen := map[string]bool{}
	for _, s := range c.Spec.Services {
		found := false
		for _, i := range g.Images {
			a := i.Admission
			if a.Image == s.Image {
				if a.ID != s.AdmissionID || a.PolicyHash != g.PolicyHash || !contracts.ValidDigest(i.Object.Digest) || i.Object.Bytes < 1 || i.Object.Bytes > 1<<30 {
					return false
				}
				found = true
				seen[s.Image] = true
			}
		}
		if !found {
			return false
		}
	}
	return len(seen) == len(g.Images)
}

type LeaseRequest struct {
	WorkerID    string `json:"worker_id"`
	Incarnation string `json:"incarnation"`
}
type LeaseResponse struct {
	WorkerID    string    `json:"worker_id"`
	Incarnation string    `json:"incarnation"`
	ExpiresAt   time.Time `json:"expires_at"`
}
type PollRequest struct {
	WorkerID    string               `json:"worker_id"`
	Incarnation string               `json:"incarnation"`
	Result      *runtimeagent.Result `json:"result,omitempty"`
}

// State is backed by management's durable records. Implementations must recheck
// worker/certificate lease, approval, app generation, scan/admission revocation
// and exact bindings in a transaction, rather than trusting caller grant maps.
type State interface {
	RuntimeLease(context.Context, artifacts.RuntimePeer, string, string) (time.Time, error)
	RuntimeGrant(context.Context, artifacts.RuntimePeer, runtimeagent.Command) (Grant, error)
	RuntimeTargetGrant(context.Context, artifacts.RuntimePeer, TargetRequest) (Grant, error)
	RuntimePoll(context.Context, artifacts.RuntimePeer, PollRequest) (*runtimeagent.Command, error)
	artifacts.RuntimeAuthorizer
}

type TargetRequest struct {
	WorkerID     string `json:"worker_id"`
	Incarnation  string `json:"incarnation"`
	AppID        string `json:"app_id"`
	DeploymentID string `json:"deployment_id"`
	Generation   int64  `json:"generation"`
	SpecHash     string `json:"spec_hash"`
	OwnerID      string `json:"owner_id"`
}

func Target(c runtimeagent.Command) TargetRequest {
	return TargetRequest{c.WorkerID, c.Incarnation, c.AppID, c.DeploymentID, c.Generation, c.SpecHash, c.ID}
}
func (g Grant) MatchesTarget(now time.Time, c runtimeagent.Command) bool {
	if g.OwnerID != c.ID {
		return false
	}
	g.OwnerID = ""
	return g.Matches(now, c)
}
