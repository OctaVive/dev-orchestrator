package runtimerpc

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"dev-orchestrator/internal/artifacts"
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/policy"
	"dev-orchestrator/internal/runtimeagent"
	"dev-orchestrator/internal/runtimeauthority"
)

// Authority consults current controller records on every lease/approval check.
// Its resolver view is populated only by a verified, exact-command mTLS grant;
// no guest/browser map or envelope approval flag is an authority source.
type Authority struct {
	Client interface {
		authorityPOST(context.Context, string, any) ([]byte, error)
	}
	refresh sync.Mutex
	mu      sync.Mutex
	grant   runtimeauthority.Grant
}

func (c *Client) authorityPOST(ctx context.Context, path string, value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > contracts.MaxPlanBytes {
		return nil, runtimeagent.ErrDenied
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.origin+path, bytes.NewReader(raw))
	if err != nil {
		return nil, runtimeagent.ErrDenied
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return nil, runtimeagent.ErrDenied
	}
	defer res.Body.Close()
	if !c.validPeer(res.TLS) || res.StatusCode != http.StatusOK {
		return nil, runtimeagent.ErrDenied
	}
	raw, err = io.ReadAll(io.LimitReader(res.Body, contracts.MaxPlanBytes+1))
	if err != nil || len(raw) > contracts.MaxPlanBytes || !c.validPeer(res.TLS) {
		return nil, runtimeagent.ErrDenied
	}
	return raw, nil
}
func (a *Authority) Valid(ctx context.Context, worker, incarnation string) error {
	if a.Client == nil {
		return runtimeagent.ErrDenied
	}
	raw, err := a.Client.authorityPOST(ctx, "/runtime/v1/lease", runtimeauthority.LeaseRequest{WorkerID: worker, Incarnation: incarnation})
	if err != nil {
		return err
	}
	lease, err := contracts.DecodeConfiguration[runtimeauthority.LeaseResponse](bytes.NewReader(raw))
	now := time.Now()
	if err != nil || lease.WorkerID != worker || lease.Incarnation != incarnation || !lease.ExpiresAt.After(now) || lease.ExpiresAt.After(now.Add(time.Minute)) {
		return runtimeagent.ErrDenied
	}
	return nil
}
func (a *Authority) Current(ctx context.Context, c runtimeagent.Command) (outcome error) {
	a.refresh.Lock()
	defer a.refresh.Unlock()
	// Keep a still-fresh verified view while another current check is in flight.
	// A known failed refresh clears it before returning. This avoids concurrent
	// authorization monitors exposing a transient empty resolver to execution.
	defer func() {
		if outcome != nil {
			a.mu.Lock()
			a.grant = runtimeauthority.Grant{}
			a.mu.Unlock()
		}
	}()
	if a.Client == nil || c.Spec == nil {
		return runtimeagent.ErrDenied
	}
	raw, err := a.Client.authorityPOST(ctx, "/runtime/v1/authorize", c)
	if err != nil {
		os.Stderr.WriteString("runtime_authority_request_denied\n")
		return err
	}
	g, err := contracts.DecodeConfiguration[runtimeauthority.Grant](bytes.NewReader(raw))
	if err != nil || !g.Matches(time.Now(), c) {
		os.Stderr.WriteString("runtime_authority_grant_denied\n")
		return runtimeagent.ErrDenied
	}
	a.mu.Lock()
	a.grant = g
	a.mu.Unlock()
	return nil
}
func (a *Authority) Image(image string) (policy.Admission, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.grant.ExpiresAt.After(time.Now()) {
		return policy.Admission{}, runtimeagent.ErrDenied
	}
	for _, i := range a.grant.Images {
		if i.Admission.Image == image {
			raw, _ := json.Marshal(i.Admission)
			var copied policy.Admission
			if json.Unmarshal(raw, &copied) != nil {
				return policy.Admission{}, runtimeagent.ErrDenied
			}
			return copied, nil
		}
	}
	return policy.Admission{}, runtimeagent.ErrDenied
}
func (*Authority) Volume(string, string) (string, error) { return "", runtimeagent.ErrUnsupported }
func (*Authority) Secret(string, string, string) error   { return runtimeagent.ErrUnsupported }
func (a *Authority) RuntimeArtifact(ctx context.Context, c runtimeagent.Command, s contracts.RuntimeServiceV2) (artifacts.RuntimeObject, error) {
	if a.Current(ctx, c) != nil {
		return artifacts.RuntimeObject{}, runtimeagent.ErrDenied
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.grant.Matches(time.Now(), c) {
		return artifacts.RuntimeObject{}, runtimeagent.ErrDenied
	}
	for _, i := range a.grant.Images {
		if i.Admission.Image == s.Image && i.Admission.ID == s.AdmissionID {
			return i.Object, nil
		}
	}
	return artifacts.RuntimeObject{}, runtimeagent.ErrDenied
}

var _ runtimeagent.Approval = (*Authority)(nil)
var _ runtimeagent.Lease = (*Authority)(nil)
var _ policy.Resolver = (*Authority)(nil)

func (a *Authority) CurrentTarget(ctx context.Context, c runtimeagent.Command) (outcome error) {
	a.refresh.Lock()
	defer a.refresh.Unlock()
	// Keep a still-fresh verified view while another current check is in flight.
	// A known failed refresh clears it before returning. This avoids concurrent
	// authorization monitors exposing a transient empty resolver to execution.
	defer func() {
		if outcome != nil {
			a.mu.Lock()
			a.grant = runtimeauthority.Grant{}
			a.mu.Unlock()
		}
	}()
	if a.Client == nil || c.Spec == nil || c.Operation != "create" {
		return runtimeagent.ErrDenied
	}
	raw, err := a.Client.authorityPOST(ctx, "/runtime/v1/target", runtimeauthority.Target(c))
	if err != nil {
		return err
	}
	g, err := contracts.DecodeConfiguration[runtimeauthority.Grant](bytes.NewReader(raw))
	if err != nil || !g.MatchesTarget(time.Now(), c) {
		return runtimeagent.ErrDenied
	}
	a.mu.Lock()
	a.grant = g
	a.mu.Unlock()
	return nil
}
