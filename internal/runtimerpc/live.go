package runtimerpc

import (
	"context"
	"io"
	"sync"

	"dev-orchestrator/internal/artifacts"
	"dev-orchestrator/internal/runtimeagent"
)

// LiveClient replaces only explicitly provisioned transport identities/trust.
// Existing in-flight operations retain their client and still check revocation.
type LiveClient struct {
	mu     sync.RWMutex
	client *Client
}

func NewLive(client *Client) (*LiveClient, error) {
	if client == nil {
		return nil, runtimeagent.ErrDenied
	}
	return &LiveClient{client: client}, nil
}
func (l *LiveClient) snapshot() *Client { l.mu.RLock(); defer l.mu.RUnlock(); return l.client }
func (l *LiveClient) Replace(client *Client) error {
	if client == nil {
		return runtimeagent.ErrDenied
	}
	l.mu.Lock()
	old := l.client
	l.client = client
	l.mu.Unlock()
	old.Close()
	return nil
}
func (l *LiveClient) Poll(ctx context.Context, w, i string, r *runtimeagent.Result) (*runtimeagent.Command, error) {
	return l.snapshot().Poll(ctx, w, i, r)
}
func (l *LiveClient) Fetch(ctx context.Context, c artifacts.RuntimeClaim, o artifacts.RuntimeObject, out io.Writer) error {
	return l.snapshot().Fetch(ctx, c, o, out)
}
func (l *LiveClient) authorityPOST(ctx context.Context, path string, v any) ([]byte, error) {
	return l.snapshot().authorityPOST(ctx, path, v)
}
func (l *LiveClient) Close() { l.snapshot().Close() }
