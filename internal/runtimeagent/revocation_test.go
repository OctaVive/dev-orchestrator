package runtimeagent

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

type atomicLease struct{ revoked atomic.Bool }

func (l *atomicLease) Valid(context.Context, string, string) error {
	if l.revoked.Load() {
		return ErrDenied
	}
	return nil
}

type waitingCreate struct {
	fakeEngine
	started chan struct{}
}

func (e *waitingCreate) Create(ctx context.Context, _ Command, _ func() error) error {
	close(e.started)
	<-ctx.Done()
	return ctx.Err()
}
func TestRevocationCancelsEngineWithoutStageCallbacks(t *testing.T) {
	f := setup(t)
	lease := &atomicLease{}
	engine := &waitingCreate{started: make(chan struct{})}
	f.agent.config.Lease = lease
	f.agent.config.Engine = engine
	done := make(chan error, 1)
	go func() { _, err := f.execute(command()); done <- err }()
	select {
	case <-engine.started:
	case <-time.After(2 * time.Second):
		t.Fatal("create never started")
	}
	lease.revoked.Store(true)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("revoked blocking create succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("revocation did not cancel blocking engine")
	}
}
