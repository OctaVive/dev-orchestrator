package runtimeagent

import (
	"context"
	"errors"
	"testing"
)

type testReconciler struct {
	calls  int
	denied bool
}

func (r *testReconciler) Reconcile(context.Context) error {
	r.calls++
	if r.denied {
		return ErrUncertain
	}
	return nil
}

type testPoller struct {
	poll func(*Result) (*Command, error)
}

func (p testPoller) Poll(_ context.Context, _, _ string, r *Result) (*Command, error) {
	return p.poll(r)
}
func TestDurableResultsAndLostPollingResponse(t *testing.T) {
	f := setup(t)
	c := command()
	if c.Sign(f.key) != nil {
		t.Fatal("sign")
	}
	result, err := f.agent.Execute(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	pending, ok, err := f.ledger.PendingResult(context.Background())
	if err != nil || !ok || pending.CommandID != result.CommandID {
		t.Fatal("result not durable", err)
	}
	if f.ledger.Close() != nil {
		t.Fatal("close")
	}
	l, err := OpenLedger(context.Background(), f.path, identity, identity)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	config := f.agent.config
	config.Ledger = l
	agent, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	poller := testPoller{func(r *Result) (*Command, error) {
		calls++
		if r == nil || r.CommandID != result.CommandID {
			t.Fatal("result dropped before acknowledgment")
		}
		switch calls {
		case 1:
			return nil, ErrDenied
		case 2:
			return &c, nil
		default:
			cancel()
			return nil, ErrDenied
		}
	}}
	reconcile := &testReconciler{}
	if err = agent.Serve(ctx, poller, reconcile); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if f.engine.creates != 1 || calls != 3 || reconcile.calls != 3 {
		t.Fatal("duplicate effect or skipped reconciliation", f.engine.creates, calls, reconcile.calls)
	}
	pending, ok, err = l.PendingResult(context.Background())
	if err != nil || !ok || pending.CommandID != result.CommandID {
		t.Fatal("lost final response discarded durable result")
	}
	if l.AcknowledgeResult(context.Background(), pending) != nil {
		t.Fatal("ack")
	}
	if _, ok, err = l.PendingResult(context.Background()); err != nil || ok {
		t.Fatal("acknowledged result retained")
	}
}
func TestServiceReconciliationIncidentBlocksNewExecution(t *testing.T) {
	f := setup(t)
	c := command()
	if c.Sign(f.key) != nil {
		t.Fatal("sign")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	poller := testPoller{func(*Result) (*Command, error) {
		calls++
		if calls == 2 {
			cancel()
			return nil, ErrDenied
		}
		return &c, nil
	}}
	if err := f.agent.Serve(ctx, poller, &testReconciler{denied: true}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if f.engine.creates != 0 {
		t.Fatal("incident permitted execution")
	}
}

func TestReconciliationIncidentAllowsExactAuthorizedCleanup(t *testing.T) {
	f := setup(t)
	original := command()
	created, err := f.execute(original)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.ledger.AcknowledgeResult(context.Background(), created); err != nil {
		t.Fatal(err)
	}
	cleanup := follow(original, "remove", 99)
	if cleanup.Sign(f.key) != nil {
		t.Fatal("sign cleanup")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	poller := testPoller{func(r *Result) (*Command, error) {
		calls++
		if calls == 1 {
			return &cleanup, nil
		}
		if r == nil || r.CommandID != cleanup.ID {
			t.Fatal("cleanup result missing during incident")
		}
		cancel()
		return nil, ErrDenied
	}}
	if err = f.agent.Serve(ctx, poller, &testReconciler{denied: true}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if f.engine.removes != 1 {
		t.Fatal("incident blocked owned cleanup", f.engine.removes)
	}
}
