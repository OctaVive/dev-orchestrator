package runtimeagent

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestCandidateCapacityConcurrentAndDurable(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	c := command()
	if _, _, err := f.ledger.reserve(ctx, c); err != nil {
		t.Fatal(err)
	}
	second := c
	second.ID = other
	second.Nonce = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	second.Operation = "prepare"
	if _, _, err := f.ledger.reserve(ctx, second); err != nil {
		t.Fatal(err)
	}
	want := CandidateUsage{Memory: 64 << 20, CPUMillis: 100, PIDs: 16}
	max := want
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, candidate := range []Command{c, second} {
		wg.Add(1)
		go func(q Command) { defer wg.Done(); results <- f.ledger.ReserveCandidate(ctx, q, want, max) }(candidate)
	}
	wg.Wait()
	close(results)
	allowed := 0
	for err := range results {
		if err == nil {
			allowed++
		} else if !errors.Is(err, ErrUnsupported) {
			t.Fatal(err)
		}
	}
	if allowed != 1 {
		t.Fatalf("capacity admitted %d candidates", allowed)
	}
	f.ledger.Close()
	l, err := OpenLedger(ctx, f.path, identity, identity)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var count int
	if err = l.db.QueryRow("SELECT count(*) FROM candidate_capacity").Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	var owner string
	if err = l.db.QueryRow("SELECT owner FROM candidate_capacity").Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if err = l.SaveResource(ctx, owner, Resource{ID: "owned", Kind: "network", Expected: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if err = l.ReleaseCandidate(ctx, owner); !errors.Is(err, ErrUncertain) {
		t.Fatalf("released live resources: %v", err)
	}
}

func TestFiniteRestartsSurviveReopenAndStopFence(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	c := command()
	c.Spec.Services[0].RestartAttempts = 2
	if _, _, err := f.ledger.reserve(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := f.ledger.RegisterRestarts(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := f.ledger.finish(ctx, c.ID, Result{CommandID: c.ID, Code: "ok"}, false); err != nil {
		t.Fatal(err)
	}
	if ok, err := f.ledger.ConsumeRestart(ctx, c, "web"); err != nil || !ok {
		t.Fatal(ok, err)
	}
	f.ledger.Close()
	l, err := OpenLedger(ctx, f.path, identity, identity)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err = l.RegisterRestarts(ctx, c); err != nil {
		t.Fatal(err)
	}
	if ok, err := l.ConsumeRestart(ctx, c, "web"); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if ok, err := l.ConsumeRestart(ctx, c, "web"); err != nil || ok {
		t.Fatal("budget replenished", ok, err)
	}
	if err = l.FenceStop(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if ok, err := l.ConsumeRestart(ctx, c, "web"); err == nil || ok {
		t.Fatal("stopped target restarted", ok, err)
	}
}
