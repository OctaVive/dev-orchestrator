package runtimeagent

import (
	"context"
	"testing"
)

func TestRecoveryPublishesUncertainIntentBeforeAnyResource(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	c := command()
	if _, _, err := f.ledger.reserve(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := f.ledger.ReserveCandidate(ctx, c, CandidateUsage{Memory: 64 << 20, CPUMillis: 100, PIDs: 16}, CandidateUsage{Memory: 64 << 20, CPUMillis: 100, PIDs: 16}); err != nil {
		t.Fatal(err)
	}
	f.ledger.Close()
	ledger, err := OpenLedger(ctx, f.path, identity, identity)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	if err = ledger.RecoverPendingResults(ctx); err != nil {
		t.Fatal(err)
	}
	result, ok, err := ledger.PendingResult(ctx)
	if err != nil || !ok || result.CommandID != c.ID || result.Code != "uncertain" {
		t.Fatal("lost intent outcome", result, ok, err)
	}
	stopped, err := ledger.TargetStopped(ctx, c.ID)
	if err != nil || !stopped {
		t.Fatal("recovered create was not fenced", stopped, err)
	}
	var charges int
	if err = ledger.db.QueryRow("SELECT count(*) FROM candidate_capacity WHERE owner=?", c.ID).Scan(&charges); err != nil || charges != 1 {
		t.Fatal("uncertain reservation released", charges, err)
	}
	if err = ledger.RecoverPendingResults(ctx); err != nil {
		t.Fatal("recovery not idempotent", err)
	}
	if _, _, err = ledger.reserve(ctx, c); err == nil {
		t.Fatal("recovered intent resumed")
	}
}
