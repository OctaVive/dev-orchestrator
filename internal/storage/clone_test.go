package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/domain"
)

func cloneIntent(t *testing.T, s *Store) CloneIntent {
	t.Helper()
	seed(t, s)
	submit(t, s)
	c := change()
	if _, e := s.Advance(context.Background(), c); e != nil {
		t.Fatal(e)
	}
	c.ExpectedState = domain.Validating
	c.ExpectedVersion = 2
	c.To = domain.Cloning
	if _, e := s.Advance(context.Background(), c); e != nil {
		t.Fatal(e)
	}
	p := contracts.ClonePolicy{Version: 1, Hosts: []string{"github.com"}, Limits: contracts.DefaultCloneLimits()}
	return CloneIntent{Job: contracts.CloneJob{Version: 1, JobID: actorID, DeploymentID: deploymentID, LeaseID: correlationID, Attempt: 1, Generation: 1, ExpiresAt: time.Now().UTC().Add(5 * time.Minute), TemplateDigest: "sha256:" + strings.Repeat("a", 64), PolicyHash: p.Hash(), RepositoryURL: "https://github.com/example/inventory.git", Branch: "main", ConfigPath: "Dockerfile", BuildContext: ".", Policy: p}, ExpectedVersion: 3, Actor: Actor{Kind: "controller", ID: actorID}, CorrelationID: correlationID}
}
func TestCloneDurableResolutionHandoffAndReplay(t *testing.T) {
	s, path := testStore(t)
	ctx := context.Background()
	i := cloneIntent(t, s)
	if e := s.BeginClone(ctx, i); e != nil {
		t.Fatal(e)
	}
	if e := s.BeginClone(ctx, i); e != nil {
		t.Fatal(e)
	}
	r := contracts.NewCloneResult(i.Job)
	r.SHA = strings.Repeat("b", 40)
	r.Outcome = "resolved"
	if _, e := s.CloneReady(ctx, i.Job); !errors.Is(e, ErrNotFound) {
		t.Fatal("premature handoff", e)
	}
	if e := s.RecordClone(ctx, i, r); e != nil {
		t.Fatal(e)
	}
	if e := s.RecordClone(ctx, i, r); e != nil {
		t.Fatal("replay", e)
	}
	bad := r
	bad.SHA = strings.Repeat("c", 40)
	if e := s.RecordClone(ctx, i, bad); !errors.Is(e, ErrConflict) {
		t.Fatal("conflicting SHA", e)
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	var e error
	s, e = Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.RecordClone(ctx, i, r); e != nil {
		t.Fatal("reopen replay", e)
	}
	r.Outcome = "success"
	r.ContextID = strings.Repeat("d", 64)
	r.Entries = 1
	r.Bytes = 12
	if e = s.RecordClone(ctx, i, r); e != nil {
		t.Fatal(e)
	}
	ready, e := s.CloneReady(ctx, i.Job)
	if e != nil || ready.SHA != r.SHA {
		t.Fatal(ready, e)
	}
	queue, e := s.PendingCloneOutbox(ctx, 100)
	if e != nil || len(queue) != 2 || queue[0].Type != "clone.resolved" {
		t.Fatal(queue, e)
	}
	for _, m := range queue {
		if e = s.MarkCloneDelivered(ctx, m.ID); e != nil {
			t.Fatal(e)
		}
	}
	if queue, e = s.PendingCloneOutbox(ctx, 100); e != nil || len(queue) != 0 {
		t.Fatal(queue, e)
	}
	if n := scalar(t, s, "SELECT count(*) FROM audit_events WHERE action LIKE 'clone.%'"); n != 2 {
		t.Fatal(n)
	}
	if e = s.CheckIntegrity(ctx); e != nil {
		t.Fatal(e)
	}
}
func TestCloneTransactionRollbackAndLateResults(t *testing.T) {
	for _, scenario := range []string{"rollback", "cancelled", "generation", "version", "wrong-source", "context-failure"} {
		t.Run(scenario, func(t *testing.T) {
			s, _ := testStore(t)
			i := cloneIntent(t, s)
			ctx := context.Background()
			if scenario == "wrong-source" {
				i.Job.Branch = "other"
				if e := s.BeginClone(ctx, i); !errors.Is(e, ErrConflict) {
					t.Fatal(e)
				}
				return
			}
			if e := s.BeginClone(ctx, i); e != nil {
				t.Fatal(e)
			}
			r := contracts.NewCloneResult(i.Job)
			r.SHA = strings.Repeat("b", 40)
			r.Outcome = "resolved"
			switch scenario {
			case "rollback":
				execSQL(t, s, `CREATE TRIGGER fail_clone_outbox BEFORE INSERT ON clone_outbox BEGIN SELECT RAISE(ABORT,'injected'); END;`)
			case "cancelled":
				c := change()
				c.ExpectedState = domain.Cloning
				c.ExpectedVersion = 3
				c.To = domain.Cancelled
				c.Reason = ReasonCancelled
				if _, e := s.Advance(ctx, c); e != nil {
					t.Fatal(e)
				}
			case "generation":
				execSQL(t, s, "UPDATE deployments SET generation=2 WHERE id=?", deploymentID)
			case "version":
				execSQL(t, s, "UPDATE deployments SET version=4 WHERE id=?", deploymentID)
			case "context-failure":
				if e := s.RecordClone(ctx, i, r); e != nil {
					t.Fatal(e)
				}
				r.Outcome = "denied"
				if e := s.RecordClone(ctx, i, r); e != nil {
					t.Fatal(e)
				}
				if _, e := s.CloneReady(ctx, i.Job); !errors.Is(e, ErrNotFound) {
					t.Fatal("failed context handed off", e)
				}
				if n := scalar(t, s, "SELECT count(*) FROM deployments WHERE commit_sha=?", r.SHA); n != 1 {
					t.Fatal("lost resolved SHA")
				}
				return
			}
			if e := s.RecordClone(ctx, i, r); e == nil {
				t.Fatal("invalid result accepted")
			}
			if n := scalar(t, s, "SELECT count(*) FROM clone_events"); n != 0 {
				t.Fatal("partial event")
			}
			if n := scalar(t, s, "SELECT count(*) FROM deployments WHERE commit_sha IS NOT NULL"); n != 0 {
				t.Fatal("partial SHA")
			}
			if scenario == "rollback" {
				execSQL(t, s, "DROP TRIGGER fail_clone_outbox")
				if e := s.RecordClone(ctx, i, r); e != nil {
					t.Fatal("retry", e)
				}
			}
		})
	}
}
