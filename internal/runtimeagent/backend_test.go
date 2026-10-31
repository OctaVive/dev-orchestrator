package runtimeagent

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"dev-orchestrator/internal/contracts"
)

func backendFixture(app string, n int) BackendBinding {
	return BackendBinding{DaemonPID: 100 + n, DaemonStartTicks: 123, BootID: identity, AppID: app, Socket: fmt.Sprintf("/run/tap/app%d/docker.sock", n), DataRoot: fmt.Sprintf("/var/lib/tap/app%d", n), DaemonID: fmt.Sprintf("daemon-%d", n), UserNamespace: fmt.Sprintf("user:[%d]", 100+n), InitialUserNamespace: "user:[1]", UIDMapHash: contracts.Digest([]byte("uidmap")), GIDMapHash: contracts.Digest([]byte("gidmap")), DaemonMemory: 10, WorkloadMemory: 90, ImageDisk: 60, WorkloadDisk: 40}
}
func backendLedger(t *testing.T) (*Ledger, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ledger.sqlite")
	l, err := OpenLedger(context.Background(), path, identity, identity)
	if err != nil {
		t.Fatal(err)
	}
	return l, path
}
func TestBackendReservationDurability(t *testing.T) {
	ctx := context.Background()
	l, path := backendLedger(t)
	cap := BackendCapacity{Apps: 2, Memory: 200, Disk: 200}
	if l.ConfigureBackends(ctx, cap) != nil {
		t.Fatal("capacity")
	}
	a, b := backendFixture(identity, 1), backendFixture(other, 2)
	for _, v := range []BackendBinding{a, a, b} {
		if err := reserveAndBind(l, ctx, v); err != nil {
			t.Fatal(err)
		}
	}
	if l.Close() != nil {
		t.Fatal("close")
	}
	var err error
	l, err = OpenLedger(ctx, path, identity, identity)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if l.ConfigureBackends(ctx, cap) != nil {
		t.Fatal("reopen capacity")
	}
	if l.ConfigureBackends(ctx, BackendCapacity{Apps: 3, Memory: 300, Disk: 300}) != ErrConflict {
		t.Fatal("capacity reset")
	}
	got, err := l.Backend(ctx, identity)
	if err != nil || got != a {
		t.Fatal("lost binding", err)
	}
	a.DaemonID = "replacement"
	if reserveAndBind(l, ctx, a) != ErrConflict {
		t.Fatal("daemon replacement")
	}
	c := backendFixture("33333333-3333-4333-8333-333333333333", 3)
	if reserveAndBind(l, ctx, c) != ErrUnsupported {
		t.Fatal("overcommitted")
	}
}
func TestBackendOwnershipAndCapacityDenials(t *testing.T) {
	for _, name := range []string{"socket", "root", "nested-root", "socket-in-root", "daemon", "namespace", "initial", "uidmap", "memory", "disk", "overhead"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			l, _ := backendLedger(t)
			defer l.Close()
			if l.ConfigureBackends(ctx, BackendCapacity{Apps: 2, Memory: 200, Disk: 200}) != nil {
				t.Fatal("configure")
			}
			a, b := backendFixture(identity, 1), backendFixture(other, 2)
			if reserveAndBind(l, ctx, a) != nil {
				t.Fatal("bind")
			}
			switch name {
			case "socket":
				b.Socket = a.Socket
			case "root":
				b.DataRoot = a.DataRoot
			case "nested-root":
				b.DataRoot = a.DataRoot + "/nested"
			case "socket-in-root":
				b.Socket = a.DataRoot + "/docker.sock"
			case "daemon":
				b.DaemonID = a.DaemonID
			case "namespace":
				b.UserNamespace = a.UserNamespace
			case "initial":
				b.UserNamespace = b.InitialUserNamespace
			case "uidmap":
				b.UIDMapHash = "invalid"
			case "memory":
				b.WorkloadMemory = 91
			case "disk":
				b.ImageDisk = 61
			case "overhead":
				b.DaemonMemory = 0
			}
			if reserveAndBind(l, ctx, b) == nil {
				t.Fatal("unsafe assignment admitted")
			}
			if _, err := l.Backend(ctx, other); err == nil {
				t.Fatal("failed reservation persisted")
			}
		})
	}
}
func TestBackendConcurrentCapacity(t *testing.T) {
	ctx := context.Background()
	l, _ := backendLedger(t)
	defer l.Close()
	if l.ConfigureBackends(ctx, BackendCapacity{Apps: 2, Memory: 100, Disk: 100}) != nil {
		t.Fatal("configure")
	}
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for n, app := range []string{identity, other} {
		wg.Add(1)
		go func(n int, app string) { defer wg.Done(); results <- reserveAndBind(l, ctx, backendFixture(app, n+1)) }(n, app)
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal("reservation race", success)
	}
}
func TestBackendV1Migration(t *testing.T) {
	ctx := context.Background()
	l, path := backendLedger(t)
	// Reconstruct the previous schema while retaining a command/replay fence.
	c := command()
	if _, _, err := l.reserve(ctx, c); err != nil {
		t.Fatal(err)
	}
	if _, err := l.db.ExecContext(ctx, "DROP TABLE restart_budgets; DROP TABLE candidate_capacity; DROP TABLE command_specs; DROP TABLE runtime_outbox; DROP TABLE runtime_profile; DROP TABLE backends; DROP TABLE backend_reservations; DROP TABLE backend_capacity; ALTER TABLE identity RENAME TO old_identity; CREATE TABLE identity (singleton INTEGER PRIMARY KEY,worker TEXT NOT NULL,incarnation TEXT NOT NULL); INSERT INTO identity SELECT singleton,worker,incarnation FROM old_identity; DROP TABLE old_identity; PRAGMA user_version=1;"); err != nil {
		t.Fatal(err)
	}
	l.Close()
	l, err := OpenLedger(ctx, path, identity, identity)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, _, err = l.reserve(ctx, c); err != ErrUncertain {
		t.Fatal("lost pending command", err)
	}
	if l.ConfigureBackends(ctx, BackendCapacity{Apps: 1, Memory: 100, Disk: 100}) != nil || reserveAndBind(l, ctx, backendFixture(identity, 1)) != nil {
		t.Fatal("migration")
	}
}
func TestInventoryAppBinding(t *testing.T) {
	i := inventory()
	now := time.Now()
	if i.ReadyFor(now, identity, identity, identity) != nil {
		t.Fatal("valid inventory")
	}
	if i.ReadyFor(now, identity, identity, other) == nil {
		t.Fatal("cross-app inventory")
	}
	i.BackendHash = ""
	if i.Ready(now, identity, identity) == nil {
		t.Fatal("unbound inventory")
	}
	i = inventory()
	i.Version = 1
	if i.Ready(now, identity, identity) == nil {
		t.Fatal("legacy inventory")
	}
}

func reserveAndBind(l *Ledger, ctx context.Context, b BackendBinding) error {
	if !b.Valid() {
		return ErrDenied
	}
	if err := l.ReserveBackend(ctx, b.Reservation()); err != nil {
		return err
	}
	return l.BindBackend(ctx, b)
}
func TestUnboundReservationSurvivesCrash(t *testing.T) {
	ctx := context.Background()
	l, path := backendLedger(t)
	if l.ConfigureBackends(ctx, BackendCapacity{Apps: 1, Memory: 100, Disk: 100}) != nil {
		t.Fatal("configure")
	}
	b := backendFixture(identity, 1)
	if l.BindBackend(ctx, b) != ErrConflict {
		t.Fatal("binding without reservation")
	}
	if l.ReserveBackend(ctx, b.Reservation()) != nil {
		t.Fatal("reserve before daemon start")
	}
	if _, err := l.Backend(ctx, identity); err == nil {
		t.Fatal("unbound reservation routed")
	}
	l.Close()
	l, err := OpenLedger(ctx, path, identity, identity)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if l.ReserveBackend(ctx, backendFixture(other, 2).Reservation()) != ErrUnsupported {
		t.Fatal("lost pre-provision charge")
	}
	if l.BindBackend(ctx, b) != nil {
		t.Fatal("bind after restart")
	}
}
