package provisioner

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLedgerNamespaceAndVersionFailClosed(t *testing.T) {
	for _, damage := range []string{"checksum", "future", "application"} {
		t.Run(damage, func(t *testing.T) {
			m, _, _, path := fixture(t)
			query := "UPDATE ledger_meta SET checksum='" + strings.Repeat("0", 64) + "'"
			if damage == "future" {
				query = "PRAGMA user_version=2"
			}
			if damage == "application" {
				query = "PRAGMA application_id=7"
			}
			if _, err := m.ledger.db.Exec(query); err != nil {
				t.Fatal(err)
			}
			m.ledger.Close()
			opened, err := OpenLedger(context.Background(), path)
			if opened != nil {
				opened.Close()
			}
			if !errors.Is(err, ErrVersion) {
				t.Fatal("incompatible ledger opened", err)
			}
		})
	}
	path := filepath.Join(t.TempDir(), "management.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE users(id TEXT); PRAGMA user_version=1"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	// sql.Open-created file may have public Unix mode; restrict it before testing namespace.
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if l, err := OpenLedger(context.Background(), path); !errors.Is(err, ErrVersion) {
		if l != nil {
			l.Close()
		}
		t.Fatal("management file accepted as host ledger", err)
	}
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_schema WHERE name='ledger_meta'").Scan(&n); err != nil || n != 0 {
		t.Fatal("foreign DB modified", err)
	}
}

func TestLedgerAtomicEventsAndImmutableIdentity(t *testing.T) {
	m, _, c, _ := fixture(t)
	if _, err := m.ledger.db.Exec("CREATE TRIGGER fail_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'private-proof-fixture'); END"); err != nil {
		t.Fatal(err)
	}
	_, _, err := m.Create(context.Background(), controller, body(t, request(c.Now())))
	if err == nil || strings.Contains(err.Error(), "private-proof-fixture") {
		t.Fatal("failure not sanitized", err)
	}
	if count(t, m.ledger, "leases") != 0 || count(t, m.ledger, "events") != 0 {
		t.Fatal("reservation committed without event")
	}
	if _, err := m.ledger.db.Exec("DROP TRIGGER fail_event"); err != nil {
		t.Fatal(err)
	}
	create(t, m, c)
	for _, query := range []string{"UPDATE leases SET expires_at=expires_at+1", "UPDATE leases SET ownership_proof='changed'", "DELETE FROM leases", "UPDATE events SET reason='rewritten'", "DELETE FROM events"} {
		if _, err := m.ledger.db.Exec(query); err == nil {
			t.Fatal("immutable record changed", query)
		}
	}
	if _, err := m.ledger.db.Exec("CREATE TRIGGER fail_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'fixture'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Release(context.Background(), controller, job); !errors.Is(err, ErrCleanup) {
		t.Fatal("cleanup ignored failed state/audit transaction", err)
	}
	got, _ := m.Get(context.Background(), controller, job)
	if got.State != Active || got.Version != 3 {
		t.Fatal("state changed without event")
	}
	if _, err := m.ledger.db.Exec("DROP TRIGGER fail_event"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Release(context.Background(), controller, job); err != nil {
		t.Fatal(err)
	}
}

func TestReopenRecoversInterruptedStartupWithoutController(t *testing.T) {
	m, b, c, path := fixture(t)
	r := record{Lease: Lease{JobID: job, CommandID: command, ControllerID: controller, AppID: app, DeploymentID: deployment,
		Template: config().Templates[0], ProfileID: "build-small-v1", State: Reserved, Version: 1, Reason: "requested", CreatedAt: c.Now(), ExpiresAt: c.Now().Add(5 * time.Minute)},
		fingerprint: strings.Repeat("a", 64), nonceHash: strings.Repeat("b", 64), proof: strings.Repeat("d", 64)}
	r, _, err := m.ledger.reserve(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	r, err = m.ledger.advance(context.Background(), r, Starting, "starting", c.Now)
	if err != nil {
		t.Fatal(err)
	}
	b.machines[job] = machine(r) // Simulated hypervisor persisted after controller/provisioner loss.
	m.ledger.Close()
	l, err := OpenLedger(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	restarted, err := NewManager(l, b, config())
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = c.Now
	c.Advance(61 * time.Second)
	if err := restarted.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := restarted.Get(context.Background(), controller, job)
	if err != nil || got.State != Cleaned {
		t.Fatal("interrupted startup not reconciled", err)
	}
	b.mu.Lock()
	remaining := len(b.machines)
	b.mu.Unlock()
	if remaining != 0 {
		t.Fatal("interrupted machine remained")
	}
}

func TestGuardShutdownInvalidatesReadiness(t *testing.T) {
	m, _, _, _ := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.RunGuard(ctx); err != nil {
		t.Fatal(err)
	}
	caps, err := m.Capabilities(context.Background())
	if err != nil || caps.GuardFresh || caps.ExecutionEnabled {
		t.Fatal("stopped guard still admitted work", err)
	}
}

func TestInvalidCatalogAndInputCannotReachBackend(t *testing.T) {
	m, b, c, _ := fixture(t)
	for _, catalog := range []Config{{}, {Templates: []Template{{ID: "../image", Digest: "sha256:" + strings.Repeat("a", 64)}}},
		{Templates: []Template{{ID: "build-linux-v1", Digest: "https://untrusted/image"}}}} {
		if _, err := NewManager(m.ledger, b, catalog); !errors.Is(err, ErrInvalid) {
			t.Fatal("unsafe operator catalog accepted", err)
		}
	}
	r := request(c.Now())
	r.TemplateID = "unknown-template"
	if _, _, err := m.Create(context.Background(), controller, body(t, r)); !errors.Is(err, ErrInvalid) {
		t.Fatal("unapproved template accepted", err)
	}
	encoded, _ := json.Marshal(request(c.Now()))
	for _, field := range []string{`"xml":"<domain/>"`, `"host_path":"/"`, `"network":"management"`, `"privileged":true`, `"controller_id":"forged"`, `"vcpus":999`} {
		mutated := strings.TrimSuffix(string(encoded), "}") + "," + field + "}"
		if _, _, err := m.Create(context.Background(), controller, strings.NewReader(mutated)); err == nil {
			t.Fatal("unsafe field accepted", field)
		}
	}
	b.mu.Lock()
	calls := b.creates
	b.mu.Unlock()
	if calls != 0 || count(t, m.ledger, "leases") != 0 {
		t.Fatal("rejected input reached execution")
	}
}
