package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"dev-orchestrator/internal/domain"
)

const (
	userID        = "11111111-1111-4111-8111-111111111111"
	appID         = "22222222-2222-4222-8222-222222222222"
	repoID        = "33333333-3333-4333-8333-333333333333"
	branchID      = "44444444-4444-4444-8444-444444444444"
	deploymentID  = "55555555-5555-4555-8555-555555555555"
	actorID       = "66666666-6666-4666-8666-666666666666"
	correlationID = "77777777-7777-4777-8777-777777777777"
)

func testStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "metadata.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func execSQL(t *testing.T, s *Store, query string, args ...any) {
	t.Helper()
	if _, err := s.db.ExecContext(context.Background(), query, args...); err != nil {
		t.Fatal(err)
	}
}

func seed(t *testing.T, s *Store) {
	t.Helper()
	now := time.Now().UnixNano()
	execSQL(t, s, "INSERT INTO users(id,username,password_hash,created_at,updated_at) VALUES (?,?,?,?,?)", userID, "fixture-admin", "test-only-not-a-login-credential", now, now)
	execSQL(t, s, "INSERT INTO user_roles(user_id,role_id) VALUES (?, 'admin')", userID)
	execSQL(t, s, "INSERT INTO applications(id,slug,display_name,owner_id,created_at,updated_at) VALUES (?,?,?,?,?,?)", appID, "inventory", "Inventory", userID, now, now)
	execSQL(t, s, "INSERT INTO git_repositories(id,canonical_url,allowed_origin,owner_id,created_at) VALUES (?,?,?,?,?)", repoID, "https://github.com/example/inventory.git", "github.com", userID, now)
	execSQL(t, s, "INSERT INTO git_branches(id,repository_id,ref_name) VALUES (?,?,?)", branchID, repoID, "main")
}

func intent() CreateDeployment {
	return CreateDeployment{ID: deploymentID, AppID: appID, BranchID: branchID, SubmittedBy: userID,
		IdempotencyKey: "fixture-key-00001", RequestHash: strings.Repeat("a", 64), CorrelationID: correlationID}
}

func change() Transition {
	return Transition{DeploymentID: deploymentID, ExpectedState: domain.Submitted, ExpectedVersion: 1, ExpectedGeneration: 1,
		To: domain.Validating, Reason: ReasonStarted, Actor: Actor{Kind: "controller", ID: actorID}, CorrelationID: correlationID}
}

func submit(t *testing.T, s *Store) Deployment {
	t.Helper()
	d, created, err := s.Create(context.Background(), intent())
	if err != nil || !created {
		t.Fatalf("create: created=%v err=%v", created, err)
	}
	return d
}

func scalar(t *testing.T, s *Store, query string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := s.db.QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func assertCounts(t *testing.T, s *Store, deployments, events int64) {
	t.Helper()
	if got := scalar(t, s, "SELECT count(*) FROM deployments"); got != deployments {
		t.Fatalf("deployments=%d, want %d", got, deployments)
	}
	for _, table := range []string{"deployment_events", "audit_events", "outbox"} {
		if got := scalar(t, s, "SELECT count(*) FROM "+table); got != events {
			t.Fatalf("%s=%d, want %d", table, got, events)
		}
	}
}

func TestBootstrapReopenAndPragmas(t *testing.T) {
	s, path := testStore(t)
	seed(t, s)
	submit(t, s)
	if got := scalar(t, s, "SELECT count(*) FROM schema_migrations"); got != 4 {
		t.Fatal("expected all embedded migrations")
	}
	if got := scalar(t, s, "PRAGMA user_version"); got != 4 {
		t.Fatal("wrong schema version")
	}
	for query, want := range map[string]int64{"PRAGMA foreign_keys": 1, "PRAGMA synchronous": 2, "PRAGMA busy_timeout": 5000, "PRAGMA trusted_schema": 0} {
		if got := scalar(t, s, query); got != want {
			t.Errorf("%s=%d, want %d", query, got, want)
		}
	}
	if err := s.CheckIntegrity(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	d, err := s.Deployment(context.Background(), deploymentID)
	if err != nil || d.State != domain.Submitted || d.Version != 1 {
		t.Fatalf("reopen lost deployment: %+v %v", d, err)
	}
	assertCounts(t, s, 1, 1)
	// Force a replacement pooled connection; pragmas must be reapplied.
	s.db.SetConnMaxLifetime(time.Nanosecond)
	if scalar(t, s, "PRAGMA foreign_keys") != 1 {
		t.Fatal("foreign keys disabled on replacement connection")
	}
	if _, err := s.db.Exec("INSERT INTO user_roles(user_id,role_id) VALUES (?, 'admin')", actorID); err == nil {
		t.Fatal("replacement connection accepted orphan FK")
	}
}

func TestCreateAndAdvanceAtomicPayloads(t *testing.T) {
	s, _ := testStore(t)
	seed(t, s)
	d := submit(t, s)
	if d.State != domain.Submitted || d.Generation != 1 || d.Version != 1 || d.CreatedAt.Location() != time.UTC {
		t.Fatalf("unexpected deployment: %+v", d)
	}
	event, err := s.Advance(context.Background(), change())
	if err != nil {
		t.Fatal(err)
	}
	if !validIDs(event.ID) || event.Sequence != 2 || event.FromState != domain.Submitted || event.ToState != domain.Validating {
		t.Fatalf("unexpected event: %+v", event)
	}
	d, err = s.Deployment(context.Background(), deploymentID)
	if err != nil || d.State != domain.Validating || d.Version != 2 {
		t.Fatalf("transition not persisted: %+v %v", d, err)
	}
	assertCounts(t, s, 1, 2)
	events, err := s.Events(context.Background(), deploymentID, 0, 100)
	if err != nil || len(events) != 2 || events[1] != event {
		t.Fatalf("persisted events differ: %+v %v", events, err)
	}
	page, err := s.Events(context.Background(), deploymentID, 1, 1)
	if err != nil || len(page) != 1 || page[0].Sequence != 2 {
		t.Fatal("event paging failed")
	}
	messages, err := s.PendingOutbox(context.Background(), 100)
	if err != nil || len(messages) != 2 || messages[1].Event != event || messages[0].ID >= messages[1].ID {
		t.Fatalf("outbox ordering/identity failed: %+v %v", messages, err)
	}
	var payload string
	if err := s.db.QueryRow("SELECT sanitized_metadata FROM audit_events WHERE deployment_event_id=?", event.ID).Scan(&payload); err != nil ||
		!strings.Contains(payload, event.ID) || strings.Contains(payload, "repository_url") || strings.Contains(payload, "environment") {
		t.Fatalf("unexpected audit payload: %v", err)
	}
	if err := s.MarkDelivered(context.Background(), messages[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkDelivered(context.Background(), messages[0].ID); err != nil {
		t.Fatal("ack retry was not idempotent")
	}
	messages, err = s.PendingOutbox(context.Background(), 100)
	if err != nil || len(messages) != 1 || messages[0].Event.ID != event.ID {
		t.Fatal("ack removed the wrong message")
	}
}

func TestCreateIdempotencyAndInflightReservation(t *testing.T) {
	s, _ := testStore(t)
	seed(t, s)
	first := submit(t, s)
	retry := intent()
	retry.ID = actorID
	d, created, err := s.Create(context.Background(), retry)
	if err != nil || created || d != first {
		t.Fatalf("idempotent retry failed: %v %v", created, err)
	}
	retry.RequestHash = strings.Repeat("b", 64)
	if _, _, err := s.Create(context.Background(), retry); !errors.Is(err, ErrConflict) {
		t.Fatal("same key accepted different request")
	}
	retry = intent()
	retry.ID, retry.IdempotencyKey = actorID, "different-key-0001"
	if _, _, err := s.Create(context.Background(), retry); !errors.Is(err, ErrConflict) {
		t.Fatalf("parallel inflight deployment accepted: %v", err)
	}
	if scalar(t, s, "SELECT deployment_generation FROM applications WHERE id=?", appID) != 1 {
		t.Fatal("failed reservation advanced generation")
	}
	failed := change()
	failed.To, failed.Reason = domain.Failed, ReasonError
	if _, err := s.Advance(context.Background(), failed); err != nil {
		t.Fatal(err)
	}
	d, created, err = s.Create(context.Background(), retry)
	if err != nil || !created || d.Generation != 2 {
		t.Fatalf("new generation after failure: %+v %v", d, err)
	}
	assertCounts(t, s, 2, 3)
}

func TestForeignKeyFailureAndDisabledAppDoNotReserveGeneration(t *testing.T) {
	s, _ := testStore(t)
	seed(t, s)
	bad := intent()
	bad.BranchID = actorID
	if _, _, err := s.Create(context.Background(), bad); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("missing branch FK accepted", err)
	}
	if scalar(t, s, "SELECT deployment_generation FROM applications") != 0 {
		t.Fatal("FK failure leaked generation reservation")
	}
	execSQL(t, s, "UPDATE applications SET state='disabled'")
	if _, _, err := s.Create(context.Background(), intent()); !errors.Is(err, ErrConflict) {
		t.Fatal("disabled app accepted deployment", err)
	}
	assertCounts(t, s, 0, 0)
}

func TestConcurrentIdempotentCreation(t *testing.T) {
	s, _ := testStore(t)
	seed(t, s)
	type result struct {
		id      string
		created bool
		err     error
	}
	results := make(chan result, 10)
	for range 10 {
		go func() {
			d, created, err := s.Create(context.Background(), intent())
			results <- result{d.ID, created, err}
		}()
	}
	created := 0
	for range 10 {
		r := <-results
		if r.err != nil || r.id != deploymentID {
			t.Errorf("idempotent race: %+v", r)
		}
		if r.created {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("%d creations for same idempotency key", created)
	}
	assertCounts(t, s, 1, 1)
}

// This exercises persistence topology only; no image approval or health proof
// is implied. Future controller tests must establish those before transitions.
func TestPersistsLegalStatePath(t *testing.T) {
	s, _ := testStore(t)
	seed(t, s)
	d := submit(t, s)
	path := []domain.State{domain.Validating, domain.Cloning, domain.Building, domain.Scanning, domain.Approved,
		domain.Deploying, domain.HealthCheck, domain.Running, domain.RolledBack}
	for _, next := range path {
		c := change()
		c.ExpectedState, c.ExpectedVersion, c.To = d.State, d.Version, next
		if next == domain.RolledBack {
			c.Reason = ReasonRollbackVerified
		}
		if _, err := s.Advance(context.Background(), c); err != nil {
			t.Fatal(err)
		}
		var err error
		d, err = s.Deployment(context.Background(), deploymentID)
		if err != nil {
			t.Fatal(err)
		}
	}
	assertCounts(t, s, 1, 10)
}

func TestAdvanceCASAndTopology(t *testing.T) {
	s, _ := testStore(t)
	seed(t, s)
	submit(t, s)
	for _, edit := range []func(*Transition){
		func(c *Transition) { c.ExpectedVersion = 2 },
		func(c *Transition) { c.ExpectedGeneration = 2 },
		func(c *Transition) { c.ExpectedState, c.To = domain.Cloning, domain.Building },
	} {
		c := change()
		edit(&c)
		if _, err := s.Advance(context.Background(), c); !errors.Is(err, ErrConflict) {
			t.Fatalf("expected CAS conflict, got %v", err)
		}
	}
	c := change()
	c.To = domain.Running
	if _, err := s.Advance(context.Background(), c); !errors.Is(err, ErrInvalidState) {
		t.Fatal("skipped security states")
	}
	if _, err := s.Advance(context.Background(), change()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Advance(context.Background(), change()); !errors.Is(err, ErrConflict) {
		t.Fatal("replayed transition accepted")
	}
	assertCounts(t, s, 1, 2)
}

func TestRollbackReasonAndTerminalStates(t *testing.T) {
	s, _ := testStore(t)
	seed(t, s)
	submit(t, s)
	c := change()
	c.To, c.Reason = domain.Failed, ReasonError
	if _, err := s.Advance(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	c.ExpectedState, c.ExpectedVersion, c.To = domain.Failed, 2, domain.RolledBack
	if _, err := s.Advance(context.Background(), c); !errors.Is(err, ErrInvalidState) {
		t.Fatal("rollback accepted without explicit verified-rollback reason")
	}
	c.Reason = ReasonRollbackVerified
	if _, err := s.Advance(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	c.ExpectedState, c.ExpectedVersion, c.To = domain.RolledBack, 3, domain.Validating
	if _, err := s.Advance(context.Background(), c); !errors.Is(err, ErrInvalidState) {
		t.Fatal("terminal deployment reused")
	}
}

func TestFailureRollsBackEveryWrite(t *testing.T) {
	for _, duringCreate := range []bool{false, true} {
		t.Run(map[bool]string{true: "create", false: "advance"}[duringCreate], func(t *testing.T) {
			s, _ := testStore(t)
			seed(t, s)
			if !duringCreate {
				submit(t, s)
			}
			execSQL(t, s, "CREATE TRIGGER fail_outbox BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT, 'fixture-secret-not-for-logs'); END")
			var err error
			if duringCreate {
				_, _, err = s.Create(context.Background(), intent())
			} else {
				_, err = s.Advance(context.Background(), change())
			}
			if err == nil || strings.Contains(err.Error(), "fixture-secret") {
				t.Fatal("missing failure or driver error leaked input")
			}
			if duringCreate {
				assertCounts(t, s, 0, 0)
				if scalar(t, s, "SELECT deployment_generation FROM applications") != 0 {
					t.Fatal("failed create reserved generation")
				}
			} else {
				assertCounts(t, s, 1, 1)
				d, _ := s.Deployment(context.Background(), deploymentID)
				if d.State != domain.Submitted || d.Version != 1 {
					t.Fatal("state changed without matching outbox")
				}
			}
			execSQL(t, s, "DROP TRIGGER fail_outbox")
			if duringCreate {
				submit(t, s)
			}
			if _, err := s.Advance(context.Background(), change()); err != nil {
				t.Fatal("failed transaction poisoned connection", err)
			}
			assertCounts(t, s, 1, 2)
		})
	}
}

func TestCancellationAndPanicRollback(t *testing.T) {
	s, _ := testStore(t)
	seed(t, s)
	submit(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	err := s.write(ctx, func(conn *sql.Conn) error {
		if _, err := s.advanceTx(ctx, conn, change()); err != nil {
			return err
		}
		cancel()
		return ctx.Err()
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	assertCounts(t, s, 1, 1)
	func() {
		defer func() {
			if recover() == nil {
				t.Error("expected test panic")
			}
		}()
		_ = s.write(context.Background(), func(conn *sql.Conn) error {
			if _, err := s.advanceTx(context.Background(), conn, change()); err != nil {
				t.Fatal(err)
			}
			panic("test-only crash before commit")
		})
	}()
	assertCounts(t, s, 1, 1)
	if _, err := s.Advance(context.Background(), change()); err != nil {
		t.Fatal("connection left in transaction after panic", err)
	}
}

func TestConcurrentCASAcrossHandles(t *testing.T) {
	s, path := testStore(t)
	seed(t, s)
	submit(t, s)
	other, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	const n = 12
	results := make(chan error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			handle := []*Store{s, other}[i%2]
			_, err := handle.Advance(context.Background(), change())
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrConflict) {
			t.Errorf("unexpected concurrent result: %v", err)
		}
	}
	if success != 1 {
		t.Fatalf("%d updates won the same CAS", success)
	}
	assertCounts(t, s, 1, 2)
}

func TestMigrationHistoryFailsClosed(t *testing.T) {
	for _, damage := range []string{"checksum", "future", "user-version", "missing", "name"} {
		t.Run(damage, func(t *testing.T) {
			s, path := testStore(t)
			switch damage {
			case "checksum":
				execSQL(t, s, "UPDATE schema_migrations SET checksum=?", strings.Repeat("0", 64))
			case "future":
				execSQL(t, s, "INSERT INTO schema_migrations(version,name,checksum,applied_at) VALUES (5,'005_future.sql',?,0)", strings.Repeat("0", 64))
				execSQL(t, s, "PRAGMA user_version=5")
			case "user-version":
				execSQL(t, s, "PRAGMA user_version=9")
			case "missing":
				execSQL(t, s, "DELETE FROM schema_migrations")
			case "name":
				execSQL(t, s, "UPDATE schema_migrations SET name='001_changed.sql' WHERE version=1")
			}
			_ = s.Close()
			opened, err := Open(context.Background(), path)
			if opened != nil {
				opened.Close()
			}
			if !errors.Is(err, ErrSchemaMismatch) {
				t.Fatalf("damaged history accepted: %v", err)
			}
		})
	}
}

func TestMigrationRollbackAndUpgradeGate(t *testing.T) {
	ctx := context.Background()
	db, err := openDatabase(ctx, filepath.Join(t.TempDir(), "broken.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Store{db: db}
	list, err := readMigrations(fstest.MapFS{"001_invalid.sql": {Data: []byte("CREATE TABLE partial(id INTEGER); INVALID SQL;")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.migrate(ctx, list); !errors.Is(err, ErrSchemaMismatch) {
		t.Fatal("invalid migration accepted", err)
	}
	if scalar(t, s, "SELECT count(*) FROM sqlite_schema WHERE name IN ('partial','schema_migrations')") != 0 || scalar(t, s, "PRAGMA user_version") != 0 {
		t.Fatal("failed migration left partial schema/version")
	}
	good, _ := loadMigrations()
	if err := s.migrate(ctx, good); err != nil {
		t.Fatal("migration retry failed", err)
	}
	future := append(append([]migration{}, good...), migration{version: len(good) + 1, name: fmt.Sprintf("%03d_next.sql", len(good)+1), checksum: strings.Repeat("0", 64), sql: "CREATE TABLE next(id INTEGER);"})
	if err := s.migrate(ctx, future); !errors.Is(err, ErrUpgradeRequired) {
		t.Fatal("existing-data upgrade did not require verified backup", err)
	}
	if scalar(t, s, "PRAGMA user_version") != int64(len(good)) || scalar(t, s, "SELECT count(*) FROM sqlite_schema WHERE name='next'") != 0 {
		t.Fatal("blocked upgrade changed schema")
	}
}

func TestMigrationFilenameValidation(t *testing.T) {
	for _, files := range []fstest.MapFS{
		{}, {"002_gap.sql": {Data: []byte("SELECT 1;")}},
		{"001_one.sql": {Data: []byte("SELECT 1;")}, "001_duplicate.sql": {Data: []byte("SELECT 1;")}},
		{"notes.txt": {Data: []byte("not SQL")}}, {"001_empty.sql": {}},
	} {
		if _, err := readMigrations(files); !errors.Is(err, ErrSchemaMismatch) {
			t.Fatalf("invalid migration set accepted: %v", files)
		}
	}
}

func TestStartupLockAndConcurrentOpen(t *testing.T) {
	s, path := testStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	locked := make(chan struct{})
	release := make(chan struct{})
	writerDone := make(chan error, 1)
	go func() {
		writerDone <- s.write(ctx, func(*sql.Conn) error { close(locked); <-release; return nil })
	}()
	<-locked
	opened := make(chan error, 1)
	go func() {
		other, err := Open(ctx, path)
		if other != nil {
			other.Close()
		}
		opened <- err
	}()
	select {
	case err := <-opened:
		close(release)
		t.Fatalf("startup escaped migration write lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-writerDone; err != nil {
		t.Fatal(err)
	}
	if err := <-opened; err != nil {
		t.Fatal("startup failed after lock released", err)
	}
	// Fresh-file bootstrap races must not duplicate migrations or leave DDL.
	fresh := filepath.Join(t.TempDir(), "concurrent.db")
	results := make(chan error, 6)
	for range 6 {
		go func() {
			handle, err := Open(ctx, fresh)
			if handle != nil {
				handle.Close()
			}
			results <- err
		}()
	}
	for range 6 {
		if err := <-results; err != nil {
			t.Errorf("concurrent startup: %v", err)
		}
	}
}

func TestForeignKeysOwnershipAndAppendOnly(t *testing.T) {
	s, path := testStore(t)
	seed(t, s)
	submit(t, s)
	queries := []string{
		"INSERT INTO user_roles(user_id,role_id) VALUES ('missing','admin')",
		"DELETE FROM users",
		"UPDATE deployments SET state='UNSAFE'",
		"UPDATE deployments SET generation=1.5",
		"UPDATE deployment_events SET reason_code='rewritten'",
		"DELETE FROM deployment_events",
		"UPDATE audit_events SET action='rewritten'",
		"DELETE FROM audit_events",
		"UPDATE outbox SET payload='{}'",
	}
	for _, query := range queries {
		if _, err := s.db.Exec(query); err == nil {
			t.Errorf("unsafe SQL succeeded: %s", query)
		}
	}
	execSQL(t, s, "INSERT INTO applications(id,slug,display_name,owner_id,created_at,updated_at) VALUES (?,?,?, ?,0,0)", actorID, "other-app", "Other", userID)
	if _, err := s.db.Exec("UPDATE applications SET active_deployment_id=? WHERE id=?", deploymentID, actorID); err == nil {
		t.Fatal("cross-app active deployment accepted")
	}
	if err := s.CheckIntegrity(context.Background()); err != nil {
		t.Fatal(err)
	}
	execSQL(t, s, "PRAGMA foreign_keys=OFF")
	execSQL(t, s, "INSERT INTO user_roles(user_id,role_id) VALUES ('orphan','admin')")
	execSQL(t, s, "PRAGMA foreign_keys=ON")
	if err := s.CheckIntegrity(context.Background()); !errors.Is(err, ErrIntegrity) {
		t.Fatal("foreign-key corruption not detected", err)
	}
	_ = s.Close()
	if opened, err := Open(context.Background(), path); !errors.Is(err, ErrIntegrity) {
		if opened != nil {
			opened.Close()
		}
		t.Fatal("corrupt foreign keys accepted at startup", err)
	}
}

func TestOperatorPathRestrictions(t *testing.T) {
	for _, path := range []string{"", ":memory:", "file:metadata.db?mode=memory", `\\server\share\metadata.db`, "//server/share/metadata.db", filepath.Join(t.TempDir(), "missing", "db")} {
		if s, err := Open(context.Background(), path); err == nil {
			s.Close()
			t.Fatalf("invalid operator path accepted: %q", path)
		}
	}
	// A URI-looking character in a filename must stay file data, not a DSN.
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "metadata#not-a-fragment.db"))
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if runtime.GOOS != "windows" {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if s, err := Open(context.Background(), filepath.Join(dir, "db")); err == nil {
			s.Close()
			t.Fatal("public parent permissions accepted")
		}
	}
}

func TestInvalidInputsAndMissingRecords(t *testing.T) {
	s, _ := testStore(t)
	seed(t, s)
	for _, edit := range []func(*CreateDeployment){
		func(c *CreateDeployment) { c.ID = "invalid" },
		func(c *CreateDeployment) { c.RequestHash = "secret-text" },
		func(c *CreateDeployment) { c.IdempotencyKey = "short" },
	} {
		c := intent()
		edit(&c)
		if _, _, err := s.Create(context.Background(), c); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("invalid intent accepted", err)
		}
	}
	for _, edit := range []func(*Transition){
		func(c *Transition) { c.Actor.Kind = "untrusted-header" },
		func(c *Transition) { c.ExpectedVersion = 0 },
		func(c *Transition) { c.Reason = "arbitrary repository output" },
	} {
		c := change()
		edit(&c)
		if _, err := s.Advance(context.Background(), c); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("invalid transition accepted", err)
		}
	}
	if _, err := s.Deployment(context.Background(), deploymentID); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing deployment not reported")
	}
	if _, err := s.Deployment(context.Background(), "bad"); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("invalid lookup accepted")
	}
	if _, err := s.Advance(context.Background(), change()); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing transition target not reported")
	}
	for _, limit := range []int{-1, 0, 101} {
		if _, err := s.PendingOutbox(context.Background(), limit); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("unbounded outbox page accepted")
		}
		if _, err := s.Events(context.Background(), deploymentID, 0, limit); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("unbounded event page accepted")
		}
	}
	if err := s.MarkDelivered(context.Background(), 0); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("invalid ack accepted")
	}
	if err := s.MarkDelivered(context.Background(), 1); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing ack not reported")
	}
}

func TestCorruptFileAndCancelledOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupt.db")
	if err := os.WriteFile(path, []byte("not a SQLite database"), 0600); err != nil {
		t.Fatal(err)
	}
	if s, err := Open(context.Background(), path); !errors.Is(err, ErrDatabase) {
		if s != nil {
			s.Close()
		}
		t.Fatal("non-SQLite file accepted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	path = filepath.Join(t.TempDir(), "cancelled.db")
	if _, err := Open(ctx, path); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled open ignored", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled open created a file")
	}
}
