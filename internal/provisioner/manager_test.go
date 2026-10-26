package provisioner

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"dev-orchestrator/internal/contracts"
)

const (
	controller   = "11111111-1111-4111-8111-111111111111"
	job          = "22222222-2222-4222-8222-222222222222"
	command      = "33333333-3333-4333-8333-333333333333"
	app          = "44444444-4444-4444-8444-444444444444"
	deployment   = "55555555-5555-4555-8555-555555555555"
	otherJob     = "66666666-6666-4666-8666-666666666666"
	otherCommand = "77777777-7777-4777-8777-777777777777"
)

// Simulator exists ONLY in _test.go. It models the backend fencing contract;
// it is not evidence of any real hypervisor, firewall, quota or VM isolation.
type fakeBackend struct {
	mu             sync.Mutex
	controls       Controls
	machines       map[string]Machine
	fenced         map[string]bool
	creates        int
	cleanups       int
	failCreate     bool
	failCleanup    bool
	partialCleanup bool
	hook           func(context.Context) error
}

func newBackend() *fakeBackend {
	return &fakeBackend{controls: readyControls(), machines: make(map[string]Machine), fenced: make(map[string]bool)}
}

func readyControls() Controls {
	return Controls{PinnedTemplate: true, KVMIsolation: true, ExternalQuotas: true, IsolatedNetwork: true,
		HostDeadline: true, LateStartFence: true, OwnershipChecks: true, ConfirmedCleanup: true}
}
func (b *fakeBackend) Controls() Controls { b.mu.Lock(); defer b.mu.Unlock(); return b.controls }
func (b *fakeBackend) Create(ctx context.Context, m Machine) error {
	b.mu.Lock()
	b.creates++
	hook := b.hook
	b.mu.Unlock()
	if hook != nil {
		if err := hook(ctx); err != nil {
			return err
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fenced[m.Lease.JobID] {
		return ErrConflict
	}
	if existing, ok := b.machines[m.Lease.JobID]; ok && existing.OwnershipProof != m.OwnershipProof {
		return ErrConflict
	}
	b.machines[m.Lease.JobID] = m
	if b.failCreate {
		return ErrUnavailable
	}
	return nil
}
func (b *fakeBackend) Cleanup(ctx context.Context, m Machine) (CleanupResult, error) {
	if ctx.Err() != nil {
		return CleanupResult{}, ctx.Err()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cleanups++
	if existing, ok := b.machines[m.Lease.JobID]; ok && existing.OwnershipProof != m.OwnershipProof {
		return CleanupResult{}, ErrConflict
	}
	b.fenced[m.Lease.JobID] = true
	if b.failCleanup {
		return CleanupResult{}, ErrCleanup
	}
	delete(b.machines, m.Lease.JobID)
	return CleanupResult{VMAbsent: true, ArtifactsAbsent: !b.partialCleanup, StartFenced: true}, nil
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.t = c.t.Add(d) }

func config() Config {
	return Config{Templates: []Template{{ID: "build-linux-v1", Digest: "sha256:" + strings.Repeat("a", 64)}}, OperationTimeout: 2 * time.Second}
}
func fixture(t *testing.T) (*Manager, *fakeBackend, *clock, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "leases.db")
	l, err := OpenLedger(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	b := newBackend()
	m, err := NewManager(l, b, config())
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Now().UTC()}
	m.now = c.Now
	if err := m.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	return m, b, c, path
}
func request(now time.Time) contracts.BuildLeaseRequest {
	return contracts.BuildLeaseRequest{SchemaVersion: 1, CommandID: command, JobID: job, AppID: app, DeploymentID: deployment,
		TemplateID: "build-linux-v1", ProfileID: "build-small-v1", Nonce: strings.Repeat("b", 64), ExpiresAt: now.Add(5 * time.Minute)}
}
func body(t *testing.T, r contracts.BuildLeaseRequest) *strings.Reader {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return strings.NewReader(string(b))
}
func create(t *testing.T, m *Manager, c *clock) Lease {
	t.Helper()
	lease, created, err := m.Create(context.Background(), controller, body(t, request(c.Now())))
	if err != nil || !created || lease.State != Active {
		t.Fatalf("create: %+v %v %v", lease, created, err)
	}
	return lease
}
func count(t *testing.T, l *Ledger, table string) int {
	t.Helper()
	var n int
	if err := l.db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestUnconfiguredBackendCannotExecute(t *testing.T) {
	budget := SmallBudget()
	if budget.VCPUs != 2 || budget.HostCPUMillis != 2000 || budget.MemoryMiB != 4096 || budget.HostMemoryMiB != 4608 ||
		budget.VirtualDiskMiB != 10240 || budget.PhysicalDiskMiB != 11264 || budget.DiskIOPS != 1000 || budget.HostPIDs != 128 || budget.GuestPIDs != 512 {
		t.Fatal("build-small-v1 resource policy changed without review")
	}
	m, _, c, _ := fixture(t)
	disabled, err := NewManager(m.ledger, UnconfiguredBackend{}, config())
	if err != nil {
		t.Fatal(err)
	}
	disabled.now = c.Now
	caps, err := disabled.Capabilities(context.Background())
	if err != nil || caps.ExecutionEnabled {
		t.Fatal("disabled backend reports ready", err)
	}
	if _, _, err := disabled.Create(context.Background(), controller, body(t, request(c.Now()))); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unconfigured backend admitted a build", err)
	}
	if count(t, m.ledger, "leases") != 0 {
		t.Fatal("disabled backend reserved work")
	}
	if err := disabled.RunGuard(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unsupported guard reports healthy", err)
	}
}

func TestCreateIdempotencyAndNoSecretResponse(t *testing.T) {
	m, b, c, _ := fixture(t)
	r := request(c.Now())
	lease := create(t, m, c)
	got, created, err := m.Create(context.Background(), controller, body(t, r))
	if err != nil || created || got != lease {
		t.Fatal("idempotent command changed lease", err)
	}
	stored, err := m.ledger.load(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(lease)
	if strings.Contains(string(encoded), stored.proof) || strings.Contains(string(encoded), r.Nonce) || strings.Contains(string(encoded), "ownership") {
		t.Fatal("private host data escaped")
	}
	b.mu.Lock()
	calls := b.creates
	machine := b.machines[job]
	b.mu.Unlock()
	if calls != 1 || machine.Budget != SmallBudget() || machine.OwnershipProof != stored.proof {
		t.Fatal("incorrect fixed budget or ownership")
	}
	r.ExpiresAt = r.ExpiresAt.Add(time.Minute)
	if _, _, err := m.Create(context.Background(), controller, body(t, r)); !errors.Is(err, ErrConflict) {
		t.Fatal("lease extended through retry", err)
	}
	if count(t, m.ledger, "events") != 3 {
		t.Fatal("retry duplicated lifecycle events")
	}
	if _, err := m.Get(context.Background(), otherJob, job); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-controller read allowed")
	}
	if _, err := m.Release(context.Background(), otherJob, job); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-controller release allowed")
	}
}

func TestReleaseTombstonesAndReplayProtection(t *testing.T) {
	m, _, c, _ := fixture(t)
	r := request(c.Now())
	create(t, m, c)
	lease, err := m.Release(context.Background(), controller, job)
	if err != nil || lease.State != Cleaned {
		t.Fatal("cleanup failed", err)
	}
	if _, err := m.Release(context.Background(), controller, job); err != nil {
		t.Fatal("release retry failed", err)
	}
	got, created, err := m.Create(context.Background(), controller, body(t, r))
	if err != nil || created || got.State != Cleaned {
		t.Fatal("tombstone resurrected", err)
	}
	r.JobID = otherJob
	r.CommandID = otherCommand
	if _, _, err := m.Create(context.Background(), controller, body(t, r)); !errors.Is(err, ErrConflict) {
		t.Fatal("nonce replay across jobs accepted", err)
	}
	r.Nonce = strings.Repeat("c", 64)
	r.CommandID = command
	if _, _, err := m.Create(context.Background(), controller, body(t, r)); !errors.Is(err, ErrConflict) {
		t.Fatal("command replay across jobs accepted", err)
	}
	r.CommandID = otherCommand
	if _, created, err := m.Create(context.Background(), controller, body(t, r)); err != nil || !created {
		t.Fatal("confirmed cleanup did not release slot", err)
	}
}

func TestExpiryIsIndependentAndImmutable(t *testing.T) {
	m, b, c, _ := fixture(t)
	original := create(t, m, c)
	c.Advance(5 * time.Minute)
	if err := m.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := m.Get(context.Background(), controller, job)
	if err != nil || got.State != Cleaned || got.ExpiresAt != original.ExpiresAt {
		t.Fatal("expiry changed or VM not cleaned", err)
	}
	b.mu.Lock()
	remaining := len(b.machines)
	fenced := b.fenced[job]
	b.mu.Unlock()
	if remaining != 0 || !fenced {
		t.Fatal("expired machine not fenced/removed")
	}
	r := request(c.Now())
	if _, _, err := m.Create(context.Background(), controller, body(t, r)); !errors.Is(err, ErrConflict) {
		t.Fatal("expired job reused with a fresh deadline", err)
	}
	if _, err := m.ledger.db.Exec("UPDATE leases SET expires_at=expires_at+1"); err == nil {
		t.Fatal("SQL deadline mutation allowed")
	}
}

func TestStaleGuardAndMissingControlsBlockAdmission(t *testing.T) {
	m, b, c, _ := fixture(t)
	c.Advance(11 * time.Second)
	if _, _, err := m.Create(context.Background(), controller, body(t, request(c.Now()))); !errors.Is(err, ErrUnavailable) {
		t.Fatal("stale guard accepted work", err)
	}
	if err := m.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	checks := []func(*Controls){func(c *Controls) { c.PinnedTemplate = false }, func(c *Controls) { c.KVMIsolation = false }, func(c *Controls) { c.ExternalQuotas = false }, func(c *Controls) { c.IsolatedNetwork = false },
		func(c *Controls) { c.HostDeadline = false }, func(c *Controls) { c.LateStartFence = false }, func(c *Controls) { c.OwnershipChecks = false }, func(c *Controls) { c.ConfirmedCleanup = false }}
	for _, disable := range checks {
		b.mu.Lock()
		b.controls = readyControls()
		disable(&b.controls)
		b.mu.Unlock()
		if _, _, err := m.Create(context.Background(), controller, body(t, request(c.Now()))); !errors.Is(err, ErrUnavailable) {
			t.Fatal("missing host control accepted work", err)
		}
	}
	if count(t, m.ledger, "leases") != 0 {
		t.Fatal("rejected requests reserved resources")
	}
}

func TestFailedOrPartialCleanupKeepsCapacity(t *testing.T) {
	for _, partial := range []bool{false, true} {
		m, b, c, _ := fixture(t)
		create(t, m, c)
		b.mu.Lock()
		b.failCleanup = !partial
		b.partialCleanup = partial
		b.mu.Unlock()
		if _, err := m.Release(context.Background(), controller, job); !errors.Is(err, ErrCleanup) {
			t.Fatal("unconfirmed cleanup accepted", err)
		}
		got, _ := m.Get(context.Background(), controller, job)
		if got.State != CleanupFailed {
			t.Fatal("cleanup failure hidden")
		}
		r := request(c.Now())
		r.JobID = otherJob
		r.CommandID = otherCommand
		r.Nonce = strings.Repeat("c", 64)
		if _, _, err := m.Create(context.Background(), controller, body(t, r)); !errors.Is(err, ErrCapacity) {
			t.Fatal("unconfirmed cleanup released capacity", err)
		}
		b.mu.Lock()
		b.failCleanup = false
		b.partialCleanup = false
		b.mu.Unlock()
		if err := m.Sweep(context.Background()); err != nil {
			t.Fatal("cleanup retry failed", err)
		}
		if _, created, err := m.Create(context.Background(), controller, body(t, r)); err != nil || !created {
			t.Fatal("confirmed cleanup did not free capacity", err)
		}
	}
}

func TestCreateFailureAndCanceledRequestCleanUp(t *testing.T) {
	for _, mode := range []string{"partial-create", "cancel", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			m, b, c, _ := fixture(t)
			if mode == "timeout" {
				m.operationTimeout = 100 * time.Millisecond
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "partial-create" {
				b.failCreate = true
			} else {
				b.hook = func(ctx context.Context) error {
					if mode == "cancel" {
						cancel()
					}
					<-ctx.Done()
					return ctx.Err()
				}
			}
			if _, _, err := m.Create(ctx, controller, body(t, request(c.Now()))); err == nil {
				t.Fatal("failed create reported success")
			}
			got, err := m.Get(context.Background(), controller, job)
			if err != nil || got.State != Cleaned {
				t.Fatal("failed create leaked capacity", err)
			}
			b.mu.Lock()
			remaining := len(b.machines)
			b.mu.Unlock()
			if remaining != 0 {
				t.Fatal("partial machine remained")
			}
		})
	}
}

func TestReleaseFencesDelayedStart(t *testing.T) {
	m, b, c, _ := fixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	b.hook = func(ctx context.Context) error {
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	done := make(chan error, 1)
	r := request(c.Now())
	go func() { _, _, err := m.Create(context.Background(), controller, body(t, r)); done <- err }()
	<-entered
	if _, err := m.Release(context.Background(), controller, job); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("delayed start survived fence")
	}
	b.mu.Lock()
	remaining := len(b.machines)
	b.mu.Unlock()
	if remaining != 0 {
		t.Fatal("late start created a machine")
	}
	got, _ := m.Get(context.Background(), controller, job)
	if got.State != Cleaned {
		t.Fatal("cleanup was resurrected")
	}
}

func TestExpiredCreateIsNeverReportedActive(t *testing.T) {
	m, b, c, _ := fixture(t)
	r := request(c.Now())
	b.hook = func(context.Context) error {
		c.Advance(6 * time.Minute)
		return nil
	}
	if _, _, err := m.Create(context.Background(), controller, body(t, r)); err == nil {
		t.Fatal("expired create reported success")
	}
	got, err := m.Get(context.Background(), controller, job)
	if err != nil || got.State != Cleaned {
		t.Fatal("expired create was not reconciled", err)
	}
}

func TestForeignResourceIsNeverRemoved(t *testing.T) {
	m, b, c, _ := fixture(t)
	b.machines[job] = Machine{OwnershipProof: "foreign"}
	if _, _, err := m.Create(context.Background(), controller, body(t, request(c.Now()))); !errors.Is(err, ErrCleanup) {
		t.Fatal("foreign collision not quarantined", err)
	}
	b.mu.Lock()
	foreign, exists := b.machines[job]
	b.mu.Unlock()
	if !exists || foreign.OwnershipProof != "foreign" {
		t.Fatal("foreign VM was removed")
	}
	got, _ := m.Get(context.Background(), controller, job)
	if got.State != CleanupFailed {
		t.Fatal("foreign resource released capacity")
	}
}

func TestConcurrentDuplicateCreateAndSeparateHandles(t *testing.T) {
	m, b, c, path := fixture(t)
	l, err := OpenLedger(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	other, err := NewManager(l, b, config())
	if err != nil {
		t.Fatal(err)
	}
	other.now = c.Now
	type outcome struct {
		created bool
		err     error
	}
	results := make(chan outcome, 10)
	r := request(c.Now())
	for i := range 10 {
		go func(i int) {
			manager := []*Manager{m, other}[i%2]
			_, created, err := manager.Create(context.Background(), controller, body(t, r))
			results <- outcome{created, err}
		}(i)
	}
	winners := 0
	for range 10 {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.created {
			winners++
		}
	}
	b.mu.Lock()
	calls := b.creates
	b.mu.Unlock()
	if winners != 1 || calls != 1 {
		t.Fatal("duplicate VM create", winners, calls)
	}
}
