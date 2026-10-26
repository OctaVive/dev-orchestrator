package provisioner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"

	"dev-orchestrator/internal/contracts"
)

var (
	identifier     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	templateName   = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)
	templateDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type Config struct {
	Templates        []Template
	OperationTimeout time.Duration
}

type Manager struct {
	ledger           *Ledger
	backend          Backend
	validator        *contracts.Validator
	templates        map[string]Template
	operationTimeout time.Duration
	now              func() time.Time
}

func NewManager(ledger *Ledger, backend Backend, config Config) (*Manager, error) {
	if ledger == nil || backend == nil || len(config.Templates) == 0 || len(config.Templates) > 8 {
		return nil, ErrInvalid
	}
	if config.OperationTimeout == 0 {
		config.OperationTimeout = 20 * time.Second
	}
	if config.OperationTimeout < 50*time.Millisecond || config.OperationTimeout > 20*time.Second {
		return nil, ErrInvalid
	}
	catalog := make(map[string]Template)
	for _, t := range config.Templates {
		if len(t.ID) > 63 || !templateName.MatchString(t.ID) || !templateDigest.MatchString(t.Digest) {
			return nil, ErrInvalid
		}
		if _, exists := catalog[t.ID]; exists {
			return nil, ErrInvalid
		}
		catalog[t.ID] = t
	}
	v, err := contracts.NewValidator()
	if err != nil {
		return nil, ErrInvalid
	}
	return &Manager{ledger: ledger, backend: backend, validator: v, templates: catalog, operationTimeout: config.OperationTimeout, now: time.Now}, nil
}

type Capabilities struct {
	ExecutionEnabled bool     `json:"execution_enabled"`
	Controls         Controls `json:"controls"`
	GuardFresh       bool     `json:"guard_fresh"`
}

func (m *Manager) Capabilities(ctx context.Context) (Capabilities, error) {
	fresh, err := m.ledger.guardFresh(ctx, m.now())
	if err != nil {
		return Capabilities{}, err
	}
	controls := m.backend.Controls()
	return Capabilities{ExecutionEnabled: controls.Ready() && fresh, Controls: controls, GuardFresh: fresh}, nil
}

// Create accepts only the narrow JSON contract. controllerID must come from a
// verified controller certificate, not a header, cookie or request body.
func (m *Manager) Create(ctx context.Context, controllerID string, body io.Reader) (Lease, bool, error) {
	if !identifier.MatchString(controllerID) {
		return Lease{}, false, ErrInvalid
	}
	request, err := m.validator.DecodeBuildLease(body, m.now().UTC())
	if err != nil {
		return Lease{}, false, err
	}
	template, ok := m.templates[request.TemplateID]
	if !ok {
		return Lease{}, false, ErrInvalid
	}
	caps, err := m.Capabilities(ctx)
	if err != nil {
		return Lease{}, false, err
	}
	if !caps.ExecutionEnabled {
		return Lease{}, false, ErrUnavailable
	}
	canonical, err := json.Marshal(struct {
		Controller string                      `json:"controller"`
		Request    contracts.BuildLeaseRequest `json:"request"`
		Template   Template                    `json:"template"`
	}{controllerID, request, template})
	if err != nil {
		return Lease{}, false, ErrInvalid
	}
	var proof [32]byte
	if _, err := rand.Read(proof[:]); err != nil {
		return Lease{}, false, ErrUnavailable
	}
	r := record{Lease: Lease{JobID: request.JobID, CommandID: request.CommandID, ControllerID: controllerID,
		AppID: request.AppID, DeploymentID: request.DeploymentID, Template: template, ProfileID: request.ProfileID,
		State: Reserved, Version: 1, Reason: "requested", CreatedAt: m.now().UTC(), ExpiresAt: request.ExpiresAt},
		fingerprint: digest(canonical), nonceHash: digest([]byte(request.Nonce)), proof: hex.EncodeToString(proof[:])}
	r, created, err := m.ledger.reserve(ctx, r)
	if err != nil {
		return Lease{}, false, err
	}
	if !created {
		return r.Lease, false, nil
	}
	r, err = m.ledger.advance(ctx, r, Starting, "starting", m.now)
	if err != nil {
		_, _ = m.cleanup(request.JobID, "create_failed")
		return Lease{}, true, err
	}
	lifetime := r.ExpiresAt.Sub(m.now())
	if lifetime <= 0 {
		_, _ = m.cleanup(r.JobID, "expired")
		return Lease{}, true, ErrUnavailable
	}
	timeout := min(lifetime, m.operationTimeout)
	operation, cancel := context.WithTimeout(ctx, timeout)
	err = m.backend.Create(operation, machine(r))
	cancel()
	if err != nil {
		_, cleanupErr := m.cleanup(r.JobID, "create_failed")
		if cleanupErr != nil {
			return Lease{}, true, ErrCleanup
		}
		return Lease{}, true, ErrUnavailable
	}
	if !m.now().Before(r.ExpiresAt) || !m.backend.Controls().Ready() {
		_, err := m.cleanup(r.JobID, "expired")
		if err != nil {
			return Lease{}, true, err
		}
		return Lease{}, true, ErrUnavailable
	}
	r, err = m.ledger.advance(ctx, r, Active, "started", m.now)
	if err != nil {
		_, cleanupErr := m.cleanup(request.JobID, "create_failed")
		if cleanupErr != nil {
			return Lease{}, true, ErrCleanup
		}
		return Lease{}, true, ErrConflict
	}
	return r.Lease, true, nil
}

func machine(r record) Machine {
	return Machine{Lease: r.Lease, Budget: SmallBudget(), OwnershipProof: r.proof}
}

func (m *Manager) Get(ctx context.Context, controllerID, jobID string) (Lease, error) {
	if !identifier.MatchString(controllerID) || !identifier.MatchString(jobID) {
		return Lease{}, ErrInvalid
	}
	r, err := m.ledger.load(ctx, jobID)
	if err != nil {
		return Lease{}, err
	}
	if r.ControllerID != controllerID {
		return Lease{}, ErrNotFound
	}
	return r.Lease, nil
}

func (m *Manager) Release(ctx context.Context, controllerID, jobID string) (Lease, error) {
	if _, err := m.Get(ctx, controllerID, jobID); err != nil {
		return Lease{}, err
	}
	return m.cleanup(jobID, "released")
}

// Accepted cleanup continues even if the RPC/controller goes away. A failed
// cleanup never releases capacity. Backend context compliance is mandatory.
func (m *Manager) cleanup(jobID, reason string) (Lease, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.operationTimeout)
	defer cancel()
	for range 4 {
		r, err := m.ledger.load(ctx, jobID)
		if err != nil {
			return Lease{}, ErrCleanup
		}
		if r.State == Cleaned {
			return r.Lease, nil
		}
		if r.State != CleanupPending {
			r, err = m.ledger.advance(ctx, r, CleanupPending, reason, m.now)
			if errors.Is(err, ErrConflict) {
				continue
			}
			if err != nil {
				return Lease{}, ErrCleanup
			}
		}
		result, backendErr := m.backend.Cleanup(ctx, machine(r))
		if backendErr != nil || !result.VMAbsent || !result.ArtifactsAbsent || !result.StartFenced {
			_, _ = m.ledger.advance(ctx, r, CleanupFailed, "cleanup_failed", m.now)
			return Lease{}, ErrCleanup
		}
		r, err = m.ledger.advance(ctx, r, Cleaned, "cleaned", m.now)
		if errors.Is(err, ErrConflict) {
			continue
		}
		if err != nil {
			return Lease{}, ErrCleanup
		}
		return r.Lease, nil
	}
	return Lease{}, ErrCleanup
}

// Sweep is host-local guard work, not an RPC. Never renews a lease. It recovers
// expired, interrupted startup and failed cleanup without the controller.
func (m *Manager) Sweep(ctx context.Context) error {
	records, err := m.ledger.occupied(ctx)
	if err != nil {
		return err
	}
	ready := m.backend.Controls().Ready()
	for _, r := range records {
		reason := ""
		now := m.now()
		switch {
		case !ready:
			reason = "controls_lost"
		case now.Before(r.CreatedAt):
			reason = "clock_invalid"
		case !now.Before(r.ExpiresAt):
			reason = "expired"
		case r.State == CleanupPending || r.State == CleanupFailed:
			reason = "retry"
		case (r.State == Reserved || r.State == Starting) && now.Sub(r.CreatedAt) >= time.Minute:
			reason = "start_timeout"
		}
		if reason != "" {
			if _, err := m.cleanup(r.JobID, reason); err != nil {
				return err
			}
		}
	}
	if !ready {
		return ErrUnavailable
	}
	return m.ledger.heartbeat(ctx, m.now().UTC())
}

// RunGuard belongs in an independent host process, not the management API.
// A healthy external backend deadline/fence is ALSO required: a Go ticker or
// this process alone is not a hard VM kill guarantee.
func (m *Manager) RunGuard(ctx context.Context) error {
	if !m.backend.Controls().Ready() {
		return ErrUnavailable
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = m.ledger.db.ExecContext(cleanup, "UPDATE guard SET heartbeat_at=0 WHERE id=1")
	}()
	for {
		_ = m.Sweep(ctx) // Failed sweep cannot refresh readiness; retry locally.
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
