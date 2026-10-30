// Package provisioner is the independent host-side build lease domain. It does
// not import management auth/storage or possess management database authority.
package provisioner

import (
	"context"
	"errors"
	"time"

	"dev-orchestrator/internal/contracts"
)

var (
	ErrInvalid     = errors.New("invalid build lease operation")
	ErrNotFound    = errors.New("build lease not found")
	ErrConflict    = errors.New("build lease command or replay conflict")
	ErrCapacity    = errors.New("build capacity is reserved")
	ErrUnavailable = errors.New("build isolation or watchdog unavailable")
	ErrCleanup     = errors.New("build cleanup is unconfirmed; capacity remains reserved")
	ErrLedger      = errors.New("provisioner ledger operation failed")
	ErrVersion     = errors.New("unsupported provisioner ledger or checksum")
)

type State string

const (
	Reserved       State = "RESERVED"
	Starting       State = "STARTING"
	Active         State = "ACTIVE"
	CleanupPending State = "CLEANUP_PENDING"
	CleanupFailed  State = "CLEANUP_FAILED"
	Cleaned        State = "CLEANED"
)

type Template struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
}

// Immutable profile meaning. A different quota needs a new reviewed profile ID.
type Budget struct {
	VCPUs           int `json:"vcpus"`
	HostCPUMillis   int `json:"host_cpu_millis"`
	MemoryMiB       int `json:"memory_mib"`
	HostMemoryMiB   int `json:"host_memory_mib"`
	VirtualDiskMiB  int `json:"virtual_disk_mib"`
	PhysicalDiskMiB int `json:"physical_disk_mib"`
	DiskIOPS        int `json:"disk_iops"`
	HostPIDs        int `json:"host_pids"`
	GuestPIDs       int `json:"guest_pids"`
}

func SmallBudget() Budget {
	return Budget{VCPUs: 2, HostCPUMillis: 2000, MemoryMiB: 4096, HostMemoryMiB: 4608,
		VirtualDiskMiB: 10240, PhysicalDiskMiB: 11264, DiskIOPS: 1000, HostPIDs: 128, GuestPIDs: 512}
}

// GuestPIDs is runner defense-in-depth, not host-enforceable guest-root process
// isolation. CPU/RAM/disk/time must be enforced externally by a real backend.
type Lease struct {
	JobID        string    `json:"job_id"`
	CommandID    string    `json:"command_id"`
	ControllerID string    `json:"controller_id"`
	AppID        string    `json:"app_id"`
	DeploymentID string    `json:"deployment_id"`
	Template     Template  `json:"template"`
	ProfileID    string    `json:"profile_id"`
	State        State     `json:"state"`
	Version      int64     `json:"version"`
	Reason       string    `json:"reason"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type record struct {
	Lease
	fingerprint string
	nonceHash   string
	proof       string
}

// Machine is a host-internal capability, NEVER a wire response. OwnershipProof
// must be persisted with host artifacts/VM metadata and checked before removal.
// It is not a management credential or guest bootstrap secret.
type Machine struct {
	Lease          Lease
	Budget         Budget
	OwnershipProof string `json:"-"`
	// Host-internal, already-authorized clone intent; never a generic command.
	Clone *contracts.CloneJob `json:",omitempty"`
}

// Controls describe obligations, not proof. A future real backend must have
// Linux integration evidence for every true field before admission is enabled.
type Controls struct {
	PinnedTemplate   bool `json:"pinned_template"`
	KVMIsolation     bool `json:"kvm_isolation"`
	ExternalQuotas   bool `json:"external_quotas"`
	IsolatedNetwork  bool `json:"isolated_network"`
	HostDeadline     bool `json:"host_deadline"`
	LateStartFence   bool `json:"late_start_fence"`
	OwnershipChecks  bool `json:"ownership_checks"`
	ConfirmedCleanup bool `json:"confirmed_cleanup"`
}

func (c Controls) Ready() bool {
	return c.PinnedTemplate && c.KVMIsolation && c.ExternalQuotas && c.IsolatedNetwork && c.HostDeadline &&
		c.LateStartFence && c.OwnershipChecks && c.ConfirmedCleanup
}

type CleanupResult struct {
	VMAbsent        bool
	ArtifactsAbsent bool
	StartFenced     bool
}

// Backend must serialize/fence create and cleanup across processes. Cleanup
// must be safe before/after a partial create, must never remove foreign objects,
// and must prevent any delayed create from starting after cleanup confirmation.
// Returning three true flags is an assertion requiring real host evidence.
type Backend interface {
	Controls() Controls
	Create(context.Context, Machine) error
	Cleanup(context.Context, Machine) (CleanupResult, error)
}

// UnconfiguredBackend is the default backend. Linux KVM requires explicit host
// configuration; there is no simulator or local/container execution fallback.
type UnconfiguredBackend struct{}

func (UnconfiguredBackend) Controls() Controls                    { return Controls{} }
func (UnconfiguredBackend) Create(context.Context, Machine) error { return ErrUnavailable }
func (UnconfiguredBackend) Cleanup(context.Context, Machine) (CleanupResult, error) {
	return CleanupResult{}, ErrUnavailable
}

// CloneBackend extends the owned VM lifecycle with bounded clone results.
type CloneBackend interface {
	Backend
	CloneResults(context.Context, Machine) ([]contracts.CloneResult, error)
}
