package runtimeengine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"time"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/policy"
	"dev-orchestrator/internal/runtimeagent"
	"dev-orchestrator/internal/runtimeisolation"
	"dev-orchestrator/internal/runtimeobservation"
	"golang.org/x/sys/unix"
)

type EnforcementConfig struct {
	WorkerID, Incarnation, TemplateHash, ProfileHash string
	CPUMillis, PIDs                                  int
	Canary                                           runtimeobservation.CanaryDescriptor
}
type MeasuredEnforcement struct {
	client      *Client
	ledger      *runtimeagent.Ledger
	backend     runtimeagent.BackendBinding
	config      EnforcementConfig
	measurement *MeasurementClient
}

func NewMeasuredEnforcement(client *Client, ledger *runtimeagent.Ledger, b runtimeagent.BackendBinding, c EnforcementConfig) (*MeasuredEnforcement, error) {
	if client == nil || ledger == nil || !ledger.Identity(c.WorkerID, c.Incarnation) || !b.Valid() || !contracts.ValidDigest(c.TemplateHash) || !contracts.ValidDigest(c.ProfileHash) || c.CPUMillis < 100 || c.CPUMillis > 4000 || c.PIDs < 16 || c.PIDs > 512 || !c.Canary.Valid() {
		return nil, runtimeagent.ErrUnsupported
	}
	m, err := NewMeasurementClient(b, c.ProfileHash)
	if err != nil {
		return nil, err
	}
	return &MeasuredEnforcement{client, ledger, b, c, m}, nil
}
func (e *MeasuredEnforcement) Close() { e.measurement.Close() }
func (e *MeasuredEnforcement) capacity() runtimeagent.CandidateUsage {
	return runtimeagent.CandidateUsage{Memory: e.backend.WorkloadMemory, CPUMillis: e.config.CPUMillis, PIDs: e.config.PIDs}
}
func (e *MeasuredEnforcement) backendReport(ctx context.Context) (runtimeobservation.Report, error) {
	r, err := e.measurement.Report(ctx, runtimeobservation.Request{Operation: "backend", AppID: e.backend.AppID})
	if err != nil || r.WorkerID != e.config.WorkerID || r.Incarnation != e.config.Incarnation || !r.Backend.NoUplink || r.Backend.DiskBytes != e.backend.ImageDisk+e.backend.WorkloadDisk || r.Backend.PhysicalBytes < r.Backend.DiskBytes || r.Backend.MemoryBytes != e.backend.DaemonMemory+e.backend.WorkloadMemory || r.Backend.CPUMillis < e.config.CPUMillis || r.Backend.PIDs < e.config.PIDs || r.Backend.NetworkNamespace == "" {
		return runtimeobservation.Report{}, runtimeagent.ErrUnsupported
	}
	return r, nil
}
func (e *MeasuredEnforcement) Reserve(ctx context.Context, c runtimeagent.Command) error {
	if c.Spec == nil || c.AppID != e.backend.AppID {
		return runtimeagent.ErrDenied
	}
	var usage runtimeagent.CandidateUsage
	for _, s := range c.Spec.Services {
		if len(s.Volumes) != 0 || len(s.Secrets) != 0 {
			return runtimeagent.ErrUnsupported
		}
		if s.Resources.MemoryBytes < 1 || s.Resources.MemoryBytes > e.backend.WorkloadMemory-usage.Memory || s.Resources.CPUMillis < 1 || s.Resources.CPUMillis > e.config.CPUMillis-usage.CPUMillis || s.Resources.PIDs < 1 || s.Resources.PIDs > e.config.PIDs-usage.PIDs {
			return runtimeagent.ErrUnsupported
		}
		usage.Memory += s.Resources.MemoryBytes
		usage.CPUMillis += s.Resources.CPUMillis
		usage.PIDs += s.Resources.PIDs
	}
	if _, err := e.backendReport(ctx); err != nil {
		return err
	}
	return e.ledger.ReserveCandidate(ctx, c, usage, e.capacity())
}
func (e *MeasuredEnforcement) Network(ctx context.Context, c runtimeagent.Command, id string) error {
	if !objectID.MatchString(id) {
		return runtimeagent.ErrDenied
	}
	var network struct {
		ID       string `json:"Id"`
		Internal bool
		Driver   string
		Labels   map[string]string
	}
	if e.client.call(ctx, "GET", "/networks/"+id, nil, &network) != nil || network.ID != id || !network.Internal || network.Driver != "bridge" || !equal(network.Labels, labels(c, "")) {
		return runtimeagent.ErrDenied
	}
	_, err := e.backendReport(ctx)
	return err
}
func owner(c runtimeagent.Command) string {
	if c.Target != "" {
		return c.Target
	}
	return c.ID
}
func (e *MeasuredEnforcement) Verify(ctx context.Context, c runtimeagent.Command) error {
	if c.AppID != e.backend.AppID {
		return runtimeagent.ErrDenied
	}
	if err := e.inventory(ctx); err != nil {
		return err
	}
	_, err := e.backendReport(ctx)
	return err
}
func (e *MeasuredEnforcement) request(ctx context.Context, c runtimeagent.Command, id string) (runtimeobservation.Request, error) {
	resources, err := e.ledger.Resources(ctx, owner(c))
	if err != nil {
		return runtimeobservation.Request{}, err
	}
	for _, r := range resources {
		if r.Kind != "container" || r.ID != id {
			continue
		}
		var cfg ContainerConfig
		if json.Unmarshal(r.Expected, &cfg) != nil {
			return runtimeobservation.Request{}, runtimeagent.ErrLedger
		}
		uid, gid, err := policy.User(cfg.User)
		if err != nil {
			return runtimeobservation.Request{}, runtimeagent.ErrDenied
		}
		tmp, err := runtimeisolation.TmpfsSize(cfg.HostConfig.Tmpfs["/tmp"])
		if err != nil {
			return runtimeobservation.Request{}, err
		}
		writable, err := runtimeisolation.TmpfsSize(cfg.HostConfig.Tmpfs["/run"])
		if err != nil {
			return runtimeobservation.Request{}, err
		}
		return runtimeobservation.Request{Operation: "container", AppID: c.AppID, ContainerID: id, OwnerID: owner(c), DeploymentID: c.DeploymentID, Generation: c.Generation, SpecHash: c.SpecHash, Service: r.Service, UID: uid, GID: gid, Resources: contracts.Resources{CPUMillis: int(cfg.HostConfig.NanoCpus / 1000000), MemoryBytes: cfg.HostConfig.Memory, PIDs: int(cfg.HostConfig.PidsLimit), TmpBytes: tmp, WritableBytes: writable, LogBytes: 1}}, nil
	}
	return runtimeobservation.Request{}, runtimeagent.ErrDenied
}
func (e *MeasuredEnforcement) VerifyContainer(ctx context.Context, c runtimeagent.Command, id string, pid int) error {
	if pid <= 1 {
		return runtimeagent.ErrDenied
	}
	q, err := e.request(ctx, c, id)
	if err != nil {
		return err
	}
	report, err := e.measurement.Report(ctx, q)
	if err != nil || report.Process == nil || report.Process.UserNamespace != e.backend.UserNamespace || report.Process.UIDMapHash != e.backend.UIDMapHash || report.Process.GIDMapHash != e.backend.GIDMapHash || report.Process.MAC != "tap-runtime (enforce)" || report.Process.Seccomp != 2 || report.Process.TmpBytes > q.Resources.TmpBytes || report.Process.WritableBytes > q.Resources.WritableBytes {
		return runtimeagent.ErrUnsupported
	}
	spec := c.Spec
	if spec == nil {
		if original, err := e.ledger.OriginalTarget(ctx, owner(c)); err == nil {
			spec = original.Spec
		}
	}
	if spec != nil && q.Service == spec.Ingress.Service {
		q.Operation = "relay-start"
		q.Port = spec.Ingress.Port
		q.Path = spec.Ingress.HealthPath
		health, err := e.measurement.Report(ctx, q)
		if err != nil || health.Health == nil || health.Health.Status != 200 {
			return runtimeagent.ErrUnsupported
		}
	}
	return nil
}
func (e *MeasuredEnforcement) Release(ctx context.Context, c runtimeagent.Command) error {
	// A crash can leave an engine effect without a recorded ID. Never release
	// logical capacity while that independently observed uncertainty remains.
	if err := e.inventory(ctx); err != nil {
		return err
	}
	return e.ledger.ReleaseCandidate(ctx, owner(c))
}
func (e *MeasuredEnforcement) importCanary(ctx context.Context, check func() error) error {
	var image struct {
		ID               string `json:"Id"`
		Architecture, Os string
		Config           struct {
			User    string
			Volumes map[string]json.RawMessage
		}
	}
	inspect := func() bool {
		return e.client.call(ctx, "GET", "/images/"+escape(e.config.Canary.ManifestDigest)+"/json", nil, &image) == nil && image.ID == e.config.Canary.ManifestDigest && image.Architecture == "amd64" && image.Os == "linux" && image.Config.User == "1000:1000" && len(image.Config.Volumes) == 0
	}
	if inspect() {
		return check()
	}
	f, err := os.OpenFile(runtimeobservation.CanaryArchive, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return runtimeagent.ErrUnsupported
	}
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0022 != 0 || st.Size != e.config.Canary.Bytes {
		return runtimeagent.ErrUnsupported
	}
	h := sha256.New()
	if _, err = io.Copy(h, io.LimitReader(f, st.Size+1)); err != nil || "sha256:"+hex.EncodeToString(h.Sum(nil)) != e.config.Canary.ArchiveDigest || check() != nil {
		return runtimeagent.ErrUnsupported
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil || e.client.load(ctx, f, st.Size) != nil || !inspect() {
		return runtimeagent.ErrUnsupported
	}
	return check()
}
func (e *MeasuredEnforcement) inventory(ctx context.Context) error {
	owners, err := e.ledger.ResourceOwners(ctx)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, c := range owners {
		if c.AppID != e.backend.AppID {
			continue
		}
		resources, err := e.ledger.Resources(ctx, c.ID)
		if err != nil {
			return err
		}
		for _, r := range resources {
			known[r.ID] = true
		}
	}
	var containers []struct {
		ID string `json:"Id"`
	}
	if e.client.call(ctx, "GET", "/containers/json?all=true", nil, &containers) != nil || len(containers) > 128 {
		return runtimeagent.ErrUnsupported
	}
	for _, c := range containers {
		if !known[c.ID] {
			return runtimeagent.ErrUncertain
		}
	}
	var networks []struct {
		ID   string `json:"Id"`
		Name string
	}
	if e.client.call(ctx, "GET", "/networks", nil, &networks) != nil || len(networks) > 128 {
		return runtimeagent.ErrUnsupported
	}
	for _, n := range networks {
		if n.Name == "bridge" || n.Name == "host" || n.Name == "none" {
			continue
		}
		if !known[n.ID] {
			return runtimeagent.ErrUncertain
		}
	}
	return nil
}

// Measure runs a real owned canary; required controls are never synthesized from
// Docker flags. Cleanup failure, absent private connectivity or failed network
// attempts refuse the entire capability inventory.
func (e *MeasuredEnforcement) Measure(ctx context.Context, c runtimeagent.Command, check func() error) (runtimeagent.Inventory, error) {
	stage := "inventory"
	fail := func() (runtimeagent.Inventory, error) {
		os.Stderr.WriteString("runtime_measure_" + stage + "_denied\n")
		return runtimeagent.Inventory{}, runtimeagent.ErrUnsupported
	}
	if c.AppID != e.backend.AppID || c.WorkerID != e.config.WorkerID || c.Incarnation != e.config.Incarnation || check == nil || check() != nil || e.inventory(ctx) != nil {
		return fail()
	}
	stage = "backend"
	if _, err := e.backendReport(ctx); err != nil {
		return fail()
	}
	canaryUsage := runtimeagent.CandidateUsage{Memory: 64 << 20, CPUMillis: 100, PIDs: 16}
	stage = "capacity"
	if e.ledger.ReserveCandidate(ctx, c, canaryUsage, e.capacity()) != nil {
		return fail()
	}
	stage = "canary_import"
	if e.importCanary(ctx, check) != nil {
		return fail()
	}
	stage = "canary"
	if err := e.runCanary(ctx, c, check); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		return fail()
	}
	stage = "post_canary"
	if _, err := e.backendReport(ctx); err != nil || check() != nil {
		return fail()
	}
	var info struct{ ID, ServerVersion, KernelVersion string }
	if e.client.call(ctx, "GET", "/info", nil, &info) != nil || info.ID != e.backend.DaemonID {
		return fail()
	}
	now := time.Now().UTC()
	return runtimeagent.Inventory{Version: 2, WorkerID: c.WorkerID, Incarnation: c.Incarnation, AppID: c.AppID, BackendHash: e.backend.Hash(), Challenge: c.Nonce, MeasuredAt: now, ExpiresAt: now.Add(time.Minute), TemplateHash: e.config.TemplateHash, Kernel: info.KernelVersion, Engine: info.ServerVersion, API: APIVersion, DaemonID: info.ID, PolicyHash: policy.Hash(), Controls: policy.RequiredControls()}, nil
}

var _ Enforcement = (*MeasuredEnforcement)(nil)

// DropIngress affects only relay children recorded by the fixed root helper for
// exact owned container IDs. No namespace/process/path selector is transmitted.
func (e *MeasuredEnforcement) DropIngress(ctx context.Context, c runtimeagent.Command) error {
	resources, err := e.ledger.Resources(ctx, owner(c))
	if err != nil {
		return err
	}
	for _, r := range resources {
		if r.Kind != "container" {
			continue
		}
		report, err := e.measurement.Report(ctx, runtimeobservation.Request{Operation: "relay-stop", AppID: c.AppID, OwnerID: owner(c), ContainerID: r.ID})
		if err != nil || report.Health == nil || report.Health.Status != 204 {
			return runtimeagent.ErrUncertain
		}
	}
	return nil
}
