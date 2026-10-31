// Package runtimehost provisions a finite set of operator-enrolled app engines
// inside a dedicated runtime VM. It is a root oneshot service, not an RPC server.
package runtimehost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/runtimeagent"
	"dev-orchestrator/internal/runtimeisolation"
	"dev-orchestrator/internal/runtimeobservation"
	"golang.org/x/sys/unix"
)

const Root = "/var/lib/tap-runtime"
const RunRoot = "/run/tap-runtime"
const ConfigPath = "/etc/tap-runtime/host.json"

var ToolPaths = []string{"/usr/local/bin/dockerd", "/usr/local/bin/dockerd-rootless.sh", "/usr/local/bin/rootlesskit", "/usr/local/bin/containerd", "/usr/local/bin/tap-runc", "/usr/local/libexec/runc-real", "/usr/bin/systemctl", "/usr/sbin/runuser", "/usr/bin/mount", "/usr/sbin/mkfs.ext4", "/usr/local/bin/tap-runtime-host", "/usr/local/bin/tap-runtime-measure", "/usr/local/bin/tap-runtime-net", "/usr/local/bin/tap-runtime-agent"}

type App struct {
	ID                string `json:"id"`
	MemoryBytes       int64  `json:"memory_bytes"`
	CPUMillis         int    `json:"cpu_millis"`
	PIDs              int    `json:"pids"`
	ImageDiskBytes    int64  `json:"image_disk_bytes"`
	WorkloadDiskBytes int64  `json:"workload_disk_bytes"`
}
type Profile struct {
	Canary       *runtimeobservation.CanaryDescriptor `json:"canary,omitempty"`
	Version      int                                  `json:"version"`
	WorkerID     string                               `json:"worker_id"`
	Incarnation  string                               `json:"incarnation"`
	TemplateHash string                               `json:"template_hash"`
	MACDigest    string                               `json:"mac_digest"`
	MemoryBytes  int64                                `json:"memory_bytes"`
	DiskBytes    int64                                `json:"disk_bytes"`
	CPUMillis    int                                  `json:"cpu_millis"`
	Apps         []App                                `json:"apps"`
	Tools        map[string]string                    `json:"tools"`
}

const DaemonMemory int64 = 128 << 20
const DaemonCPU = 250
const DaemonPIDs = 128

func (p Profile) Valid() bool {
	if p.Version != 1 || !contracts.ValidJobID(p.WorkerID) || !contracts.ValidJobID(p.Incarnation) || !contracts.ValidDigest(p.TemplateHash) || !contracts.ValidDigest(p.MACDigest) || len(p.Apps) < 1 || len(p.Apps) > 16 || p.MemoryBytes < 256<<20 || p.MemoryBytes > 32<<30 || p.DiskBytes < 256<<20 || p.DiskBytes > 256<<30 || p.CPUMillis < 350 || p.CPUMillis > 16000 || len(p.Tools) != len(ToolPaths) {
		return false
	}
	if p.Canary != nil && !p.Canary.Valid() {
		return false
	}
	for _, path := range ToolPaths {
		if !contracts.ValidDigest(p.Tools[path]) {
			return false
		}
	}
	var memory, disk int64
	cpu := 0
	seen := map[string]bool{}
	for _, a := range p.Apps {
		if !contracts.ValidJobID(a.ID) || seen[a.ID] || a.MemoryBytes < 16<<20 || a.MemoryBytes > 8<<30 || a.CPUMillis < 100 || a.CPUMillis > 4000 || a.PIDs < 16 || a.PIDs > 512 || a.ImageDiskBytes < 128<<20 || a.WorkloadDiskBytes < 128<<20 || a.ImageDiskBytes > 10<<30 || a.WorkloadDiskBytes > 10<<30 {
			return false
		}
		seen[a.ID] = true
		memory += a.MemoryBytes + DaemonMemory
		disk += a.ImageDiskBytes + a.WorkloadDiskBytes
		cpu += a.CPUMillis + DaemonCPU
	}
	return memory <= p.MemoryBytes && disk <= p.DiskBytes && cpu <= p.CPUMillis
}
func unit(app string) string { return "tapapp" + strings.ReplaceAll(app, "-", "") }
func (a App) Reservation() runtimeagent.BackendReservation {
	return runtimeagent.BackendReservation{AppID: a.ID, Socket: RunRoot + "/apps/" + a.ID + "/docker.sock", DataRoot: Root + "/apps/" + a.ID + "/engine", DaemonMemory: DaemonMemory, WorkloadMemory: a.MemoryBytes, ImageDisk: a.ImageDiskBytes, WorkloadDisk: a.WorkloadDiskBytes}
}
func (p Profile) Hash() string { raw, _ := json.Marshal(p); return contracts.Digest(raw) }
func privateRoot(path string, perm os.FileMode) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return runtimeagent.ErrDenied
	}
	if err := os.MkdirAll(path, perm); err != nil {
		return runtimeagent.ErrDenied
	}
	for cur := path; ; cur = filepath.Dir(cur) {
		var st unix.Stat_t
		if unix.Lstat(cur, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0022 != 0 {
			return runtimeagent.ErrDenied
		}
		if cur == "/" {
			break
		}
	}
	return nil
}
func Load() (Profile, error) {
	var p Profile
	if err := privateRoot(filepath.Dir(ConfigPath), 0755); err != nil {
		return p, err
	}
	f, err := os.OpenFile(ConfigPath, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return p, runtimeagent.ErrDenied
	}
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&0022 != 0 || st.Size > 65536 {
		return p, runtimeagent.ErrDenied
	}
	p, err = contracts.DecodeConfiguration[Profile](io.LimitReader(f, 65537))
	if err != nil || !p.Valid() {
		return Profile{}, runtimeagent.ErrDenied
	}
	return p, nil
}

// VerifyPolicy checks maintained policy bytes independently of Docker labels.
func (p Profile) VerifyPolicy() error {
	const path = "/etc/apparmor.d/tap-runtime"
	if privateRoot(filepath.Dir(path), 0755) != nil {
		return runtimeagent.ErrUnsupported
	}
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return runtimeagent.ErrUnsupported
	}
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&0022 != 0 || st.Size < 1 || st.Size > 65536 {
		return runtimeagent.ErrUnsupported
	}
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || contracts.Digest(raw) != p.MACDigest {
		return runtimeagent.ErrUnsupported
	}
	return nil
}
func (p Profile) VerifyTools() error {
	if !p.Valid() {
		return runtimeagent.ErrDenied
	}
	for _, path := range ToolPaths {
		// The allowlisted path and any package-managed symlink ancestors must remain
		// root-owned. The final resolved regular executable is hash pinned.
		real, err := filepath.EvalSymlinks(path)
		if err != nil {
			return runtimeagent.ErrUnsupported
		}
		if privateRoot(filepath.Dir(real), 0755) != nil {
			return runtimeagent.ErrUnsupported
		}
		f, err := os.OpenFile(real, os.O_RDONLY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return runtimeagent.ErrUnsupported
		}
		var st unix.Stat_t
		if unix.Fstat(int(f.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&0022 != 0 || st.Size < 1 || st.Size > 256<<20 || st.Mode&0111 == 0 {
			f.Close()
			return runtimeagent.ErrUnsupported
		}
		h := sha256.New()
		_, err = io.Copy(h, f)
		f.Close()
		if err != nil || "sha256:"+hex.EncodeToString(h.Sum(nil)) != p.Tools[path] {
			return runtimeagent.ErrUnsupported
		}
	}
	return nil
}
func command(ctx context.Context, path string, args ...string) error {
	timeout, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(timeout, path, args...)
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if cmd.Run() != nil {
		return runtimeagent.ErrUncertain
	}
	return nil
}
func userSystemd(ctx context.Context, args ...string) error {
	all := []string{"-u", "runtime", "--", "/usr/bin/env", "XDG_RUNTIME_DIR=/run/user/1000", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus", "/usr/bin/systemctl", "--user"}
	all = append(all, args...)
	return command(ctx, "/usr/sbin/runuser", all...)
}
func install(path string, raw []byte, mode os.FileMode) error {
	// Refuse preexisting links and differing operator material; there is no
	// implicit unit replacement during a daemon restart.
	if old, err := os.ReadFile(path); err == nil {
		var st unix.Stat_t
		if unix.Lstat(path, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&0022 != 0 || string(old) != string(raw) {
			return runtimeagent.ErrConflict
		}
		return nil
	} else if !os.IsNotExist(err) {
		return runtimeagent.ErrDenied
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, mode)
	if err != nil {
		return runtimeagent.ErrDenied
	}
	if _, err = f.Write(raw); err != nil || f.Sync() != nil {
		f.Close()
		return runtimeagent.ErrUncertain
	}
	if f.Close() != nil {
		return runtimeagent.ErrUncertain
	}
	return nil
}
func ownedDir(path string) error {
	if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
		return runtimeagent.ErrDenied
	}
	var st unix.Stat_t
	if unix.Lstat(path, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || (st.Uid != 0 && st.Uid != 1000) || (st.Uid == 1000 && st.Mode&0077 != 0) || (st.Uid == 0 && st.Mode&0022 != 0) {
		return runtimeagent.ErrDenied
	}
	if os.Chown(path, 1000, 1000) != nil || os.Chmod(path, 0700) != nil {
		return runtimeagent.ErrDenied
	}
	return nil
}
func provisionDisk(ctx context.Context, a App) error {
	path := Root + "/disks/" + a.ID + ".ext4"
	mount := Root + "/apps/" + a.ID
	size := a.ImageDiskBytes + a.WorkloadDiskBytes
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		// A failed/interrupted provisioning attempt cannot be adopted or reformatted.
		// Existing fully bound engines are handled by Provision before this method.
		return runtimeagent.ErrUncertain
	}
	defer f.Close()
	var fs unix.Statfs_t
	if unix.Statfs(Root+"/disks", &fs) != nil || uint64(fs.Bavail)*uint64(fs.Bsize) < uint64(size)+(128<<20) || unix.Fallocate(int(f.Fd()), 0, 0, size) != nil || f.Sync() != nil {
		return runtimeagent.ErrUncertain
	}
	if command(ctx, "/usr/sbin/mkfs.ext4", "-q", "-F", "-m", "0", "-E", "nodiscard,lazy_itable_init=0,lazy_journal_init=0", path) != nil {
		return runtimeagent.ErrUncertain
	}
	var diskStat unix.Stat_t
	if unix.Fstat(int(f.Fd()), &diskStat) != nil || diskStat.Blocks < size/512 {
		return runtimeagent.ErrUncertain
	}
	if privateRoot(mount, 0700) != nil {
		return runtimeagent.ErrDenied
	}
	if command(ctx, "/usr/bin/mount", "-o", "loop,nodev,nosuid,noatime", "--source", path, "--target", mount) != nil {
		return runtimeagent.ErrUncertain
	}
	if ownedDir(mount) != nil || ownedDir(mount+"/engine") != nil || ownedDir(mount+"/spool") != nil {
		return runtimeagent.ErrUncertain
	}
	return nil
}
func installUnits(a App) error {
	r := a.Reservation()
	name := unit(a.ID)
	slice := fmt.Sprintf("[Unit]\nDescription=Bounded TAP application\n[Slice]\nMemoryMax=%d\nMemorySwapMax=0\nCPUQuota=%d.%d%%\nTasksMax=%d\n", a.MemoryBytes+DaemonMemory, (a.CPUMillis+DaemonCPU)/10, (a.CPUMillis+DaemonCPU)%10, a.PIDs+DaemonPIDs)
	run := RunRoot + "/apps/" + a.ID
	service := fmt.Sprintf(`[Unit]
Description=App-scoped TAP rootless engine
[Service]
Type=simple
Slice=%s.slice
Environment=PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=XDG_RUNTIME_DIR=/run/user/1000
Environment=DOCKERD_ROOTLESS_ROOTLESSKIT_STATE_DIR=%s/rootlesskit
Environment=DOCKERD_ROOTLESS_ROOTLESSKIT_NET=none
Environment=DOCKERD_ROOTLESS_ROOTLESSKIT_PORT_DRIVER=none
Environment=DOCKERD_ROOTLESS_ROOTLESSKIT_DETACH_NETNS=false
Environment=TAP_RUNTIME_APP=%s
ExecStart=/usr/local/bin/dockerd-rootless.sh --config-file=/etc/tap-runtime/daemon.json --rootless --host=unix://%s --data-root=%s --exec-root=%s/exec --pidfile=%s/daemon.pid --storage-driver=native --exec-opt native.cgroupdriver=systemd --cgroup-parent=%s.slice --add-runtime=tap-runc=/usr/local/bin/tap-runc --default-runtime=tap-runc --userland-proxy=false --shutdown-timeout=5
Delegate=yes
Restart=no
TimeoutStopSec=15
`, name, run, a.ID, r.Socket, r.DataRoot, run, run, name)
	for _, suffix := range []string{".service", ".slice"} {
		// User-owned overrides would sever the ownership of these fixed templates.
		if _, err := os.Lstat("/home/runtime/.config/systemd/user/" + name + suffix); !os.IsNotExist(err) {
			return runtimeagent.ErrDenied
		}
	}
	if install("/etc/systemd/user/"+name+".slice", []byte(slice), 0644) != nil || install("/etc/systemd/user/"+name+".service", []byte(service), 0644) != nil {
		return runtimeagent.ErrConflict
	}
	return nil
}

// Provision reserves each slot before disk/unit/daemon side effects. Any failure
// retains its ledger charges and physical artifacts, with no automatic deletion.
func (p Profile) Provision(ctx context.Context) error {
	if os.Geteuid() != 0 || !p.Valid() || p.VerifyTools() != nil || p.VerifyPolicy() != nil {
		return runtimeagent.ErrUnsupported
	}
	for _, path := range []string{Root, Root + "/apps", Root + "/disks", Root + "/enrollments", Root + "/state", RunRoot, RunRoot + "/apps", "/etc/tap-runtime", "/etc/systemd/user"} {
		if privateRoot(path, 0755) != nil {
			return runtimeagent.ErrDenied
		}
	}
	if os.Chmod(Root+"/state", 0700) != nil {
		return runtimeagent.ErrDenied
	}
	l, err := runtimeagent.OpenLedger(ctx, Root+"/state/host.sqlite", p.WorkerID, p.Incarnation)
	if err != nil {
		return err
	}
	defer l.Close()
	if l.PinRuntimeProfile(ctx, p.Hash()) != nil || l.ConfigureBackends(ctx, runtimeagent.BackendCapacity{Apps: len(p.Apps), Memory: p.MemoryBytes, Disk: p.DiskBytes}) != nil {
		return runtimeagent.ErrConflict
	}
	if p.bootstrapAgent(ctx) != nil {
		return runtimeagent.ErrUncertain
	}
	if privateRoot("/run/user", 0755) != nil || ownedDir("/run/user/1000") != nil {
		return runtimeagent.ErrUncertain
	}
	if install("/etc/tap-runtime/daemon.json", []byte(`{"features":{"containerd-snapshotter":true},"log-driver":"local","log-opts":{"max-size":"10m","max-file":"2","compress":"false"}}`), 0644) != nil {
		return runtimeagent.ErrConflict
	}
	if command(ctx, "/usr/bin/systemctl", "start", "user@1000.service") != nil {
		return runtimeagent.ErrUncertain
	}
	for _, a := range p.Apps {
		r := a.Reservation()
		if l.ReserveBackend(ctx, r) != nil {
			return runtimeagent.ErrConflict
		}
		if previous, err := l.Backend(ctx, a.ID); err == nil {
			live, err := runtimeisolation.CollectBackend(ctx, p.WorkerID, p.Incarnation, r)
			if err != nil || live.Backend != previous {
				return runtimeagent.ErrUncertain
			}
			enrolled, err := runtimeisolation.ReadEnrollment(a.ID)
			if err != nil || enrolled.Backend != previous {
				return runtimeagent.ErrUncertain
			}
			continue
		}
		if ownedDir(RunRoot+"/apps/"+a.ID) != nil {
			return fmt.Errorf("runtime_host_slot_directory_denied")
		}
		if provisionDisk(ctx, a) != nil {
			return fmt.Errorf("runtime_host_disk_uncertain")
		}
		if installUnits(a) != nil {
			return fmt.Errorf("runtime_host_units_uncertain")
		}
		if userSystemd(ctx, "daemon-reload") != nil || userSystemd(ctx, "start", unit(a.ID)+".service") != nil {
			return fmt.Errorf("runtime_host_start_uncertain")
		}
		var enrollment runtimeisolation.Enrollment
		wait, cancel := context.WithTimeout(ctx, 45*time.Second)
		for {
			enrollment, err = runtimeisolation.CollectBackend(wait, p.WorkerID, p.Incarnation, r)
			if err == nil {
				break
			}
			select {
			case <-wait.Done():
				cancel()
				return runtimeagent.ErrUncertain
			case <-time.After(250 * time.Millisecond):
			}
		}
		cancel()
		if os.Chmod(r.Socket, 0600) != nil || os.Chmod(r.DataRoot, 0700) != nil || l.BindBackend(ctx, enrollment.Backend) != nil {
			return runtimeagent.ErrUncertain
		}
		raw, err := runtimeisolation.EncodeEnrollment(enrollment)
		if err != nil || install(runtimeisolation.EnrollmentRoot+"/"+a.ID+".json", raw, 0644) != nil {
			return runtimeagent.ErrUncertain
		}
	}
	return nil
}

func (a App) Slice() string          { return unit(a.ID) + ".slice" }
func (a App) DiskBytes() int64       { return a.ImageDiskBytes + a.WorkloadDiskBytes }
func (a App) RunDirectory() string   { return RunRoot + "/apps/" + a.ID }
func (a App) MountDirectory() string { return Root + "/apps/" + a.ID }
func RuntimeUID() string             { return strconv.Itoa(1000) }

// bootstrapAgent writes an external root-owned ledger anchor before transferring
// the fresh private database to the runtime account. Existing anchors never reset
// state; a missing/rolled-back ledger remains an enrollment/reconciliation error.
func (p Profile) bootstrapAgent(ctx context.Context) error {
	path := Root + "/agent/ledger.sqlite"
	if _, err := os.Lstat(runtimeisolation.AgentAnchorPath); err == nil {
		anchor, err := runtimeisolation.ReadAgentEnrollment()
		if err != nil || anchor.WorkerID != p.WorkerID || anchor.Incarnation != p.Incarnation {
			return runtimeagent.ErrUncertain
		}
		var st unix.Stat_t
		if unix.Lstat(path, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 1000 || st.Mode&0077 != 0 {
			return runtimeagent.ErrUncertain
		}
		return nil
	} else if !os.IsNotExist(err) {
		return runtimeagent.ErrUncertain
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return runtimeagent.ErrUncertain
	}
	if privateRoot(Root+"/agent", 0700) != nil {
		return runtimeagent.ErrUncertain
	}
	l, err := runtimeagent.OpenLedger(ctx, path, p.WorkerID, p.Incarnation)
	if err != nil {
		return err
	}
	anchor := runtimeisolation.AgentEnrollment{Version: 1, WorkerID: p.WorkerID, Incarnation: p.Incarnation, LedgerID: l.ID()}
	if l.Close() != nil {
		return runtimeagent.ErrUncertain
	}
	raw, err := json.Marshal(anchor)
	if err != nil || install(runtimeisolation.AgentAnchorPath, raw, 0644) != nil {
		return runtimeagent.ErrUncertain
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if _, err := os.Lstat(path + suffix); err == nil {
			if os.Chown(path+suffix, 1000, 1000) != nil {
				return runtimeagent.ErrUncertain
			}
		} else if !os.IsNotExist(err) {
			return runtimeagent.ErrUncertain
		}
	}
	if os.Chown(Root+"/agent", 1000, 1000) != nil {
		return runtimeagent.ErrUncertain
	}
	return nil
}
