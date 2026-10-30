//go:build linux

package provisioner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type linuxBackend struct {
	c LinuxConfig
	// Package-local fault injection, absent in production constructors and
	// unavailable through configuration, CLI or the provisioner RPC.
	networkStage func(string) error
}

// Retain only a bounded diagnostic prefix; continue draining child output so
// excess stderr cannot grow memory or block QEMU. Read only after q.Wait.
type launchDiagnostic struct{ buffer bytes.Buffer }

func (d *launchDiagnostic) Len() int       { return d.buffer.Len() }
func (d *launchDiagnostic) String() string { return d.buffer.String() }

func (d *launchDiagnostic) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := 4096 - d.Len(); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = d.buffer.Write(p)
	}
	return n, nil
}

type hostMachine struct {
	Version      int          `json:",omitempty"`
	CloneVersion int          `json:",omitempty"`
	Network      *hostNetwork `json:",omitempty"`
	Machine      Machine
	BootID       string
	Deadline     int64 // absolute CLOCK_BOOTTIME nanoseconds; never renewed
	Fenced       bool
	DiskDev      uint64
	DiskIno      uint64
	DiskFSUUID   string `json:",omitempty"`
	ReadyDev     uint64
	ReadyIno     uint64
	ReadyFSUUID  string `json:",omitempty"`
}

// FS_IOC_GETFSUUID reads the filesystem's UUID through an existing file FD.
// Unlike st_dev (and XFS statfs.f_fsid), it survives a storage-controller or
// hypervisor change. Linux amd64 UAPI: _IOR(0x15, 0, struct fsuuid2), 17 bytes.
// Older kernels retain the legacy device/inode check rather than guessing.
func fileFilesystemUUID(f *os.File) (string, error) {
	var value [17]byte
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), 0x80111500, uintptr(unsafe.Pointer(&value[0])))
	runtime.KeepAlive(f)
	if errno == unix.ENOTTY || errno == unix.EOPNOTSUPP || errno == unix.ENOSYS {
		return "", nil
	}
	if errno != 0 {
		return "", errno
	}
	if value[0] != 16 || bytes.Equal(value[1:], make([]byte, 16)) {
		return "", ErrUnavailable
	}
	return hex.EncodeToString(value[1:]), nil
}

func sameOwnedFile(dev, ino uint64, fsUUID string, currentDev, currentIno uint64, currentUUID string) bool {
	if ino == 0 || ino != currentIno {
		return false
	}
	if fsUUID == "" {
		return dev == currentDev
	} // legacy: never infer migration
	uuid, err := hex.DecodeString(fsUUID)
	return err == nil && len(uuid) == 16 && !bytes.Equal(uuid, make([]byte, 16)) && fsUUID == currentUUID
}

func verifyOwnedFile(f *os.File, info os.FileInfo, dev, ino uint64, fsUUID string) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ErrConflict
	}
	var currentUUID string
	if fsUUID != "" {
		var err error
		currentUUID, err = fileFilesystemUUID(f)
		if err != nil {
			return fmt.Errorf("%w: read filesystem UUID: %v", ErrUnavailable, err)
		}
	}
	if !sameOwnedFile(dev, ino, fsUUID, uint64(st.Dev), st.Ino, currentUUID) {
		return ErrConflict
	}
	return nil
}

// Every ancestor must be root-owned and not group/world writable. This excludes
// symlinks, user-controlled path replacement and shared writable ancestors.
func trustedPath(path string, private bool) (os.FileInfo, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrInvalid
	}
	var result os.FileInfo
	for p := path; ; p = filepath.Dir(p) {
		i, err := os.Lstat(p)
		if err != nil || i.Mode()&os.ModeSymlink != 0 {
			return nil, ErrUnavailable
		}
		s, ok := i.Sys().(*syscall.Stat_t)
		if !ok || s.Uid != 0 || i.Mode().Perm()&0022 != 0 {
			return nil, ErrUnavailable
		}
		if p == path {
			result = i
			if private && i.Mode().Perm()&0077 != 0 {
				return nil, ErrUnavailable
			}
		}
		if p == "/" {
			break
		}
	}
	return result, nil
}

func loadLinuxConfig(path string) (LinuxConfig, error) {
	i, err := trustedPath(path, true)
	if err != nil || !i.Mode().IsRegular() || i.Size() > 8192 {
		return LinuxConfig{}, ErrInvalid
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return LinuxConfig{}, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var c LinuxConfig
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		return c, ErrInvalid
	}
	return c, nil
}

func validateLinuxConfig(c LinuxConfig) error {
	if c.CloneEnabled && c.NetworkMode != "broker-v1" {
		return ErrInvalid
	}
	if !templateName.MatchString(c.TemplateID) || !templateDigest.MatchString(c.Digest) || c.UID < 100 || c.GID < 100 || c.KVMGID == 0 {
		return ErrInvalid
	}
	// systemd-run's ExecStart serialization must not interpret caller syntax.
	for _, p := range []string{c.Root, c.Image, c.Executable, c.QEMU} {
		if !filepath.IsAbs(p) || strings.ContainsAny(p, " \t\n\r%\\\"'$") {
			return ErrInvalid
		}
	}
	return validateNetworkConfig(c)
}

func newLinuxBackend(c LinuxConfig) (Backend, error) {
	return linuxBackendPreflight(c, true)
}
func newLinuxGuardBackend(c LinuxConfig) (Backend, error) {
	return linuxBackendPreflight(c, false)
}
func linuxBackendPreflight(c LinuxConfig, egressHealth bool) (Backend, error) {
	if os.Geteuid() != 0 || runtime.GOARCH != "amd64" || validateLinuxConfig(c) != nil {
		return nil, ErrUnavailable
	}
	account, e := user.LookupId(strconv.FormatUint(uint64(c.UID), 10))
	if e != nil || account.Username != "orchestrator-qemu" || account.Gid != strconv.FormatUint(uint64(c.GID), 10) {
		return nil, ErrUnavailable
	}
	i, err := trustedPath(c.Root, true)
	if err != nil || !i.IsDir() {
		return nil, ErrUnavailable
	}
	stored, e := loadLinuxConfig(filepath.Join(c.Root, "backend.json"))
	if e != nil || stored != c {
		return nil, ErrUnavailable
	}
	for _, p := range []string{c.Executable, c.QEMU, "/usr/bin/systemd-run", "/usr/bin/systemctl"} {
		i, err = trustedPath(p, false)
		if err != nil || !i.Mode().IsRegular() || i.Mode().Perm()&0111 == 0 {
			return nil, ErrUnavailable
		}
	}
	i, err = trustedPath(c.Image, true)
	if err != nil || !i.Mode().IsRegular() || i.Size() < 512 || i.Size() > 1<<30 {
		return nil, ErrUnavailable
	}
	var fs unix.Statfs_t
	if unix.Statfs(c.Root, &fs) != nil || (fs.Type != unix.EXT4_SUPER_MAGIC && fs.Type != unix.XFS_SUPER_MAGIC) {
		return nil, ErrUnavailable
	}
	if _, err = os.Stat("/run/systemd/system"); err != nil {
		return nil, ErrUnavailable
	}
	b, err := os.ReadFile("/sys/fs/cgroup/cgroup.controllers")
	if err != nil {
		return nil, ErrUnavailable
	}
	for _, controller := range []string{"cpu", "memory", "pids"} {
		if !strings.Contains(" "+strings.TrimSpace(string(b))+" ", " "+controller+" ") {
			return nil, ErrUnavailable
		}
	}
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer f.Close()
	ki, err := f.Stat()
	if err != nil || ki.Sys().(*syscall.Stat_t).Gid != c.KVMGID {
		return nil, ErrUnavailable
	}
	version, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), 0xae00, 0)
	if errno != 0 || version != 12 {
		return nil, ErrUnavailable
	}
	if egressHealth {
		if err := preflightNetwork(c); err != nil {
			return nil, err
		}
	}
	return &linuxBackend{c: c}, nil
}

func (b *linuxBackend) Controls() Controls {
	return Controls{true, true, true, true, true, true, true, true}
}
func bootNow() (int64, error) {
	var t unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &t)
	return t.Nano(), err
}
func bootID() (string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(b)), err
}
func (b *linuxBackend) statePath(job string) string { return filepath.Join(b.c.Root, job+".json") }
func unitName(job string) string                    { return "orchestrator-build-" + job + ".service" }
func ownerDescription(m Machine) string {
	return "orchestrator-build:" + digest([]byte(m.Lease.JobID+":"+m.OwnershipProof))
}

func (b *linuxBackend) lock(ctx context.Context) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(b.c.Root, "host.lock"), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	for {
		if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
			return f, nil
		}
		if err != unix.EWOULDBLOCK {
			f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}
func unlock(f *os.File) {
	if f != nil {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}
}

// OwnershipProof is explicitly serialized here ONLY in the private host journal.
type diskState struct {
	Value hostMachine
	Proof string
}

func (b *linuxBackend) read(job string) (hostMachine, error) {
	p := b.statePath(job)
	if _, err := trustedPath(p, true); err != nil {
		if _, e := os.Lstat(p); os.IsNotExist(e) {
			return hostMachine{}, os.ErrNotExist
		}
		return hostMachine{}, err
	}
	f, err := os.Open(p)
	if err != nil {
		return hostMachine{}, err
	}
	defer f.Close()
	return decodeHostMachine(f)
}

func decodeHostMachine(r io.Reader) (hostMachine, error) {
	var s diskState
	d := json.NewDecoder(io.LimitReader(r, 65537))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil || d.Decode(new(any)) != io.EOF {
		return hostMachine{}, ErrInvalid
	}
	s.Value.Machine.OwnershipProof = s.Proof
	if err := validateNetworkState(s.Value); err != nil {
		return hostMachine{}, err
	}
	return s.Value, nil
}
func (b *linuxBackend) write(s hostMachine) error {
	p := b.statePath(s.Machine.Lease.JobID)
	f, err := os.OpenFile(p+".new", os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(p + ".new")
	err = json.NewEncoder(f).Encode(diskState{s, s.Machine.OwnershipProof})
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(p+".new", p); err != nil {
		return err
	}
	d, err := os.Open(b.c.Root)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func validMachine(m Machine, c LinuxConfig) bool {
	_, err := hex.DecodeString(m.OwnershipProof)
	return identifier.MatchString(m.Lease.JobID) && len(m.OwnershipProof) == 64 && err == nil && m.Budget == SmallBudget() && m.Lease.ProfileID == "build-small-v1" && m.Lease.Template == (Template{c.TemplateID, c.Digest})
}
func sameMachine(a, b Machine) bool {
	return a.Lease.JobID == b.Lease.JobID && a.OwnershipProof == b.OwnershipProof && a.Lease.Template == b.Lease.Template && a.Lease.ExpiresAt.Equal(b.Lease.ExpiresAt) && cloneEqual(a.Clone, b.Clone)
}

func hostCommand(ctx context.Context, path string, args ...string) (string, error) {
	c := exec.CommandContext(ctx, path, args...)
	c.Env = []string{"PATH=/usr/sbin:/usr/bin", "LANG=C", "SYSTEMD_COLORS=0"}
	var out limitedOutput
	c.Stdout = &out
	c.Stderr = &out
	err := c.Run()
	return out.String(), err
}

type limitedOutput struct{ buffer bytes.Buffer }

func (o *limitedOutput) Len() int       { return o.buffer.Len() }
func (o *limitedOutput) String() string { return o.buffer.String() }

func (o *limitedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if o.Len() < 32768 {
		_, _ = o.buffer.Write(p[:min(len(p), 32768-o.Len())])
	}
	return n, nil
}

// Check description before touching any systemd object. Absent units are safe;
// foreign collisions, including inactive units, are never stopped or reset.
func (b *linuxBackend) unit(ctx context.Context, m Machine) (bool, bool, error) {
	return b.namedUnit(ctx, m, unitName(m.Lease.JobID))
}
func (b *linuxBackend) namedUnit(ctx context.Context, m Machine, name string) (bool, bool, error) {
	out, err := hostCommand(ctx, "/usr/bin/systemctl", "show", name, "--property=LoadState,ActiveState,Description")
	if err != nil {
		return false, false, ErrUnavailable
	}
	fields := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(l, "=")
		if ok {
			fields[k] = v
		}
	}
	if fields["LoadState"] == "not-found" {
		return false, false, nil
	}
	if fields["Description"] != ownerDescription(m) {
		return false, false, ErrConflict
	}
	active := fields["ActiveState"]
	if active == "" {
		return false, false, ErrUnavailable
	}
	return true, active != "inactive" && active != "failed", nil
}
func expiryName(job string) string { return "orchestrator-expiry-" + job }

func (b *linuxBackend) Create(ctx context.Context, m Machine) error {
	if !validMachine(m, b.c) {
		return ErrInvalid
	}
	if err := validateCloneMachine(m, b.c, time.Now()); err != nil {
		return err
	}
	if err := preflightNetwork(b.c); err != nil {
		return err
	}
	l, err := b.lock(ctx)
	if err != nil {
		return err
	}
	defer func() { unlock(l) }()
	if _, err = b.read(m.Lease.JobID); !os.IsNotExist(err) {
		return ErrConflict
	}
	if _, err = os.Lstat(filepath.Join(b.c.Root, m.Lease.JobID+".ready")); !os.IsNotExist(err) {
		return ErrConflict
	}
	if exists, _, e := b.unit(ctx, m); e != nil || exists {
		return ErrConflict
	}
	for _, suffix := range []string{".timer", ".service"} {
		if exists, _, e := b.namedUnit(ctx, m, expiryName(m.Lease.JobID)+suffix); e != nil || exists {
			return ErrConflict
		}
	}
	now, err := bootNow()
	if err != nil {
		return err
	}
	boot, err := bootID()
	if err != nil {
		return err
	}
	remaining := time.Until(m.Lease.ExpiresAt)
	if remaining <= 0 || remaining > 30*time.Minute {
		return ErrInvalid
	}
	s := hostMachine{Machine: m, BootID: boot, Deadline: now + int64(remaining)}
	if m.Clone != nil {
		s.CloneVersion = 1
	}
	if err = b.write(s); err != nil {
		return err
	}
	// Do all image/storage work under the same lock as cleanup. Partial disk
	// creation is owned by the durable record and can never be mistaken for clean.
	if err = b.prepare(ctx, &s); err != nil {
		return err
	}
	config := filepath.Join(b.c.Root, "backend.json")
	// A separate PID-1 timer expires this exact owned unit even if the guest
	// supervisor is SIGSTOPed. WakeSystem selects CLOCK_BOOTTIME, not wall time.
	timerArgs := []string{"--quiet", "--unit=" + expiryName(m.Lease.JobID), "--description=" + ownerDescription(m),
		"--on-boot=" + strconv.FormatFloat(float64(s.Deadline)/1e9, 'f', 9, 64) + "s", "--timer-property=WakeSystem=yes", "--timer-property=AccuracySec=1us", "--timer-property=Description=" + ownerDescription(m),
		"--property=Type=exec", "--property=Restart=no", "--", b.c.Executable, "-mode", "host-expire", "-linux-config", config, "-host-job", m.Lease.JobID}
	if _, err = hostCommand(ctx, "/usr/bin/systemd-run", timerArgs...); err != nil {
		return err
	}
	if _, active, e := b.namedUnit(ctx, m, expiryName(m.Lease.JobID)+".timer"); e != nil || !active {
		return ErrUnavailable
	}
	if b.c.NetworkMode == "broker-v1" {
		if err = b.prepareNetwork(ctx, &s); err != nil {
			return err
		}
	}
	if s.Network != nil {
		if err = b.startBroker(ctx, s); err != nil {
			return err
		}
		if err = b.checkpointNetwork("broker-started"); err != nil {
			return err
		}
		// The broker helper validates the durable fence under this same lock.
		unlock(l)
		l = nil
		if err = waitBrokerReady(ctx, b, m); err != nil {
			return err
		}
		l, err = b.lock(ctx)
		if err != nil {
			return err
		}
		current, e := b.read(m.Lease.JobID)
		if e != nil || current.Fenced || !sameMachine(current.Machine, m) {
			return ErrConflict
		}
		if _, active, e := b.namedUnit(ctx, m, brokerUnit(m.Lease.JobID)); e != nil || !active {
			return ErrUnavailable
		}
	}
	remaining = time.Until(m.Lease.ExpiresAt)
	if remaining <= 0 {
		return ErrUnavailable
	}
	args := []string{"--quiet", "--no-block", "--unit=" + unitName(m.Lease.JobID), "--description=" + ownerDescription(m)}
	for _, p := range guestServiceProperties(remaining, s.Network != nil) {
		args = append(args, "--property="+p)
	}
	args = append(args, "--property=ReadWritePaths="+b.c.Root)
	// The root supervisor validates /dev/kvm before dropping QEMU credentials.
	// Its capability bounding set deliberately excludes DAC overrides, so it
	// needs the device's configured group just as the QEMU child does.
	args = append(args, "--property=SupplementaryGroups="+strconv.FormatUint(uint64(b.c.KVMGID), 10))
	args = append(args, "--", b.c.Executable, "-mode", "host-run", "-linux-config", config, "-host-job", m.Lease.JobID)
	if _, err = hostCommand(ctx, "/usr/bin/systemd-run", args...); err != nil {
		return err
	}
	// Release lock before waiting: helper must acquire it to validate the fence.
	unlock(l)
	l = nil
	return waitGuestReady(ctx, func() (bool, error) {
		_, err := os.Stat(filepath.Join(b.c.Root, m.Lease.JobID+".ready"))
		if os.IsNotExist(err) {
			return false, nil
		}
		return err == nil, err
	}, func() (bool, error) {
		_, active, err := b.unit(ctx, m) // verifies ownership before trusting state
		return active, err
	}, unitName(m.Lease.JobID))
}

// systemd-run --no-block acknowledges admission, not successful startup.
// A dead supervisor cannot publish readiness; report it without spending the
// entire operation budget. Activating units remain eligible (ExecStartPre).
func waitGuestReady(ctx context.Context, ready func() (bool, error), active func() (bool, error), unit string) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		ok, err := ready()
		if err != nil {
			return err
		}
		running, err := active()
		if err != nil {
			return err
		}
		if !running {
			return fmt.Errorf("%w: guest unit %s exited before readiness; inspect journalctl -b -u %s", ErrUnavailable, unit, unit)
		}
		if ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func serviceProperties(ttl time.Duration) []string {
	return []string{"Type=exec", "Restart=no", "KillMode=control-group", "TimeoutStopSec=2s", "SendSIGKILL=yes", "RuntimeMaxSec=" + strconv.FormatFloat(ttl.Seconds(), 'f', 3, 64),
		"Slice=system.slice", "CapabilityBoundingSet=CAP_SETUID CAP_SETGID", "RestrictNamespaces=yes", "DevicePolicy=closed", "DeviceAllow=/dev/kvm rw",
		"InaccessiblePaths=/tmp /var/tmp /dev/shm /run/user",
		"CPUQuota=200%", "MemoryMax=4608M", "MemorySwapMax=0", "TasksMax=128", "LimitFSIZE=10737418240", "LimitCORE=0", "OOMPolicy=stop",
		"PrivateNetwork=yes", "PrivateTmp=yes", "ProtectSystem=strict", "ProtectHome=yes", "NoNewPrivileges=yes", "RestrictSUIDSGID=yes", "RestrictRealtime=yes", "LockPersonality=yes", "ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectControlGroups=yes", "ProtectKernelLogs=yes", "RestrictAddressFamilies=AF_UNIX", "UMask=0077", "StandardOutput=null", "StandardError=journal"}
}

func (b *linuxBackend) prepare(ctx context.Context, s *hostMachine) error {
	m := s.Machine
	f, err := os.Open(b.c.Image)
	if err != nil {
		return err
	}
	defer f.Close()
	i, err := f.Stat()
	if err != nil || i.Size() > 1<<30 {
		return ErrInvalid
	}
	p := filepath.Join(b.c.Root, m.Lease.JobID+".raw")
	d, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer d.Close()
	info, err := d.Stat()
	if err != nil {
		return err
	}
	st := info.Sys().(*syscall.Stat_t)
	s.DiskDev = uint64(st.Dev)
	s.DiskIno = st.Ino
	var identityErr error
	s.DiskFSUUID, identityErr = fileFilesystemUUID(d)
	if err = b.write(*s); err != nil {
		return err
	}
	if identityErr != nil {
		return identityErr
	}
	if err = unix.Fallocate(int(d.Fd()), 0, 0, int64(m.Budget.VirtualDiskMiB)<<20); err != nil {
		return err
	}
	h := sha256.New()
	buf := make([]byte, 1<<20)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, e := f.Read(buf)
		if n > 0 {
			if _, err = d.Write(buf[:n]); err != nil {
				return err
			}
			_, _ = h.Write(buf[:n])
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
	}
	if "sha256:"+hex.EncodeToString(h.Sum(nil)) != b.c.Digest {
		return ErrInvalid
	}
	return d.Sync()
}

func (b *linuxBackend) Cleanup(ctx context.Context, m Machine) (CleanupResult, error) {
	if !validMachine(m, b.c) {
		return CleanupResult{}, ErrInvalid
	}
	l, err := b.lock(ctx)
	if err != nil {
		return CleanupResult{}, err
	}
	defer unlock(l)
	s, err := b.read(m.Lease.JobID)
	if os.IsNotExist(err) {
		s = hostMachine{Machine: m, Fenced: true}
		if m.Clone != nil {
			s.CloneVersion = 1
		}
	} else if err != nil || !sameMachine(s.Machine, m) {
		return CleanupResult{}, ErrConflict
	}
	s.Fenced = true
	if err = b.write(s); err != nil {
		return CleanupResult{}, err
	}
	exists, running, err := b.unit(ctx, m)
	if err != nil {
		return CleanupResult{}, err
	}
	if exists && running {
		if _, err = hostCommand(ctx, "/usr/bin/systemctl", "stop", unitName(m.Lease.JobID)); err != nil {
			return CleanupResult{}, err
		}
	}
	_, running, err = b.unit(ctx, m)
	if err != nil || running {
		return CleanupResult{}, ErrCleanup
	}
	if err = confirmGuestGroupEmpty(m.Lease.JobID); err != nil {
		return CleanupResult{}, err
	}
	if err = b.cleanupNetwork(ctx, s); err != nil {
		return CleanupResult{}, err
	}
	for _, suffix := range []string{".timer", ".service"} {
		name := expiryName(m.Lease.JobID) + suffix
		exists, active, e := b.namedUnit(ctx, m, name)
		if e != nil {
			return CleanupResult{}, e
		}
		if exists && active {
			if _, e = hostCommand(ctx, "/usr/bin/systemctl", "stop", name); e != nil {
				return CleanupResult{}, e
			}
		}
		_, active, e = b.namedUnit(ctx, m, name)
		if e != nil || active {
			return CleanupResult{}, ErrCleanup
		}
	}
	// Retain root-owned journal tombstones forever. Never recursively remove a
	// directory or follow a link; only these exact, verified regular files exist.
	for _, suffix := range []string{".raw", ".ready"} {
		p := filepath.Join(b.c.Root, m.Lease.JobID+suffix)
		i, e := trustedPath(p, true)
		if e != nil {
			if _, e = os.Lstat(p); os.IsNotExist(e) {
				continue
			}
			return CleanupResult{}, ErrConflict
		}
		st := i.Sys().(*syscall.Stat_t)
		if !i.Mode().IsRegular() || st.Nlink != 1 {
			return CleanupResult{}, ErrConflict
		}
		dev, ino, fsUUID := s.DiskDev, s.DiskIno, s.DiskFSUUID
		if suffix == ".ready" {
			dev, ino = s.ReadyDev, s.ReadyIno
			fsUUID = s.ReadyFSUUID
		}
		f, e := os.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if e != nil {
			return CleanupResult{}, e
		}
		current, e := f.Stat()
		if e == nil && !os.SameFile(i, current) {
			e = ErrConflict
		}
		if e == nil {
			e = verifyOwnedFile(f, current, dev, ino, fsUUID)
		}
		_ = f.Close()
		if e != nil {
			return CleanupResult{}, e
		}
		if err = os.Remove(p); err != nil {
			return CleanupResult{}, err
		}
	}
	d, err := os.Open(b.c.Root)
	if err != nil {
		return CleanupResult{}, err
	}
	defer d.Close()
	if err = d.Sync(); err != nil {
		return CleanupResult{}, err
	}
	return CleanupResult{true, true, true}, nil
}

func confirmGuestGroupEmpty(job string) error {
	data, err := os.ReadFile(filepath.Join("/sys/fs/cgroup/system.slice", unitName(job), "cgroup.events"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !strings.Contains(string(data), "populated 0\n") {
		return ErrCleanup
	}
	return nil
}

func runLinuxGuest(ctx context.Context, config, job string) error {
	if !identifier.MatchString(job) {
		return ErrInvalid
	}
	c, err := loadLinuxConfig(config)
	if err != nil {
		return err
	}
	backend, err := newLinuxBackend(c)
	if err != nil {
		return err
	}
	b := backend.(*linuxBackend)
	if config != filepath.Join(c.Root, "backend.json") {
		return ErrInvalid
	}
	cgroup, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || !strings.Contains(string(cgroup), "/"+unitName(job)+"\n") {
		return ErrUnavailable
	}
	l, err := b.lock(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if l != nil {
			unlock(l)
		}
	}()
	s, err := b.read(job)
	if err != nil || s.Fenced || !validMachine(s.Machine, c) {
		return ErrConflict
	}
	boot, err := bootID()
	if err != nil || boot != s.BootID {
		return ErrUnavailable
	}
	now, err := bootNow()
	if err != nil || now >= s.Deadline {
		return ErrUnavailable
	}
	// This timer is independent of controller, API, guard, wall clock and Go's
	// scheduler. Its supervisor belongs to the VM's systemd control group: death
	// of the main process causes systemd to kill every remaining guest process.
	timer, err := unix.TimerfdCreate(unix.CLOCK_BOOTTIME, unix.TFD_CLOEXEC)
	if err != nil {
		return err
	}
	defer unix.Close(timer)
	if err = unix.TimerfdSettime(timer, unix.TFD_TIMER_ABSTIME, &unix.ItimerSpec{Value: unix.NsecToTimespec(s.Deadline)}, nil); err != nil {
		return err
	}
	disk, err := os.OpenFile(filepath.Join(c.Root, job+".raw"), os.O_RDWR|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer disk.Close()
	i, err := disk.Stat()
	if err != nil || i.Size() != int64(SmallBudget().VirtualDiskMiB)<<20 || !i.Mode().IsRegular() {
		return ErrInvalid
	}
	if err = verifyOwnedFile(disk, i, s.DiskDev, s.DiskIno, s.DiskFSUUID); err != nil {
		return err
	}
	// QEMU may open an fdset read-only during block initialization even for a
	// writable raw drive. fdset lookup requires an exact access-mode match.
	// Supply both modes, verifying they refer to the same already-owned inode.
	readDisk, err := os.OpenFile(filepath.Join(c.Root, job+".raw"), os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer readDisk.Close()
	readInfo, err := readDisk.Stat()
	if err != nil || !os.SameFile(i, readInfo) {
		return ErrConflict
	}
	q := guestCommand(c, disk, readDisk)
	if s.Network != nil {
		if c.NetworkMode != "broker-v1" || s.Network.PolicyHash != c.EgressPolicyHash {
			return ErrConflict
		}
		if _, active, e := b.namedUnit(ctx, s.Machine, brokerUnit(job)); e != nil || !active {
			return ErrUnavailable
		}
		tap, e := openGuestTAP(s)
		if e != nil {
			return e
		}
		defer tap.Close()
		attachGuestTAP(q, tap)
	}
	var serial *cloneSerial
	if s.Machine.Clone != nil {
		input, e := cloneInputFD(*s.Machine.Clone)
		if e != nil {
			return e
		}
		defer input.Close()
		attachClone(q, input)
		serial = &cloneSerial{}
		q.Stdout = serial
	}
	var diagnostic launchDiagnostic
	q.Stderr = &diagnostic
	if err = q.Start(); err != nil {
		return fmt.Errorf("start guest QEMU: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- q.Wait() }()
	serialStop := make(chan struct{})
	defer close(serialStop)
	if serial != nil {
		go func() {
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-serialStop:
					return
				case <-ctx.Done():
					return
				case <-ticker.C:
					serial.mu.Lock()
					overflow := serial.overflow
					serial.mu.Unlock()
					if overflow {
						_ = q.Process.Kill()
						return
					}

				}
			}
		}()
	}
	deadline := make(chan struct{})
	go func() { var data [8]byte; _, _ = unix.Read(timer, data[:]); close(deadline) }()
	// Ensure QEMU did not immediately reject KVM or a required control.
	select {
	case err = <-done:
		return guestExitError(err, &diagnostic)
	case <-time.After(300 * time.Millisecond):
	}
	ready, err := os.OpenFile(filepath.Join(c.Root, job+".ready"), os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
	if err != nil {
		_ = q.Process.Kill()
		<-done
		return err
	}
	ri, e := ready.Stat()
	if e == nil {
		rs := ri.Sys().(*syscall.Stat_t)
		s.ReadyDev = uint64(rs.Dev)
		s.ReadyIno = rs.Ino
		var identityErr error
		s.ReadyFSUUID, identityErr = fileFilesystemUUID(ready)
		e = b.write(s)
		if e == nil {
			e = identityErr
		}
	}
	if e == nil {
		e = ready.Sync()
	}
	if e == nil && serial != nil {
		e = serial.publish(ready)
	}
	if serial != nil {
		defer ready.Close()
	} else {
		_ = ready.Close()
	}
	if e != nil {
		_ = q.Process.Kill()
		<-done
		return e
	}
	unlock(l)
	l = nil
	select {
	case err = <-done:
		return guestExitError(err, &diagnostic)
	case <-ctx.Done():
	case <-deadline:
	}
	_ = q.Process.Kill()
	<-done
	return nil
}

// Called only after Wait has drained the bounded stderr buffer.
func guestExitError(err error, diagnostic *launchDiagnostic) error {
	if err == nil {
		err = ErrUnavailable // even exit 0 is unexpected before expiry/cancellation
	}
	return fmt.Errorf("guest exited: %w; qemu stderr: %q", err, diagnostic.String())
}

func guestCommand(c LinuxConfig, disk, readDisk *os.File) *exec.Cmd {
	q := exec.Command(c.QEMU, qemuArgs()...)
	q.Env = []string{"PATH=/usr/bin", "LANG=C"}
	// ExtraFiles starts at child FD 3, matching the two fixed -add-fd options.
	q.ExtraFiles = []*os.File{disk, readDisk}
	q.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: c.UID, Gid: c.GID, Groups: []uint32{c.KVMGID}}, Pdeathsig: syscall.SIGKILL}
	return q
}

func qemuArgs() []string {
	return []string{"-no-user-config", "-nodefaults", "-machine", "q35,accel=kvm", "-cpu", "host", "-smp", "2", "-m", "4096", "-display", "none", "-serial", "none", "-monitor", "none", "-nic", "none", "-no-reboot",
		"-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
		"-add-fd", "fd=3,set=1", "-add-fd", "fd=4,set=1", "-drive", "file=/dev/fdset/1,format=raw,if=virtio,cache=writeback,aio=threads,throttling.iops-total=1000"}
}

func expireLinuxGuest(ctx context.Context, config, job string) error {
	if !identifier.MatchString(job) {
		return ErrInvalid
	}
	c, err := loadLinuxConfig(config)
	if err != nil {
		return err
	}
	// Do not require KVM/image/backend health to kill an already admitted guest.
	if os.Geteuid() != 0 || validateLinuxConfig(c) != nil || config != filepath.Join(c.Root, "backend.json") {
		return ErrUnavailable
	}
	b := &linuxBackend{c: c}
	s, err := b.read(job)
	if err != nil {
		return err
	}
	if !validMachine(s.Machine, c) {
		return ErrInvalid
	}
	boot, err := bootID()
	if err != nil {
		return err
	}
	now, err := bootNow()
	if err != nil {
		return err
	}
	if boot == s.BootID && now < s.Deadline {
		return ErrConflict
	}
	if _, active, e := b.unit(ctx, s.Machine); e != nil {
		return e
	} else if active {
		if _, e = hostCommand(ctx, "/usr/bin/systemctl", "kill", "--signal=SIGKILL", "--kill-whom=all", unitName(job)); e != nil {
			return e
		}
		if _, e = hostCommand(ctx, "/usr/bin/systemctl", "stop", unitName(job)); e != nil {
			return e
		}
	}
	// Stop sessions independently of the host-state lock. A paused launcher
	// holding that lock must not keep an already-admitted broker alive.
	if err = b.stopBroker(ctx, s); err != nil {
		return err
	}
	l, err := b.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock(l)
	current, err := b.read(job)
	if err != nil || !sameMachine(current.Machine, s.Machine) {
		return ErrConflict
	}
	current.Fenced = true
	if err = b.write(current); err != nil {
		return err
	}
	if err = b.stopBroker(ctx, current); err != nil {
		return err
	}
	if err = confirmGuestGroupEmpty(job); err != nil {
		return err
	}
	return b.cleanupNetwork(ctx, current)
}
