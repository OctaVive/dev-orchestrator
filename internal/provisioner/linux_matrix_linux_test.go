//go:build linux

package provisioner

// These tests require separately reviewed, pinned fixtures and root-installed
// binaries. They never run in the ordinary software suite.
import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func matrixBackend(t *testing.T, mode string) *linuxBackend {
	t.Helper()
	base := os.Getenv("M04_MATRIX_ROOT")
	if base == "" || os.Getenv("M04_DISPOSABLE_HOST") != "YES-I-AUTHORIZE-REAL-KVM" {
		t.Skip("reviewed matrix lab not authorized")
	}
	if os.Geteuid() != 0 {
		t.Fatal("installed matrix binary requires root")
	}
	c, e := LoadLinuxConfig(filepath.Join(base, mode, "backend.json"))
	if e != nil {
		t.Fatal(e)
	}
	b, e := NewLinuxBackend(c)
	if e != nil {
		t.Fatal(e)
	}
	return b.(*linuxBackend)
}
func matrixContext(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return c
}
func matrixRead(t *testing.T, p string) string {
	t.Helper()
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	return strings.TrimSpace(string(b))
}
func matrixCG(t *testing.T, m Machine) string {
	t.Helper()
	return filepath.Join("/sys/fs/cgroup/system.slice", unitName(m.Lease.JobID))
}

func matrixID(t *testing.T) string {
	t.Helper()
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	id[6] = (id[6] & 15) | 64
	id[8] = (id[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])
}

// A separate production guard must continue refreshing its private ledger
// while the guest is under pressure. No production service is installed.
func matrixGuard(t *testing.T, b *linuxBackend) *Manager {
	t.Helper()
	mgr, l := matrixManager(t, b, "pressure-guard")
	var seq int
	var name, ledgerPath string
	if err := l.db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &ledgerPath); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(ledgerPath)
	log, err := os.OpenFile(filepath.Join(dir, "guard.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(b.c.Executable, "-mode", "guard", "-backend", "linux-kvm", "-linux-config", filepath.Join(b.c.Root, "backend.json"), "-ledger", ledgerPath)
	cmd.Stdout, cmd.Stderr = log, log
	if err = cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); _ = log.Close() })
	return mgr
}
func matrixMarker(t *testing.T, b *linuxBackend, m Machine, want string, timeout time.Duration) string {
	t.Helper()
	f, e := os.Open(filepath.Join(b.c.Root, m.Lease.JobID+".raw"))
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	end := time.Now().Add(timeout)
	for time.Now().Before(end) {
		var data [512]byte
		_, e = f.ReadAt(data[:], (10<<30)-512)
		if e != nil {
			t.Fatal(e)
		}
		// The fixture record ends at its newline; shorter writes can leave
		// bytes from the prior record later in the same fixed sector.
		s := strings.TrimRight(strings.SplitN(string(data[:]), "\n", 2)[0], "\x00")
		if strings.HasPrefix(s, "M04-FIXTURE "+want) {
			t.Log(s)
			return s
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("fixture marker %q not observed", want)
	return ""
}
func matrixStats(t *testing.T, p string) map[string]int64 {
	t.Helper()
	f := strings.Fields(matrixRead(t, p))
	r := map[string]int64{}
	for i := 0; i+1 < len(f); i += 2 {
		n, e := strconv.ParseInt(f[i+1], 10, 64)
		if e != nil {
			t.Fatal(e)
		}
		r[f[i]] = n
	}
	return r
}
func matrixCleanup(t *testing.T, b *linuxBackend, m Machine) {
	t.Helper()
	r, e := b.Cleanup(matrixContext(t, 20*time.Second), m)
	if e != nil || !r.VMAbsent || !r.ArtifactsAbsent || !r.StartFenced {
		t.Fatalf("cleanup: %+v %v", r, e)
	}
}
func matrixInspect(t *testing.T, b *linuxBackend, m Machine) {
	t.Helper()
	ctx := matrixContext(t, 5*time.Second)
	out, e := hostCommand(ctx, "/usr/bin/systemctl", "show", unitName(m.Lease.JobID), "-p", "MainPID", "--value")
	if e != nil {
		t.Fatal(e)
	}
	pid := strings.TrimSpace(out)
	// Go can fork QEMU from any supervisor thread. The main thread's children
	// file alone does not enumerate the service's processes.
	var children []string
	for _, member := range strings.Fields(matrixRead(t, matrixCG(t, m)+"/cgroup.procs")) {
		if member != pid {
			children = append(children, member)
		}
	}
	if len(children) != 1 {
		t.Fatalf("expected one QEMU child: %v", children)
	}
	q := children[0]
	proc := "/proc/" + q
	status := matrixRead(t, proc+"/status")
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, "Uid:") || strings.HasPrefix(line, "Gid:") || strings.HasPrefix(line, "Groups:") || strings.HasPrefix(line, "CapEff:") {
			t.Log(line)
		}
	}
	for _, line := range strings.Split(status, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "Uid:":
			for _, n := range f[1:] {
				if n != strconv.Itoa(int(b.c.UID)) {
					t.Fatal("QEMU UID", line)
				}
			}
		case "Gid:":
			for _, n := range f[1:] {
				if n != strconv.Itoa(int(b.c.GID)) {
					t.Fatal("QEMU GID", line)
				}
			}
		case "CapEff:":
			if f[1] != "0000000000000000" {
				t.Fatal(line)
			}
		case "Groups:":
			if !strings.Contains(" "+strings.Join(f[1:], " ")+" ", " "+strconv.Itoa(int(b.c.KVMGID))+" ") {
				t.Fatal(line)
			}
		}
	}
	cmd := strings.ReplaceAll(matrixRead(t, proc+"/cmdline"), "\x00", " ")
	t.Log("QEMU", cmd)
	if !strings.Contains(cmd, "accel=kvm") || !strings.Contains(cmd, "-nic none") || !strings.Contains(cmd, "file=/dev/fdset/1,format=raw") {
		t.Fatal("unexpected QEMU command")
	}
	for _, bad := range []string{"tcg", "-virtfs", "-fsdev", "-netdev", "-qmp", "-kernel"} {
		if strings.Contains(cmd, bad) {
			t.Fatal(bad)
		}
	}
	hostnet, _ := os.Readlink("/proc/self/ns/net")
	guestnet, e := os.Readlink(proc + "/ns/net")
	if e != nil || hostnet == guestnet {
		t.Fatal("network namespace", e)
	}
	t.Log("network namespaces", hostnet, guestnet)
	fds, e := os.ReadDir(proc + "/fd")
	if e != nil {
		t.Fatal(e)
	}
	kvm := false
	modes := map[int]bool{}
	disk, e := os.Stat(filepath.Join(b.c.Root, m.Lease.JobID+".raw"))
	if e != nil {
		t.Fatal(e)
	}
	for _, fd := range fds {
		p := proc + "/fd/" + fd.Name()
		target, _ := os.Readlink(p)
		if strings.Contains(target, "kvm") {
			kvm = true
			t.Log("KVM FD", fd.Name(), target)
		}
		st, e := os.Stat(p)
		if e == nil && os.SameFile(st, disk) {
			info := matrixRead(t, proc+"/fdinfo/"+fd.Name())
			for _, line := range strings.Split(info, "\n") {
				if strings.HasPrefix(line, "flags:") {
					n, e := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "flags:")), 8, 64)
					if e != nil {
						t.Fatal(e)
					}
					modes[int(n)&syscall.O_ACCMODE] = true
					t.Log("owned disk FD", fd.Name(), line)
				}
			}
		}
	}
	if !kvm || !modes[os.O_RDONLY] || !modes[os.O_RDWR] {
		t.Fatalf("missing KVM or paired disk modes: %v %v", kvm, modes)
	}
}
func TestMatrixHostV01V02V03BootPinFreshIsolation(t *testing.T) {
	b := matrixBackend(t, "idle")
	ctx := matrixContext(t, 20*time.Second)
	// Inspect preallocation before any guest can write its boot sector.
	pristine := labMachine(t, b, time.Minute)
	now, e := bootNow()
	if e != nil {
		t.Fatal(e)
	}
	boot, e := bootID()
	if e != nil {
		t.Fatal(e)
	}
	s := hostMachine{Machine: pristine, BootID: boot, Deadline: now + int64(time.Minute)}
	if e = b.write(s); e != nil {
		t.Fatal(e)
	}
	if e = b.prepare(ctx, &s); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(filepath.Join(b.c.Root, pristine.Lease.JobID+".raw"))
	if e != nil {
		t.Fatal(e)
	}
	var zero [512]byte
	var got [512]byte
	_, e = f.ReadAt(got[:], (10<<30)-512)
	f.Close()
	if e != nil || got != zero {
		t.Fatal("new disk result sector not pristine", e)
	}
	matrixCleanup(t, b, pristine)
	var old uint64
	// Keep a reference to the unlinked first inode until the second creation;
	// otherwise ext4 may legitimately recycle its inode number immediately.
	var firstDisk *os.File
	defer func() {
		if firstDisk != nil {
			_ = firstDisk.Close()
		}
	}()
	for i := 0; i < 2; i++ {
		m := labMachine(t, b, 90*time.Second)
		labCreate(t, b, m)
		info, e := os.Stat(filepath.Join(b.c.Root, m.Lease.JobID+".raw"))
		if e != nil {
			t.Fatal(e)
		}
		ino := info.Sys().(*syscall.Stat_t).Ino
		if ino == old {
			t.Fatal("disk inode reused across immediate fresh jobs")
		}
		old = ino
		if i == 0 {
			firstDisk, e = os.Open(filepath.Join(b.c.Root, m.Lease.JobID+".raw"))
			if e != nil {
				t.Fatal(e)
			}
		}
		t.Log("fresh disk inode", ino)
		matrixMarker(t, b, m, "BOOT mode=idle runner_pids=512", 30*time.Second)
		matrixInspect(t, b, m)
		ctx := matrixContext(t, 5*time.Second)
		if _, active, err := b.unit(ctx, m); err != nil || !active {
			t.Fatal("owned guest unavailable before stop", err)
		}
		if _, err := hostCommand(ctx, "/usr/bin/systemctl", "stop", unitName(m.Lease.JobID)); err != nil {
			t.Fatal(err)
		}
		if err := confirmGuestGroupEmpty(m.Lease.JobID); err != nil {
			t.Fatal(err)
		}
		matrixMarker(t, b, m, "BOOT mode=idle runner_pids=512", time.Second)
		matrixCleanup(t, b, m)
	}
	bad := matrixBackend(t, "tampered")
	m := labMachine(t, bad, time.Minute)
	err := bad.Create(matrixContext(t, 20*time.Second), m)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered pin: %v", err)
	}
	exists, active, e := bad.unit(context.Background(), m)
	if e != nil || exists || active {
		t.Fatal("tampered image started a unit", e)
	}
	matrixCleanup(t, bad, m)
	t.Log("tampered image rejected before unit creation")
}
func TestMatrixHostV05CPU(t *testing.T) {
	b := matrixBackend(t, "cpu")
	guard := matrixGuard(t, b)
	m := labMachine(t, b, 90*time.Second)
	labCreate(t, b, m)
	matrixMarker(t, b, m, "BOOT mode=cpu runner_pids=512", 25*time.Second)
	cg := matrixCG(t, m)
	before := matrixStats(t, cg+"/cpu.stat")
	start := time.Now()
	for time.Since(start) < 20*time.Second {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, active, e := b.unit(ctx, m)
		caps, guardErr := guard.Capabilities(ctx)
		cancel()
		if e != nil || !active || guardErr != nil || !caps.ExecutionEnabled {
			t.Fatal("control/guard query unresponsive", e, guardErr, caps)
		}
		time.Sleep(time.Second)
	}
	after := matrixStats(t, cg+"/cpu.stat")
	elapsed := time.Since(start).Seconds()
	usage := float64(after["usage_usec"]-before["usage_usec"]) / 1e6
	t.Logf("window=%.3fs CPU=%.3fs throttled_delta=%d", elapsed, usage, after["nr_throttled"]-before["nr_throttled"])
	if usage > elapsed*2*1.1 || after["nr_throttled"] <= before["nr_throttled"] {
		t.Fatal("CPU enforcement failed")
	}
	// Keep the guest for the entire bounded 60-second fixture, in addition to
	// the 20-second measurement window required for the quota calculation.
	matrixMarker(t, b, m, "CPU-DONE", 45*time.Second)
	if caps, err := guard.Capabilities(matrixContext(t, 2*time.Second)); err != nil || !caps.ExecutionEnabled {
		t.Fatal("guard failed during full CPU fixture", err)
	}
	matrixCleanup(t, b, m)
}
func TestMatrixHostV06Memory(t *testing.T) {
	b := matrixBackend(t, "memory")
	guard := matrixGuard(t, b)
	m := labMachine(t, b, 90*time.Second)
	rootBefore := matrixStats(t, "/proc/vmstat")
	labCreate(t, b, m)
	result := matrixMarker(t, b, m, "MEMORY-DONE", 60*time.Second)
	cg := matrixCG(t, m)
	peak, e := strconv.ParseInt(matrixRead(t, cg+"/memory.peak"), 10, 64)
	if e != nil {
		t.Fatal(e)
	}
	swap := matrixRead(t, cg+"/memory.swap.current")
	t.Logf("peak=%d swap=%s result=%s", peak, swap, result)
	if peak > 4831838208 || swap != "0" {
		t.Fatal("memory envelope exceeded")
	}
	if caps, err := guard.Capabilities(matrixContext(t, 2*time.Second)); err != nil || !caps.ExecutionEnabled {
		t.Fatal("guard failed under memory pressure", err)
	}
	events := matrixStats(t, cg+"/memory.events")
	rootAfter := matrixStats(t, "/proc/vmstat")
	if rootAfter["oom_kill"]-rootBefore["oom_kill"] > events["oom_kill"] {
		t.Fatal("OOM outside guest group")
	}
	matrixInspect(t, b, m)
	matrixCleanup(t, b, m)
}
func TestMatrixHostV07DiskIO(t *testing.T) {
	b := matrixBackend(t, "io")
	m := labMachine(t, b, 90*time.Second)
	labCreate(t, b, m)
	result := matrixMarker(t, b, m, "IO-DONE", 65*time.Second)
	if !strings.Contains(result, "beyond_end_status=1 sectors=20971520") {
		t.Fatal("device boundary check", result)
	}
	f, e := os.Open(filepath.Join(b.c.Root, m.Lease.JobID+".raw"))
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	buf := make([]byte, 65536)
	_, e = f.ReadAt(buf, 20971390*512)
	if e != nil {
		t.Fatal(e)
	}
	buf = []byte(strings.TrimRight(string(buf), "\x00"))
	var resultJSON struct {
		Jobs []struct {
			Error int `json:"error"`
			Write struct {
				IOPS    float64 `json:"iops"`
				Runtime int64   `json:"runtime"`
				Total   int64   `json:"total_ios"`
			} `json:"write"`
		} `json:"jobs"`
	}
	if e = json.Unmarshal(buf, &resultJSON); e != nil {
		t.Fatalf("fio JSON: %v", e)
	}
	if len(resultJSON.Jobs) != 1 {
		t.Fatal("unexpected fio jobs")
	}
	j := resultJSON.Jobs[0]
	t.Logf("fio error=%d IOPS=%.3f runtime_ms=%d operations=%d", j.Error, j.Write.IOPS, j.Write.Runtime, j.Write.Total)
	if j.Error != 0 || j.Write.Runtime < 30000 || j.Write.IOPS > 1100 || j.Write.Total == 0 {
		t.Fatal("IO enforcement failed")
	}
	st, e := f.Stat()
	if e != nil {
		t.Fatal(e)
	}
	allocated := st.Sys().(*syscall.Stat_t).Blocks * 512
	t.Logf("virtual=%d physical=%d", st.Size(), allocated)
	if st.Size() != 10<<30 || allocated > 11264<<20 || allocated < 10<<30 {
		t.Fatal("disk envelope")
	}
	matrixCleanup(t, b, m)
}
func TestMatrixHostV08PIDs(t *testing.T) {
	b := matrixBackend(t, "pids")
	m := labMachine(t, b, 90*time.Second)
	labCreate(t, b, m)
	s := matrixMarker(t, b, m, "PIDS", 35*time.Second)
	t.Log(s)
	var count int
	if _, e := fmt.Sscanf(s, "M04-FIXTURE PIDS count=%d", &count); e != nil || count < 1 || count > 512 {
		t.Fatal("runner count exceeded limit or invalid", s, e)
	}
	at := strings.Index(s, "events=max ")
	if at < 0 {
		t.Fatal("missing PID rejection event")
	}
	n, e := strconv.ParseInt(strings.TrimSpace(s[at+len("events=max "):]), 10, 64)
	if e != nil || n < 1 {
		t.Fatal("no rejected fork", e)
	}
	if matrixRead(t, matrixCG(t, m)+"/pids.max") != "128" {
		t.Fatal("host tasks limit")
	}
	t.Log("guest root may override guest-local PID limit; host limit is separate")
	matrixCleanup(t, b, m)
}
func matrixManager(t *testing.T, b *linuxBackend, name string) (*Manager, *Ledger) {
	t.Helper()
	dir := filepath.Join(b.c.Root, name+"-"+matrixID(t))
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	l, e := OpenLedger(context.Background(), filepath.Join(dir, "leases.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	m, e := NewManager(l, b, Config{Templates: []Template{{b.c.TemplateID, b.c.Digest}}})
	if e != nil {
		t.Fatal(e)
	}
	if e = m.Sweep(context.Background()); e != nil {
		t.Fatal(e)
	}
	return m, l
}
func TestMatrixHostV12CleanupCapacity(t *testing.T) {
	b := matrixBackend(t, "idle")
	mgr, l := matrixManager(t, b, "cleanup-ledger")
	req := request(time.Now())
	req.JobID, req.CommandID = matrixID(t), matrixID(t)
	req.ExpiresAt = time.Now().Add(90 * time.Second)
	lease, _, e := mgr.Create(context.Background(), controller, body(t, req))
	if e != nil {
		t.Fatal(e)
	}
	r, e := l.load(context.Background(), lease.JobID)
	if e != nil {
		t.Fatal(e)
	}
	mach := machine(r)
	t.Cleanup(func() { matrixCleanup(t, b, mach) })
	p := filepath.Join(b.c.Root, lease.JobID+".raw")
	saved := p + ".matrix-owned-backup"
	if e = os.Rename(p, saved); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(p, []byte("foreign cleanup canary"), 0600); e != nil {
		os.Rename(saved, p)
		t.Fatal(e)
	}
	// Restore only the exact canary we created, including after assertion failure.
	defer func() {
		data, e := os.ReadFile(p)
		if e == nil && string(data) == "foreign cleanup canary" {
			if e = os.Remove(p); e != nil {
				t.Error(e)
			}
			if e = os.Rename(saved, p); e != nil {
				t.Error(e)
			}
		}
	}()
	if _, e = mgr.Release(context.Background(), controller, lease.JobID); !errors.Is(e, ErrCleanup) {
		t.Fatal("cleanup must quarantine", e)
	}
	r, e = l.load(context.Background(), lease.JobID)
	if e != nil || r.State != CleanupFailed {
		t.Fatal("capacity released", r.State, e)
	}
	other := req
	other.JobID = otherJob
	other.CommandID = otherCommand
	other.Nonce = strings.Repeat("c", 64)
	if _, _, e = mgr.Create(context.Background(), controller, body(t, other)); !errors.Is(e, ErrCapacity) {
		t.Fatal("second admission while cleanup failed", e)
	}
	if matrixRead(t, p) != "foreign cleanup canary" {
		t.Fatal("canary modified")
	}
	if e = os.Remove(p); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(saved, p); e != nil {
		t.Fatal(e)
	}
	if e = mgr.Sweep(context.Background()); e != nil {
		t.Fatal(e)
	}
	r, e = l.load(context.Background(), lease.JobID)
	if e != nil || r.State != Cleaned {
		t.Fatal("recovery cleanup", r.State, e)
	}
	t.Log("failed cleanup retained slot; exact inode restoration and sweep recovered CLEANED")
}
func TestMatrixHostV13ForeignUnit(t *testing.T) {
	b := matrixBackend(t, "idle")
	m := labMachine(t, b, time.Minute)
	ctx := matrixContext(t, 15*time.Second)
	name := unitName(m.Lease.JobID)
	_, e := hostCommand(ctx, "/usr/bin/systemd-run", "--unit="+name, "--description=M04 foreign test canary", "--", "/usr/bin/sleep", "60")
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		_, e := hostCommand(context.Background(), "/usr/bin/systemctl", "stop", name)
		if e != nil {
			t.Error(e)
		}
	}()
	if e = b.Create(ctx, m); !errors.Is(e, ErrConflict) {
		t.Fatal("foreign create", e)
	}
	if _, e = b.Cleanup(ctx, m); !errors.Is(e, ErrConflict) {
		t.Fatal("foreign cleanup", e)
	}
	out, e := hostCommand(ctx, "/usr/bin/systemctl", "show", name, "-p", "ActiveState", "-p", "Description")
	if e != nil || !strings.Contains(out, "ActiveState=active") || !strings.Contains(out, "Description=M04 foreign test canary") {
		t.Fatal("foreign unit changed", out, e)
	}
	t.Log("foreign unit unchanged and still active before exact canary teardown")
}
func TestMatrixHostV14LedgerMetadataSubchecks(t *testing.T) {
	if os.Getenv("M04_MATRIX_V14") != "YES-I-AUTHORIZE-SNAPSHOT-TESTS" {
		t.Skip("V14 skipped by operator: isolated outer-VM snapshot unavailable")
	}
	b := matrixBackend(t, "idle")
	mgr, l := matrixManager(t, b, "unavailable-ledger")
	req := request(time.Now())
	req.JobID, req.CommandID = matrixID(t), matrixID(t)
	req.ExpiresAt = time.Now().Add(15 * time.Second)
	lease, _, e := mgr.Create(context.Background(), controller, body(t, req))
	if e != nil {
		t.Fatal(e)
	}
	r, e := l.load(context.Background(), lease.JobID)
	if e != nil {
		t.Fatal(e)
	}
	m := machine(r)
	t.Cleanup(func() { matrixCleanup(t, b, m) })
	if e = l.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = mgr.Release(context.Background(), controller, lease.JobID); !errors.Is(e, ErrCleanup) {
		t.Fatal("unavailable ledger false CLEANED", e)
	}
	for time.Now().Before(lease.ExpiresAt.Add(5 * time.Second)) {
		_, active, e := b.unit(context.Background(), m)
		if e != nil {
			t.Fatal(e)
		}
		if !active {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, active, e := b.unit(context.Background(), m); e != nil || active {
		t.Fatal("ledger loss prevented expiry", e)
	}
	t.Logf("expired with unavailable ledger, observed lateness=%s", time.Since(lease.ExpiresAt))
	matrixCleanup(t, b, m)
	// An interrupted private .new must never be overwritten or treated as CLEANED.
	n := labMachine(t, b, time.Minute)
	p := b.statePath(n.Lease.JobID) + ".new"
	canary := []byte("interrupted private metadata")
	if e = os.WriteFile(p, canary, 0600); e != nil {
		t.Fatal(e)
	}
	if e = b.Create(context.Background(), n); e == nil {
		t.Fatal("admitted interrupted metadata")
	}
	if _, e = b.Cleanup(context.Background(), n); e == nil {
		t.Fatal("false cleaned interrupted metadata")
	}
	if matrixRead(t, p) != string(canary) {
		t.Fatal("metadata canary modified")
	}
	if e = os.Remove(p); e != nil {
		t.Fatal(e)
	}
	matrixCleanup(t, b, n)
	t.Log("ledger and .new subchecks passed; clock discontinuity and reboot NOT RUN without isolated outer snapshot")
}

func TestMatrixHostV12AllocationFailure(t *testing.T) {
	b := matrixBackend(t, "allocation")
	m := labMachine(t, b, time.Minute)
	// ext4 may consume all free blocks during a failed fallocate. Keep a
	// separately owned recovery reserve; never free an unverified guest file
	// to make room for its durable fence.
	reservePath := filepath.Join(b.c.Root, m.Lease.JobID+".recovery-reserve")
	reserve, err := os.OpenFile(reservePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := reserve.Stat()
	if err != nil {
		reserve.Close()
		t.Fatal(err)
	}
	freeReserve := func() {
		_ = reserve.Close()
		current, err := os.Lstat(reservePath)
		if os.IsNotExist(err) {
			return
		}
		if err != nil || !os.SameFile(owned, current) {
			t.Error("recovery reserve ownership changed")
			return
		}
		if err := os.Remove(reservePath); err != nil {
			t.Error(err)
		}
	}
	defer freeReserve()
	if err := unix.Fallocate(int(reserve.Fd()), 0, 0, 16<<20); err != nil {
		t.Fatal(err)
	}
	e := b.Create(matrixContext(t, 20*time.Second), m)
	if !errors.Is(e, syscall.ENOSPC) {
		t.Fatalf("dedicated small filesystem allocation: %v", e)
	}
	_, active, e := b.unit(context.Background(), m)
	if e != nil || active {
		t.Fatal("allocation failure launched guest", e)
	}
	result, cleanupErr := b.Cleanup(matrixContext(t, 20*time.Second), m)
	if cleanupErr != nil && (result.VMAbsent || result.ArtifactsAbsent || result.StartFenced) {
		t.Fatal("false cleanup confirmation on full filesystem", result, cleanupErr)
	}
	t.Log("initial cleanup on full test filesystem", result, cleanupErr)
	freeReserve()
	matrixCleanup(t, b, m)
	t.Log("dedicated small ext4 filesystem returned ENOSPC; owned partial disk cleaned, OS filesystem not filled")
}

type matrixCrashBackend struct {
	b                 *linuxBackend
	stage, checkpoint string
}

func (b matrixCrashBackend) Controls() Controls { return b.b.Controls() }
func (b matrixCrashBackend) Cleanup(c context.Context, m Machine) (CleanupResult, error) {
	return b.b.Cleanup(c, m)
}
func (b matrixCrashBackend) Create(c context.Context, m Machine) error {
	switch b.stage {
	case "reserve": // Manager has durably reserved and marked STARTING.
	case "allocate":
		now, e := bootNow()
		if e != nil {
			return e
		}
		boot, e := bootID()
		if e != nil {
			return e
		}
		s := hostMachine{Machine: m, BootID: boot, Deadline: now + int64(time.Until(m.Lease.ExpiresAt))}
		l, e := b.b.lock(c)
		if e != nil {
			return e
		}
		e = b.b.write(s)
		if e == nil {
			e = b.b.prepare(c, &s)
		}
		unlock(l)
		if e != nil {
			return e
		}
	case "start":
		if e := b.b.Create(c, m); e != nil {
			return e
		}
	default:
		return ErrInvalid
	}
	if e := os.WriteFile(b.checkpoint, []byte(m.Lease.JobID), 0600); e != nil {
		return e
	}
	time.Sleep(time.Hour) // parent SIGKILLs only this checkpointed test process
	return ErrUnavailable
}
func TestMatrixHostCrashChild(t *testing.T) {
	stage := os.Getenv("M04_MATRIX_CRASH_STAGE")
	if stage == "" {
		t.Skip("crash child only")
	}
	b := matrixBackend(t, "idle")
	dir := os.Getenv("M04_MATRIX_CRASH_DIR")
	if filepath.Dir(dir) != b.c.Root {
		t.Fatal("crash dir outside lab root")
	}
	l, e := OpenLedger(context.Background(), dir+"/leases.db")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	mgr, e := NewManager(l, matrixCrashBackend{b, stage, dir + "/checkpoint"}, Config{Templates: []Template{{b.c.TemplateID, b.c.Digest}}})
	if e != nil {
		t.Fatal(e)
	}
	if e = mgr.Sweep(context.Background()); e != nil {
		t.Fatal(e)
	}
	req := request(time.Now())
	req.JobID = os.Getenv("M04_MATRIX_CRASH_JOB")
	req.ExpiresAt = time.Now().Add(20 * time.Second)
	_, _, e = mgr.Create(context.Background(), controller, body(t, req))
	t.Fatal("crash checkpoint not reached", e)
}
func TestMatrixHostV12CrashRecovery(t *testing.T) {
	b := matrixBackend(t, "idle")
	for _, stage := range []string{"reserve", "allocate", "start"} {
		t.Run(stage, func(t *testing.T) {
			var id [16]byte
			if _, e := rand.Read(id[:]); e != nil {
				t.Fatal(e)
			}
			id[6] = (id[6] & 15) | 64
			id[8] = (id[8] & 63) | 128
			m := Machine{Lease: Lease{JobID: fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])}}
			dir := filepath.Join(b.c.Root, "crash-"+m.Lease.JobID)
			if e := os.Mkdir(dir, 0700); e != nil {
				t.Fatal(e)
			}
			self, e := os.Executable()
			if e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command(self, "-test.run=^TestMatrixHostCrashChild$", "-test.v", "-test.timeout=45s")
			cmd.Env = append(os.Environ(), "M04_MATRIX_CRASH_STAGE="+stage, "M04_MATRIX_CRASH_DIR="+dir, "M04_MATRIX_CRASH_JOB="+m.Lease.JobID)
			log, e := os.OpenFile(dir+"/child.log", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				t.Fatal(e)
			}
			defer log.Close()
			cmd.Stdout = log
			cmd.Stderr = log
			if e = cmd.Start(); e != nil {
				t.Fatal(e)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			defer func() {
				if cmd.ProcessState == nil {
					_ = cmd.Process.Kill()
					<-done
				}
			}()
			end := time.Now().Add(15 * time.Second)
			reached := false
			for time.Now().Before(end) {
				if data, e := os.ReadFile(dir + "/checkpoint"); e == nil && string(data) == m.Lease.JobID {
					reached = true
					break
				}
				select {
				case e := <-done:
					t.Fatal("crash child exited early", e)
				default:
				}
				time.Sleep(100 * time.Millisecond)
			}
			if !reached {
				t.Fatal("child did not reach checkpoint")
			}
			if e = cmd.Process.Kill(); e != nil {
				t.Fatal(e)
			}
			if e = <-done; e == nil {
				t.Fatal("child not killed")
			}
			l, e := OpenLedger(context.Background(), dir+"/leases.db")
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			r, e := l.load(context.Background(), m.Lease.JobID)
			if e != nil || r.State != Starting {
				t.Fatal("durable STARTING record missing", e)
			}
			// Use the child's immutable actual machine/proof, never the canary proof.
			actual := machine(r)
			t.Cleanup(func() { matrixCleanup(t, b, actual) })
			for time.Now().Before(r.ExpiresAt.Add(200 * time.Millisecond)) {
				time.Sleep(100 * time.Millisecond)
			}
			mgr, e := NewManager(l, b, Config{Templates: []Template{{b.c.TemplateID, b.c.Digest}}})
			if e != nil {
				t.Fatal(e)
			}
			if e = mgr.Sweep(context.Background()); e != nil {
				t.Fatal(e)
			}
			r, e = l.load(context.Background(), m.Lease.JobID)
			if e != nil || r.State != Cleaned {
				t.Fatal("crash recovery failed", e)
			}
			t.Log("SIGKILL after", stage, "reopened ledger and reconciled CLEANED", m.Lease.JobID)
		})
	}
}
