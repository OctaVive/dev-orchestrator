//go:build linux

package provisioner

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLinuxCommandPolicy(t *testing.T) {
	args := strings.Join(qemuArgs(), " ")
	for _, required := range []string{"accel=kvm", "-nic none", "-monitor none", "format=raw", "throttling.iops-total=1000", "-add-fd fd=3,set=1", "spawn=deny"} {
		if !strings.Contains(args, required) {
			t.Fatal(required)
		}
	}
	for _, forbidden := range []string{"tcg", "qcow", "-netdev", "-virtfs", "-qmp", "-snapshot", "-kernel"} {
		if strings.Contains(args, forbidden) {
			t.Fatal(forbidden)
		}
	}
	properties := strings.Join(serviceProperties(time.Minute), "\n")
	for _, required := range []string{"CPUQuota=200%", "MemoryMax=4608M", "MemorySwapMax=0", "TasksMax=128", "KillMode=control-group", "PrivateNetwork=yes", "RuntimeMaxSec=60.000", "Restart=no", "LimitFSIZE=10737418240"} {
		if !strings.Contains(properties, required) {
			t.Fatal(required)
		}
	}
}

func TestLinuxConfigRejectsCommandAndIdentityOverrides(t *testing.T) {
	c := LinuxConfig{Root: "/var/lib/orchestrator-builder", Image: "/var/lib/image.raw", Digest: "sha256:" + strings.Repeat("a", 64), TemplateID: "build-linux-v1", Executable: "/usr/local/sbin/orchestrator-provisioner", QEMU: "/usr/bin/qemu-system-x86_64", UID: 991, GID: 991, KVMGID: 108}
	if validateLinuxConfig(c) != nil {
		t.Fatal("valid local configuration refused")
	}
	for _, p := range []string{"relative", "/tmp/a b", "/tmp/%n", "/tmp/$X", "/tmp/a\n"} {
		bad := c
		bad.Executable = p
		if validateLinuxConfig(bad) == nil {
			t.Fatal(p)
		}
	}
	bad := c
	bad.UID = 0
	if validateLinuxConfig(bad) == nil {
		t.Fatal("root guest allowed")
	}
	bad = c
	bad.Digest = "latest"
	if validateLinuxConfig(bad) == nil {
		t.Fatal("unpinned image allowed")
	}
}

func TestLinuxPrivateStateKeepsProofOffWire(t *testing.T) {
	s := hostMachine{Machine: Machine{OwnershipProof: strings.Repeat("a", 64)}, Deadline: 123, Fenced: true}
	b, err := json.Marshal(diskState{s, s.Machine.OwnershipProof})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), s.Machine.OwnershipProof) {
		t.Fatal("private journal lost ownership proof")
	}
	wire, _ := json.Marshal(s.Machine)
	if strings.Contains(string(wire), s.Machine.OwnershipProof) {
		t.Fatal("proof on wire")
	}
}

// These tests execute REAL systemd/KVM actions. They are never enabled by an
// ordinary go test. Compile as a normal user; install/review the binary before
// running it as root on a dedicated disposable Linux host. No simulator exists.
func hostLab(t *testing.T) *linuxBackend {
	t.Helper()
	if os.Getenv("M04_DISPOSABLE_HOST") != "YES-I-AUTHORIZE-REAL-KVM" {
		t.Skip("real host acceptance not authorized")
	}
	path := os.Getenv("M04_HOST_CONFIG")
	if path == "" {
		t.Fatal("M04_HOST_CONFIG missing")
	}
	c, err := LoadLinuxConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewLinuxBackend(c)
	if err != nil {
		t.Fatal(err)
	}
	return b.(*linuxBackend)
}
func labMachine(t *testing.T, b *linuxBackend, ttl time.Duration) Machine {
	t.Helper()
	var id [16]byte
	var proof [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(proof[:]); err != nil {
		t.Fatal(err)
	}
	id[6] = (id[6] & 15) | 64
	id[8] = (id[8] & 63) | 128
	job := fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])
	m := Machine{Lease: Lease{JobID: job, ProfileID: "build-small-v1", Template: Template{b.c.TemplateID, b.c.Digest}, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(ttl)}, Budget: SmallBudget(), OwnershipProof: fmt.Sprintf("%x", proof)}
	t.Logf("owned test job: %s", job)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		r, err := b.Cleanup(ctx, m)
		if err != nil || !r.VMAbsent || !r.ArtifactsAbsent || !r.StartFenced {
			t.Errorf("cleanup %s: %+v %v; retain evidence, do NOT prune", job, r, err)
		}
	})
	return m
}
func labCreate(t *testing.T, b *linuxBackend, m Machine) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := b.Create(ctx, m); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxHostLifecycleAndKernelEnvelope(t *testing.T) {
	b := hostLab(t)
	observe := 0
	if value := os.Getenv("M04_OBSERVE_SECONDS"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 || n > 60 {
			t.Fatal("M04_OBSERVE_SECONDS must be 0..60")
		}
		observe = n
	}
	m := labMachine(t, b, 90*time.Second)
	labCreate(t, b, m)
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	for property, want := range map[string]string{
		"SupplementaryGroups": strconv.FormatUint(uint64(b.c.KVMGID), 10),
		"StandardError":       "journal",
	} {
		out, err := hostCommand(ctx, "/usr/bin/systemctl", "show", unitName(m.Lease.JobID), "--property="+property, "--value")
		if err != nil || strings.TrimSpace(out) != want {
			t.Fatalf("%s: got %q, want %q: %v", property, out, want, err)
		}
		t.Logf("%s=%s", property, strings.TrimSpace(out))
	}
	out, err := hostCommand(ctx, "/usr/bin/systemctl", "show", unitName(m.Lease.JobID), "--property=ControlGroup", "--value")
	if err != nil {
		t.Fatal(err)
	}
	cgroup := strings.TrimSpace(out)
	if !strings.HasPrefix(cgroup, "/system.slice/") {
		t.Fatal(cgroup)
	}
	for file, want := range map[string]string{"memory.max": "4831838208", "memory.swap.max": "0", "pids.max": "128"} {
		data, e := os.ReadFile(filepath.Join("/sys/fs/cgroup", cgroup, file))
		if e != nil || strings.TrimSpace(string(data)) != want {
			t.Fatalf("%s: %s %v", file, data, e)
		}
		t.Logf("%s=%s", file, strings.TrimSpace(string(data)))
	}
	data, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", cgroup, "cpu.max"))
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(data))
	if len(fields) != 2 {
		t.Fatal(string(data))
	}
	quota, e := strconv.ParseInt(fields[0], 10, 64)
	period, e2 := strconv.ParseInt(fields[1], 10, 64)
	if e != nil || e2 != nil || quota != 2*period {
		t.Fatal(string(data))
	}
	t.Logf("cpu.max=%s", data)
	if observe > 0 {
		t.Logf("observe %ds: unit=%s cgroup=%s", observe, unitName(m.Lease.JobID), cgroup)
		time.Sleep(time.Duration(observe) * time.Second)
		f, e := os.Open(filepath.Join(b.c.Root, m.Lease.JobID+".raw"))
		if e != nil {
			t.Fatal(e)
		}
		var marker [512]byte
		_, e = f.ReadAt(marker[:], (int64(SmallBudget().VirtualDiskMiB)<<20)-512)
		_ = f.Close()
		if e != nil {
			t.Fatal(e)
		}
		t.Logf("fixture result sector: %q", strings.TrimRight(string(marker[:]), "\x00"))
		if !strings.HasPrefix(string(marker[:]), "M04-FIXTURE ") {
			t.Fatal("fixture did not prove guest boot")
		}
	}
	if _, err = b.Cleanup(ctx, m); err != nil {
		t.Fatal(err)
	}
	if err = b.Create(ctx, m); err == nil {
		t.Fatal("tombstoned guest resurrected")
	}
	assertEmptyCgroup(t, cgroup)
}
func assertEmptyCgroup(t *testing.T, cgroup string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", cgroup, "cgroup.events"))
	if os.IsNotExist(err) {
		return
	}
	if err != nil || !strings.Contains(string(data), "populated 0") {
		t.Fatalf("guest group still populated: %s %v", data, err)
	}
}

func TestLinuxHostExpiryWithFrozenSupervisor(t *testing.T) {
	b := hostLab(t)
	m := labMachine(t, b, 15*time.Second)
	labCreate(t, b, m)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := hostCommand(ctx, "/usr/bin/systemctl", "show", unitName(m.Lease.JobID), "--property=ControlGroup", "--value")
	if err != nil {
		t.Fatal(err)
	}
	cg := strings.TrimSpace(out)
	if _, err = hostCommand(ctx, "/usr/bin/systemctl", "kill", "--kill-whom=main", "--signal=SIGSTOP", unitName(m.Lease.JobID)); err != nil {
		t.Fatal(err)
	}
	for time.Now().Before(m.Lease.ExpiresAt.Add(5 * time.Second)) {
		_, active, e := b.unit(ctx, m)
		if e != nil {
			t.Fatal(e)
		}
		if !active {
			assertEmptyCgroup(t, cg)
			t.Log("real guest expired with supervisor SIGSTOPed and no API, guard or controller running")
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("independent expiry exceeded deadline + 5s")
}

func TestLinuxHostForeignDiskIsRetained(t *testing.T) {
	b := hostLab(t)
	m := labMachine(t, b, time.Minute)
	p := filepath.Join(b.c.Root, m.Lease.JobID+".raw")
	if err := os.WriteFile(p, []byte("foreign canary"), 0600); err != nil {
		t.Fatal(err)
	}
	// Only this newly created exact canary is removed, before the registered
	// owned-job cleanup runs. Cleanup must first reject it, retaining capacity.
	defer os.Remove(p)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := b.Create(ctx, m); err == nil {
		t.Fatal("foreign disk accepted")
	}
	if _, err := b.Cleanup(ctx, m); err == nil {
		t.Fatal("foreign disk deleted")
	}
	data, err := os.ReadFile(p)
	if err != nil || string(data) != "foreign canary" {
		t.Fatal("canary changed", err)
	}
}

func TestLinuxHostDelayedStartCannotResurrect(t *testing.T) {
	b := hostLab(t)
	m := labMachine(t, b, time.Minute)
	dir := filepath.Join("/run/systemd/system", unitName(m.Lease.JobID)+".d")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "10-m04-test-delay.conf")
	if err := os.WriteFile(p, []byte("[Service]\nExecStartPre=/usr/bin/sleep 10\n"), 0644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	t.Cleanup(func() {
		if err := os.Remove(p); err != nil {
			t.Error(err)
		}
		if err := os.Remove(dir); err != nil {
			t.Error(err)
		}
		c, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := hostCommand(c, "/usr/bin/systemctl", "daemon-reload"); err != nil {
			t.Error(err)
		}
	})
	if _, err := hostCommand(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
		t.Fatal(err)
	}
	createCtx, stopCreate := context.WithCancel(ctx)
	defer stopCreate()
	done := make(chan error, 1)
	go func() { done <- b.Create(createCtx, m) }()
	for {
		_, active, err := b.unit(ctx, m)
		if err != nil {
			t.Fatal(err)
		}
		if active {
			break
		}
		select {
		case err := <-done:
			t.Fatal("create exited before delayed start", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	if _, err := b.Cleanup(ctx, m); err != nil {
		t.Fatal(err)
	}
	stopCreate()
	if err := <-done; err == nil {
		t.Fatal("delayed create falsely succeeded")
	}
	// Explicitly ask PID1 to restart the same owned transient unit, simulating
	// a start arriving after cleanup. The helper must refuse its durable fence.
	_, _ = hostCommand(ctx, "/usr/bin/systemctl", "start", unitName(m.Lease.JobID))
	time.Sleep(12 * time.Second)
	if _, active, err := b.unit(ctx, m); err != nil || active {
		t.Fatal("resurrected unit", active, err)
	}
	if err := confirmGuestGroupEmpty(m.Lease.JobID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(b.c.Root, m.Lease.JobID+".ready")); !os.IsNotExist(err) {
		t.Fatal("resurrected ready marker", err)
	}
}
