//go:build linux

package provisioner

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func networkTestConfig() LinuxConfig {
	return LinuxConfig{Root: "/var/lib/orchestrator-builder/host", Image: "/var/lib/orchestrator-builder/image.raw", Digest: "sha256:" + strings.Repeat("a", 64), TemplateID: "build-linux-v1", Executable: "/usr/local/sbin/orchestrator-provisioner", QEMU: "/usr/bin/qemu-system-x86_64", UID: 991, GID: 991, KVMGID: 108, NetworkMode: "broker-v1", EgressPolicy: "/etc/orchestrator-builder/egress/policy.json", EgressPolicyHash: strings.Repeat("b", 64), EgressCA: "/etc/orchestrator-builder/egress/ca.pem", EgressKey: "/etc/orchestrator-builder/egress/ca-key.pem", EgressCAHash: strings.Repeat("c", 64), EgressResolver: "8.8.8.8:53", BrokerExecutable: "/usr/local/libexec/egress-broker", BrokerUID: 992, BrokerGID: 992}
}
func TestNetworkConfigurationFailsClosed(t *testing.T) {
	c := networkTestConfig()
	if validateLinuxConfig(c) != nil {
		t.Fatal("valid broker configuration")
	}
	for _, change := range []func(*LinuxConfig){
		func(c *LinuxConfig) { c.NetworkMode = "bridge" }, func(c *LinuxConfig) { c.NetworkMode = "none" }, func(c *LinuxConfig) { c.BrokerUID = c.UID }, func(c *LinuxConfig) { c.BrokerUID = 0 }, func(c *LinuxConfig) { c.EgressPolicyHash = "latest" }, func(c *LinuxConfig) { c.EgressCAHash = "" }, func(c *LinuxConfig) { c.EgressResolver = "resolver.example:53" }, func(c *LinuxConfig) { c.EgressResolver = "8.8.8.8:443" }, func(c *LinuxConfig) { c.BrokerExecutable = "/tmp/%n" }, func(c *LinuxConfig) { c.EgressKey = "relative" },
	} {
		bad := c
		change(&bad)
		if validateLinuxConfig(bad) == nil {
			t.Fatal("unsafe network configuration accepted", bad.NetworkMode)
		}
	}
}
func TestNetworkManifestVersionAndIdentity(t *testing.T) {
	s := hostMachine{Machine: Machine{OwnershipProof: strings.Repeat("a", 64)}}
	if validateNetworkState(s) != nil {
		t.Fatal("legacy no-NIC rejected")
	}
	s.Version = 2
	if validateNetworkState(s) == nil {
		t.Fatal("future version accepted")
	}
	s.Version = 1
	s.Network = &hostNetwork{Version: 1, Namespace: networkName(s.Machine), PolicyHash: strings.Repeat("b", 64)}
	if validateNetworkState(s) != nil {
		t.Fatal("planned namespace rejected")
	}
	s.Network.Enforced = true
	if validateNetworkState(s) == nil {
		t.Fatal("unowned enforcement accepted")
	}
	s.Network.Ino = 12
	if validateNetworkState(s) != nil {
		t.Fatal("owned state rejected")
	}
	s.Network.Namespace = "foreign"
	if validateNetworkState(s) == nil {
		t.Fatal("foreign namespace accepted")
	}
	s.Network.Namespace = networkName(s.Machine)
	s.Network.Removed = true
	if validateNetworkState(s) == nil {
		t.Fatal("unfenced removal accepted")
	}
	s.Fenced = true
	if validateNetworkState(s) != nil {
		t.Fatal("cleanup tombstone rejected")
	}
	b, _ := json.Marshal(s)
	var roundtrip hostMachine
	if json.Unmarshal(b, &roundtrip) != nil {
		t.Fatal("round trip")
	}
}
func TestNamespaceOwnershipRejectsForeignFile(t *testing.T) {
	// No privileged commands: checking a missing or foreign namespace must fail
	// before setns or any mutation. Collision identity cannot be guessed.
	n := &hostNetwork{Version: 1, Namespace: "tap-absent-unit-test", Dev: 123, Ino: 456}
	if verifyNamespace(n) == nil {
		t.Fatal("missing namespace accepted")
	}
	called := false
	if inNamespace(n, func() error { called = true; return nil }) == nil || called {
		t.Fatal("entered unowned namespace")
	}
}
func TestNetworkQEMUDescriptorAndPrivilegeBoundary(t *testing.T) {
	c := networkTestConfig()
	disk, e := os.CreateTemp(t.TempDir(), "disk")
	if e != nil {
		t.Fatal(e)
	}
	defer disk.Close()
	tap, e := os.CreateTemp(t.TempDir(), "tap")
	if e != nil {
		t.Fatal(e)
	}
	defer tap.Close()
	q := guestCommand(c, disk, disk)
	attachGuestTAP(q, tap)
	if len(q.ExtraFiles) != 3 || q.ExtraFiles[2] != tap {
		t.Fatal("TAP not inherited as fd 5")
	}
	args := strings.Join(q.Args, " ")
	if strings.Contains(args, "-nic none") || strings.Contains(args, "script=") || strings.Contains(args, "helper=") || !strings.Contains(args, "tap,id=egress,fd=5") || !strings.Contains(args, "mac="+guestMAC) {
		t.Fatal("unsafe QEMU network command", args)
	}
	if q.SysProcAttr.Credential.Uid != c.UID || q.SysProcAttr.Credential.Gid != c.GID || len(q.SysProcAttr.AmbientCaps) != 0 {
		t.Fatal("network privileges passed to QEMU")
	}
	props := strings.Join(guestServiceProperties(time.Minute, true), "\n")
	if !strings.Contains(props, "PrivateNetwork=yes") || !strings.Contains(props, "RestrictAddressFamilies=AF_UNIX") || !strings.Contains(props, "DeviceAllow=/dev/net/tun rw") {
		t.Fatal("launcher isolation weakened")
	}
}
func TestNetworkStateUnknownVersionRejectedOnRead(t *testing.T) {
	for _, data := range []string{`{"Value":{"Version":99},"Proof":""}`, `{"Value":{"Version":1,"Network":{"Version":99}},"Proof":""}`} {
		if _, e := decodeHostMachine(strings.NewReader(data)); e == nil {
			t.Fatal("unknown manifest accepted")
		}
	}
	if _, e := decodeHostMachine(strings.NewReader(`{"Value":{"Version":99},"Proof":""}`)); !errors.Is(e, ErrVersion) {
		t.Fatal("version error lost", e)
	}
	if _, e := decodeHostMachine(strings.NewReader(`{"Value":{},"Proof":""}`)); e != nil {
		t.Fatal("legacy journal rejected", e)
	}
}

// Real network+KVM tests are deliberately opt-in, never simulated. The installed
// template must contain the public build CA and the network probe runner.
func TestRealBrokerNetworkLifecycle(t *testing.T) {
	if os.Getenv("M05_DISPOSABLE_HOST") != "YES-I-AUTHORIZE-REAL-NETWORK" {
		t.Skip("requires approved disposable KVM/network lab")
	}
	b := hostLab(t)
	if b.c.NetworkMode != "broker-v1" {
		t.Fatal("broker-v1 configuration required")
	}
	var otherCapture *labCapture
	captureDir := os.Getenv("M05_CAPTURE_DIR")
	if captureDir != "" {
		other := labMachine(t, b, 2*time.Minute)
		otherState := hostMachine{Machine: other}
		lock, e := b.lock(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		e = b.prepareNetwork(context.Background(), &otherState)
		unlock(lock)
		if e != nil {
			t.Fatal(e)
		}
		defer func() {
			if otherCapture != nil {
				otherCapture.stop()
			}
			if _, e := b.Cleanup(context.Background(), other); e != nil {
				t.Error(e)
			}
		}()
		otherCapture = startLabCapture(t, otherState.Network, filepath.Join(captureDir, "other-job.pcap"), false)
	}
	var currentCaptureJob string
	var guestCapture, hostCapture *labCapture
	if captureDir != "" {
		hostCapture = startLabCapture(t, nil, filepath.Join(captureDir, "host.pcap"), true)
		b.networkStage = func(stage string) error {
			if stage == "enabled" {
				record, e := b.read(currentCaptureJob)
				if e != nil {
					return e
				}
				guestCapture = startLabCapture(t, record.Network, filepath.Join(captureDir, "guest.pcap"), false)
			}
			return nil
		}
		defer func() {
			if guestCapture != nil {
				guestCapture.stop()
			}
			if hostCapture != nil {
				hostCapture.stop()
			}
		}()
	}
	m := labMachine(t, b, 2*time.Minute)
	currentCaptureJob = m.Lease.JobID
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	defer func() {
		if _, e := b.Cleanup(context.Background(), m); e != nil {
			t.Error("cleanup unconfirmed", e)
		}
	}()
	if e := b.Create(ctx, m); e != nil {
		t.Fatal(e)
	}
	s, e := b.read(m.Lease.JobID)
	if e != nil || s.Network == nil || !s.Network.Enforced {
		t.Fatal("missing durable enforced ownership", e)
	}
	if e = verifyNamespace(s.Network); e != nil {
		t.Fatal(e)
	}
	if e = waitBrokerReady(ctx, b, m); e != nil {
		t.Fatal(e)
	}
	n := s.Network.Namespace
	// Read only the fixture's fixed bounded export region; never mount or
	// interpret a guest filesystem. Missing/incorrect observations fail smoke.
	disk, e := os.Open(filepath.Join(b.c.Root, m.Lease.JobID+".raw"))
	if e != nil {
		t.Fatal(e)
	}
	defer disk.Close()
	observed := false
	brokerStopped := false
	for !observed {
		if canaryLog := os.Getenv("M05_CANARY_LOG"); canaryLog != "" && !brokerStopped {
			data, e := os.ReadFile(canaryLog)
			if e == nil && strings.Contains(string(data), `"path": "/broker-stop-trigger"`) {
				if e = b.stopBroker(ctx, s); e != nil {
					t.Fatal(e)
				}
				brokerStopped = true
			}
		}
		marker := make([]byte, 512)
		if _, e = disk.ReadAt(marker, 20971519*512); e != nil {
			t.Fatal(e)
		}
		if strings.Contains(string(marker), "M05-NETWORK-DONE") {
			observed = true
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("fixture did not finish", ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
	report := make([]byte, 128*512)
	if _, e = disk.ReadAt(report, 20971390*512); e != nil {
		t.Fatal(e)
	}
	text := strings.TrimRight(string(report), "\x00")
	if strings.Contains(text, "UNEXPECTED-") || !strings.Contains(text, "N01-approved OBSERVED-ALLOW") || !strings.Contains(text, "N05-recovered OBSERVED-ALLOW") {
		t.Fatalf("guest probe observations: %q", text)
	}
	t.Logf("guest observations (not capture-based acceptance): %q", text)
	if captureDir != "" {
		rules, e := hostCommand(ctx, "/usr/bin/ip", "netns", "exec", s.Network.Namespace, "/usr/sbin/nft", "-j", "list", "ruleset")
		if e != nil {
			t.Fatal(e)
		}
		drops := labIngressDrops(rules)
		guestCapture.stop()
		hostCapture.stop()
		writeCaptureSummary(t, captureDir, guestCapture, hostCapture, drops)
		otherCapture.stop()
		if otherCapture.summary["frames"] != 0 || otherCapture.err != nil || otherCapture.summary["capture_drops"] != 0 {
			t.Fatal("cross-job traffic or incomplete canary capture", otherCapture.summary, otherCapture.err)
		}
		otherData, _ := json.Marshal(otherCapture.summary)
		if e = os.WriteFile(filepath.Join(captureDir, "other-job-summary.json"), otherData, 0600); e != nil {
			t.Fatal(e)
		}
		if guestCapture.summary["frames"] == 0 || hostCapture.summary["frames"] == 0 || hostCapture.summary["guest_frames_on_host"] != 0 || hostCapture.summary["protected_destination_frames"] != 0 || drops < 24 {
			t.Fatal("capture/counter isolation evidence failed", guestCapture.summary, hostCapture.summary, drops)
		}
		// stop is idempotent only at this call site: disable the deferred closure.
		guestCapture = nil
		hostCapture = nil
	}
	result, e := b.Cleanup(ctx, m)
	if e != nil || !result.VMAbsent || !result.ArtifactsAbsent || !result.StartFenced {
		t.Fatal("incomplete cleanup", e)
	}
	if _, e = os.Lstat("/run/netns/" + n); !os.IsNotExist(e) {
		t.Fatal("namespace remains")
	}
	exists, active, e := b.namedUnit(ctx, m, brokerUnit(m.Lease.JobID))
	if e != nil || exists && active {
		t.Fatal("broker remains", e)
	}
	if e = b.Create(ctx, m); e == nil {
		t.Fatal("delayed/replayed start accepted")
	}
}

func TestRealBrokerIndependentExpiry(t *testing.T) {
	if os.Getenv("M05_DISPOSABLE_HOST") != "YES-I-AUTHORIZE-REAL-NETWORK" {
		t.Skip("requires approved disposable KVM/network lab")
	}
	b := hostLab(t)
	if b.c.NetworkMode != "broker-v1" {
		t.Fatal("broker mode required")
	}
	m := labMachine(t, b, 20*time.Second)
	controlledLeaseMode(t, "expiry", m.Lease.JobID)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	defer func() {
		if _, e := b.Cleanup(context.Background(), m); e != nil {
			t.Error("cleanup", e)
		}
	}()
	if e := b.Create(ctx, m); e != nil {
		t.Fatal(e)
	}
	s, e := b.read(m.Lease.JobID)
	if e != nil {
		t.Fatal(e)
	}
	// Freeze both supervisors. The PID-1 expiry timer must terminate all of
	// their descendants without controller/API/guard activity or Go timers.
	for _, unit := range []string{unitName(m.Lease.JobID), brokerUnit(m.Lease.JobID)} {
		if _, _, e = b.namedUnit(ctx, m, unit); e != nil {
			t.Fatal(e)
		}
		if _, e = hostCommand(ctx, "/usr/bin/systemctl", "kill", "--signal=SIGSTOP", "--kill-whom=main", unit); e != nil {
			t.Fatal(e)
		}
	}
	for {
		current, e := b.read(m.Lease.JobID)
		if e != nil {
			t.Fatal(e)
		}
		if current.Fenced && current.Network.Removed {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("independent expiry did not fence/remove namespace", ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
	for _, unit := range []string{unitName(m.Lease.JobID), brokerUnit(m.Lease.JobID)} {
		if _, active, e := b.namedUnit(ctx, m, unit); e != nil || active {
			t.Fatal("expired service remains", unit, e)
		}
		if e := confirmServiceGroupEmpty(unit); e != nil {
			t.Fatal("expired cgroup remains", e)
		}
	}
	if _, e = os.Lstat(namespacePath(s.Network)); !os.IsNotExist(e) {
		t.Fatal("expired namespace remains")
	}
	waitLabStream(t, ctx, m.Lease.JobID, "http")
	waitLabStream(t, ctx, m.Lease.JobID, "stream-interrupted")
}

// Checkpoints exist only as a package-private function field; no environment,
// request or production command can activate one. The subprocess exits without
// unwinding, modelling loss of the provisioner at each setup boundary.
func TestRealBrokerSetupCrashRecovery(t *testing.T) {
	if os.Getenv("M05_DISPOSABLE_HOST") != "YES-I-AUTHORIZE-REAL-NETWORK" {
		t.Skip("requires approved disposable KVM/network lab")
	}
	if input := os.Getenv("M05_CRASH_INPUT"); input != "" {
		data, e := os.ReadFile(input)
		if e != nil {
			t.Fatal(e)
		}
		var journal diskState
		if e = json.Unmarshal(data, &journal); e != nil {
			t.Fatal(e)
		}
		c, e := LoadLinuxConfig(os.Getenv("M04_HOST_CONFIG"))
		if e != nil {
			t.Fatal(e)
		}
		m := journal.Value.Machine
		m.OwnershipProof = journal.Proof
		b := &linuxBackend{c: c}
		stage := os.Getenv("M05_CRASH_STAGE")
		b.networkStage = func(current string) error {
			if current == "namespace-created" {
				i, e := os.Lstat(namespacePath(&hostNetwork{Namespace: networkName(m)}))
				if e != nil {
					t.Fatal(e)
				}
				st := i.Sys().(*syscall.Stat_t)
				witness, _ := json.Marshal(hostNetwork{Dev: uint64(st.Dev), Ino: st.Ino})
				if e = os.WriteFile(input+".witness", witness, 0600); e != nil {
					t.Fatal(e)
				}
			}
			if current == stage {
				os.Exit(77)
			}
			return nil
		}
		if e = b.Create(context.Background(), m); e != nil {
			t.Fatal(e)
		}
		t.Fatal("checkpoint did not terminate child")
	}
	b := hostLab(t)
	if b.c.NetworkMode != "broker-v1" {
		t.Fatal("broker mode required")
	}
	for _, stage := range []string{"intent", "namespace-created", "identity", "tap", "firewall", "enabled", "broker-started"} {
		t.Run(stage, func(t *testing.T) {
			m := labMachine(t, b, 2*time.Minute)
			// Keep the input and creation witness private under the trusted lab root.
			input := filepath.Join(b.c.Root, m.Lease.JobID+".crash-input")
			data, _ := json.Marshal(diskState{Value: hostMachine{Machine: m}, Proof: m.OwnershipProof})
			if e := os.WriteFile(input, data, 0600); e != nil {
				t.Fatal(e)
			}
			self, e := os.Executable()
			if e != nil {
				t.Fatal(e)
			}
			child := exec.Command(self, "-test.run=^TestRealBrokerSetupCrashRecovery$")
			child.Env = append(os.Environ(), "M05_CRASH_INPUT="+input, "M05_CRASH_STAGE="+stage)
			out, e := child.CombinedOutput()
			exit, ok := e.(*exec.ExitError)
			if !ok || exit.ExitCode() != 77 {
				t.Fatalf("crash stage exit: %v %q", e, out)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			_, e = b.Cleanup(ctx, m)
			if stage == "namespace-created" {
				if !errors.Is(e, ErrCleanup) {
					t.Fatal("uncertain namespace ownership was not retained", e)
				}
				s, readErr := b.read(m.Lease.JobID)
				if readErr != nil {
					t.Fatal(readErr)
				}
				witnessData, readErr := os.ReadFile(input + ".witness")
				if readErr != nil {
					t.Fatal(readErr)
				}
				var witness hostNetwork
				if e = json.Unmarshal(witnessData, &witness); e != nil {
					t.Fatal(e)
				}
				// Lab-only explicit recovery from the child-created private witness. The
				// production cleanup never guesses this missing identity from a name.
				witness.Namespace = s.Network.Namespace
				if e = verifyNamespace(&witness); e != nil {
					t.Fatal(e)
				}
				s.Network.Dev = witness.Dev
				s.Network.Ino = witness.Ino
				if e = b.write(s); e != nil {
					t.Fatal(e)
				}
				_, e = b.Cleanup(ctx, m)
			}
			if e != nil {
				t.Fatal("reconciliation failed", e)
			}
			if _, e = os.Lstat(namespacePath(&hostNetwork{Namespace: networkName(m)})); !os.IsNotExist(e) {
				t.Fatal("namespace remains")
			}
			if e = b.Create(ctx, m); !errors.Is(e, ErrConflict) {
				t.Fatal("late start was not fenced", e)
			}
		})
	}
}

func TestRealBrokerForeignNetworkPreserved(t *testing.T) {
	if os.Getenv("M05_DISPOSABLE_HOST") != "YES-I-AUTHORIZE-REAL-NETWORK" {
		t.Skip("requires approved disposable KVM/network lab")
	}
	b := hostLab(t)
	if b.c.NetworkMode != "broker-v1" {
		t.Fatal("broker mode required")
	}
	m := labMachine(t, b, 2*time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s := hostMachine{Machine: m}
	lock, e := b.lock(ctx)
	if e != nil {
		t.Fatal(e)
	}
	e = b.prepareNetwork(ctx, &s)
	unlock(lock)
	if e != nil {
		t.Fatal(e)
	}
	if e = verifyNamespace(s.Network); e != nil {
		t.Fatal(e)
	}
	// Explicitly replace the just-created lab namespace with a foreign canary
	// under the same name. Cleanup must preserve it, not infer ownership by name.
	if _, e = hostCommand(ctx, "/usr/bin/ip", "netns", "delete", s.Network.Namespace); e != nil {
		t.Fatal(e)
	}
	if _, e = hostCommand(ctx, "/usr/bin/ip", "netns", "add", s.Network.Namespace); e != nil {
		t.Fatal(e)
	}
	info, e := os.Lstat(namespacePath(s.Network))
	if e != nil {
		t.Fatal(e)
	}
	st := info.Sys().(*syscall.Stat_t)
	foreign := &hostNetwork{Namespace: s.Network.Namespace, Dev: uint64(st.Dev), Ino: st.Ino}
	defer func() {
		if e := verifyNamespace(foreign); e == nil {
			if _, e = hostCommand(context.Background(), "/usr/bin/ip", "netns", "delete", foreign.Namespace); e != nil {
				t.Error(e)
			}
		}
		if _, e := b.Cleanup(context.Background(), m); e != nil {
			t.Error(e)
		}
	}()
	if foreign.Ino == s.Network.Ino && foreign.Dev == s.Network.Dev {
		t.Fatal("canary inode unexpectedly reused")
	}
	if e = namespaceCommand(ctx, foreign, "add table inet m05_foreign\nadd chain inet m05_foreign marker\n", "/usr/sbin/nft", "-f", "-"); e != nil {
		t.Fatal(e)
	}
	before, e := hostCommand(ctx, "/usr/bin/ip", "netns", "exec", foreign.Namespace, "/usr/sbin/nft", "-j", "list", "ruleset")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = b.Cleanup(ctx, m); !errors.Is(e, ErrCleanup) {
		t.Fatal("foreign namespace did not retain cleanup failure", e)
	}
	if e = verifyNamespace(foreign); e != nil {
		t.Fatal("foreign namespace removed", e)
	}
	after, e := hostCommand(ctx, "/usr/bin/ip", "netns", "exec", foreign.Namespace, "/usr/sbin/nft", "-j", "list", "ruleset")
	if e != nil || before != after {
		t.Fatal("foreign firewall changed", e)
	}
}

func TestRealBrokerPolicyFailureAndGuardRecovery(t *testing.T) {
	if os.Getenv("M05_DISPOSABLE_HOST") != "YES-I-AUTHORIZE-REAL-NETWORK" {
		t.Skip("requires approved disposable KVM/network lab")
	}
	b := hostLab(t)
	if b.c.NetworkMode != "broker-v1" {
		t.Fatal("broker mode required")
	}
	original, e := os.ReadFile(b.c.EgressPolicy)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := os.WriteFile(b.c.EgressPolicy, original, 0600); e != nil {
			t.Error(e)
		}
	}()
	p, e := loadEgressPolicy(b.c)
	if e != nil {
		t.Fatal(e)
	}
	p.MaxConnections++
	stale, _ := json.Marshal(p)
	for _, input := range [][]byte{[]byte("{"), []byte(`{"version":99}`), stale} {
		if e = os.WriteFile(b.c.EgressPolicy, input, 0600); e != nil {
			t.Fatal(e)
		}
		m := labMachine(t, b, 2*time.Minute)
		if e = b.Create(context.Background(), m); e == nil {
			t.Fatal("invalid policy admitted guest")
		}
		if _, e = os.Lstat(b.statePath(m.Lease.JobID)); !os.IsNotExist(e) {
			t.Fatal("resources created before invalid-policy rejection")
		}
		if _, e = NewLinuxBackend(b.c); e == nil {
			t.Fatal("invalid-policy backend enabled")
		}
		if _, e = NewLinuxGuardBackend(b.c); e != nil {
			t.Fatal("policy health blocked recovery guard", e)
		}
	}
	// Missing-policy failure uses a scoped lab backup and always restores it.
	backup := b.c.EgressPolicy + ".m05-test-backup"
	if _, e = os.Lstat(backup); !os.IsNotExist(e) {
		t.Fatal("backup collision")
	}
	if e = os.Rename(b.c.EgressPolicy, backup); e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := os.Rename(backup, b.c.EgressPolicy); e != nil {
			t.Error(e)
		}
	}()
	m := labMachine(t, b, 2*time.Minute)
	if e = b.Create(context.Background(), m); e == nil {
		t.Fatal("missing policy admitted")
	}
	if _, e = NewLinuxGuardBackend(b.c); e != nil {
		t.Fatal("missing policy blocked recovery", e)
	}
}

func TestRealBrokerCreateCancellationRace(t *testing.T) {
	if os.Getenv("M05_DISPOSABLE_HOST") != "YES-I-AUTHORIZE-REAL-NETWORK" {
		t.Skip("requires approved disposable KVM/network lab")
	}
	b := hostLab(t)
	if b.c.NetworkMode != "broker-v1" {
		t.Fatal("broker mode required")
	}
	m := labMachine(t, b, 2*time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- b.Create(ctx, m) }()
	for {
		if _, e := os.Stat(b.statePath(m.Lease.JobID)); e == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	result, e := b.Cleanup(ctx, m)
	if e != nil || !result.VMAbsent || !result.ArtifactsAbsent || !result.StartFenced {
		t.Fatal("racing cleanup unconfirmed", e)
	}
	select {
	case <-finished:
	case <-ctx.Done():
		t.Fatal("creation did not settle after cancellation")
	}
	if _, e = b.Cleanup(ctx, m); e != nil {
		t.Fatal("post-race cleanup", e)
	}
	if e = b.Create(ctx, m); !errors.Is(e, ErrConflict) {
		t.Fatal("late start after racing cancellation", e)
	}
	if _, e = os.Lstat(namespacePath(&hostNetwork{Namespace: networkName(m)})); !os.IsNotExist(e) {
		t.Fatal("racing namespace remains")
	}
}

func controlledLeaseMode(t *testing.T, mode, job string) {
	t.Helper()
	path := os.Getenv("M05_LAB_MODE_FILE")
	if path == "" {
		return
	}
	data, _ := json.Marshal(map[string]string{"mode": mode, "job": job})
	if e := os.WriteFile(path, data, 0600); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := os.WriteFile(path, []byte(`{"mode":"normal"}`), 0600); e != nil {
			t.Error(e)
		}
	})
}
func waitLabStream(t *testing.T, ctx context.Context, job, kind string) {
	t.Helper()
	path := os.Getenv("M05_CANARY_LOG")
	if path == "" {
		return
	}
	for {
		data, e := os.ReadFile(path)
		if e == nil {
			for _, line := range strings.Split(string(data), "\n") {
				var event struct{ Kind, Path string }
				if json.Unmarshal([]byte(line), &event) == nil && event.Kind == kind && event.Path == "/stream?job="+job {
					return
				}
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("stream canary event missing", kind, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func TestRealBrokerTransferCancellation(t *testing.T) {
	if os.Getenv("M05_DISPOSABLE_HOST") != "YES-I-AUTHORIZE-REAL-NETWORK" || os.Getenv("M05_LAB_MODE_FILE") == "" {
		t.Skip("requires controlled disposable KVM/network lab")
	}
	b := hostLab(t)
	m := labMachine(t, b, 2*time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	controlledLeaseMode(t, "cancel", m.Lease.JobID)
	defer func() {
		if _, e := b.Cleanup(context.Background(), m); e != nil {
			t.Error(e)
		}
	}()
	if e := b.Create(ctx, m); e != nil {
		t.Fatal(e)
	}
	waitLabStream(t, ctx, m.Lease.JobID, "http")
	if _, e := b.Cleanup(ctx, m); e != nil {
		t.Fatal(e)
	}
	waitLabStream(t, ctx, m.Lease.JobID, "stream-interrupted")
}
