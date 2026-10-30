//go:build linux

package provisioner

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"dev-orchestrator/internal/egress"
	"golang.org/x/sys/unix"
)

const guestIP = "192.0.2.2"
const brokerAddress = "192.0.2.1:8443"
const guestMAC = "02:00:00:00:00:02"

// A namespace has no uplink, veth, bridge, host route or NAT. Only the broker
// listening socket lives here; the broker's upstream sockets live outside it.
// Persist intent before creation, then inode identity before adding devices.
// A crash before identity persistence deliberately requires operator recovery.
type hostNetwork struct {
	Version    int
	Namespace  string
	Dev        uint64
	Ino        uint64
	PolicyHash string
	Enforced   bool
	Removed    bool
}

func networkName(m Machine) string {
	h := sha256.Sum256([]byte(m.Lease.JobID + ":" + m.OwnershipProof))
	return "tap-" + hex.EncodeToString(h[:10])
}
func brokerUnit(job string) string        { return "orchestrator-broker-" + job + ".service" }
func namespacePath(n *hostNetwork) string { return "/run/netns/" + n.Namespace }
func validHash(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && s == strings.ToLower(s)
}

func validateNetworkConfig(c LinuxConfig) error {
	if c.NetworkMode == "" || c.NetworkMode == "none" {
		if c.EgressPolicy != "" || c.EgressPolicyHash != "" || c.EgressCA != "" || c.EgressKey != "" || c.EgressCAHash != "" || c.EgressResolver != "" || c.BrokerExecutable != "" || c.BrokerUID != 0 || c.BrokerGID != 0 {
			return ErrInvalid
		}
		return nil
	}
	if c.NetworkMode != "broker-v1" || !validHash(c.EgressPolicyHash) || !validHash(c.EgressCAHash) || c.BrokerUID < 100 || c.BrokerGID < 100 || c.BrokerUID == c.UID {
		return ErrInvalid
	}
	for _, p := range []string{c.EgressPolicy, c.EgressCA, c.EgressKey, c.BrokerExecutable} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsAny(p, " \t\n\r%\\\"'$") {
			return ErrInvalid
		}
	}
	dns, err := netip.ParseAddrPort(c.EgressResolver)
	if err != nil || dns.Port() != 53 || !dns.Addr().IsValid() || dns.Addr().IsUnspecified() || dns.Addr().Is4In6() || dns.Addr().Zone() != "" {
		return ErrInvalid
	}
	return nil
}
func validateNetworkState(s hostMachine) error {
	if (s.IngestVersion != 0 && s.IngestVersion != 1) || (s.IngestVersion == 0) != (s.Machine.Ingest == nil) || s.Machine.Ingest != nil && s.Machine.Clone != nil {
		return ErrInvalid
	}

	if s.CloneVersion != 0 && s.CloneVersion != 1 {
		return ErrVersion
	}
	if (s.CloneVersion == 0) != (s.Machine.Clone == nil) {
		return ErrInvalid
	}
	if s.Version != 0 && s.Version != 1 {
		return ErrVersion
	}
	n := s.Network
	if n == nil {
		if s.Version != 0 {
			return ErrInvalid
		}
		return nil
	}
	if s.Version != 1 || n.Version != 1 || n.Namespace != networkName(s.Machine) || !validHash(n.PolicyHash) || (n.Enforced && n.Ino == 0) || n.Removed && !s.Fenced {
		return ErrInvalid
	}
	return nil
}
func loadEgressPolicy(c LinuxConfig) (egress.Policy, error) {
	i, e := trustedPath(c.EgressPolicy, true)
	if e != nil || !i.Mode().IsRegular() || i.Size() > 65536 {
		return egress.Policy{}, ErrInvalid
	}
	f, e := os.Open(c.EgressPolicy)
	if e != nil {
		return egress.Policy{}, e
	}
	defer f.Close()
	p, e := egress.DecodePolicy(f)
	if e != nil || p.Hash() != c.EgressPolicyHash {
		return egress.Policy{}, ErrInvalid
	}
	return p, nil
}
func preflightNetwork(c LinuxConfig) error {
	if c.NetworkMode != "broker-v1" {
		return nil
	}
	for _, p := range []string{"/usr/bin/ip", "/usr/sbin/nft", c.BrokerExecutable} {
		i, e := trustedPath(p, false)
		if e != nil || !i.Mode().IsRegular() || i.Mode().Perm()&0111 == 0 {
			return ErrUnavailable
		}
	}
	i, e := os.Stat("/dev/net/tun")
	if e != nil || i.Mode()&os.ModeDevice == 0 {
		return ErrUnavailable
	}
	account, e := user.LookupId(strconv.FormatUint(uint64(c.BrokerUID), 10))
	if e != nil || account.Username != "orchestrator-egress" || account.Gid != strconv.FormatUint(uint64(c.BrokerGID), 10) {
		return ErrUnavailable
	}
	p, e := loadEgressPolicy(c)
	if e != nil {
		return e
	}
	for _, path := range []string{c.EgressCA, c.EgressKey} {
		i, e := trustedPath(path, true)
		if e != nil || !i.Mode().IsRegular() || i.Size() > 65536 {
			return ErrInvalid
		}
	}
	ca, e := tls.LoadX509KeyPair(c.EgressCA, c.EgressKey)
	if e != nil {
		return ErrInvalid
	}
	sum := sha256.Sum256(ca.Certificate[0])
	if hex.EncodeToString(sum[:]) != c.EgressCAHash {
		return ErrInvalid
	}
	_, e = egress.New(p, ca, net.DefaultResolver, func(netip.Addr) (egress.Lease, bool) { return egress.Lease{}, false })
	return e
}

// Atomic rules inside this namespace only. The TAP ingress hook also rejects
// source MAC/IP changes, IPv6, ARP poisoning, fragments and non-TCP traffic.
func guestFirewall() string {
	return `table netdev tap_ingress {
 chain ingress {
  type filter hook ingress device "tap0" priority -500; policy drop;
  ether saddr 02:00:00:00:00:02 ether type arp arp saddr ip 192.0.2.2 arp daddr ip 192.0.2.1 counter accept
  ether saddr 02:00:00:00:00:02 ether type ip ip saddr 192.0.2.2 ip daddr 192.0.2.1 ip frag-off & 0x3fff == 0 tcp dport 8443 counter accept
  counter drop
 }
}
table inet tap_build {
 chain input {
  type filter hook input priority -200; policy drop;
  iifname "tap0" ip saddr 192.0.2.2 ip daddr 192.0.2.1 tcp dport 8443 ct state new,established accept
 }
 chain forward { type filter hook forward priority -200; policy drop; }
 chain output {
  type filter hook output priority -200; policy drop;
  oifname "tap0" ip saddr 192.0.2.1 ip daddr 192.0.2.2 tcp sport 8443 ct state established accept
 }
}
`
}
func namespaceCommand(ctx context.Context, n *hostNetwork, input string, args ...string) error {
	argv := append([]string{"netns", "exec", n.Namespace}, args...)
	cmd := exec.CommandContext(ctx, "/usr/bin/ip", argv...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin", "LANG=C"}
	cmd.Stdin = strings.NewReader(input)
	var out limitedOutput
	cmd.Stdout = &out
	cmd.Stderr = &out
	if cmd.Run() != nil {
		return ErrUnavailable
	}
	return nil
}
func verifyNamespace(n *hostNetwork) error {
	i, e := trustedPath(namespacePath(n), false)
	if e != nil {
		return e
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok || n.Ino == 0 || uint64(st.Dev) != n.Dev || st.Ino != n.Ino {
		return ErrConflict
	}
	return nil
}
func (b *linuxBackend) prepareNetwork(ctx context.Context, s *hostMachine) error {
	if exists, _, e := b.namedUnit(ctx, s.Machine, brokerUnit(s.Machine.Lease.JobID)); e != nil || exists {
		return ErrConflict
	}
	n := &hostNetwork{Version: 1, Namespace: networkName(s.Machine), PolicyHash: b.c.EgressPolicyHash}
	if _, e := os.Lstat(namespacePath(n)); !os.IsNotExist(e) {
		return ErrConflict
	}
	// ip netns owns a shared system directory; verify it rather than creating
	// resources under a symlink or group/world-writable namespace registry.
	if i, e := trustedPath("/run/netns", false); e != nil || !i.IsDir() {
		return ErrUnavailable
	}
	s.Version = 1
	s.Network = n
	if e := b.write(*s); e != nil {
		return e
	}
	if e := b.checkpointNetwork("intent"); e != nil {
		return e
	}
	if _, e := hostCommand(ctx, "/usr/bin/ip", "netns", "add", n.Namespace); e != nil {
		return e
	}
	if e := b.checkpointNetwork("namespace-created"); e != nil {
		return e
	}
	i, e := os.Lstat(namespacePath(n))
	if e != nil {
		return e
	}
	st := i.Sys().(*syscall.Stat_t)
	n.Dev = uint64(st.Dev)
	n.Ino = st.Ino
	if e = b.write(*s); e != nil {
		return e
	}
	if e = b.checkpointNetwork("identity"); e != nil {
		return e
	}
	if e = verifyNamespace(n); e != nil {
		return e
	}
	for _, args := range [][]string{
		{"/usr/bin/ip", "tuntap", "add", "dev", "tap0", "mode", "tap"},
		{"/usr/bin/ip", "link", "set", "dev", "tap0", "alias", s.Machine.OwnershipProof, "address", "02:00:00:00:00:01"},
		{"/usr/bin/ip", "addr", "add", "192.0.2.1/30", "dev", "tap0"},
	} {
		if e = namespaceCommand(ctx, n, "", args...); e != nil {
			return e
		}
	}
	if e = b.checkpointNetwork("tap"); e != nil {
		return e
	}
	// IPv6 is additionally filtered by both nft hooks, even on kernels where
	// autoconfiguration occurs before this sysctl can be written.
	if e = inNamespace(n, func() error {
		for _, p := range []string{"/proc/sys/net/ipv6/conf/all/disable_ipv6", "/proc/sys/net/ipv6/conf/default/disable_ipv6"} {
			if e := os.WriteFile(p, []byte("1"), 0600); e != nil {
				return e
			}
		}
		return nil
	}); e != nil {
		return e
	}
	if e = namespaceCommand(ctx, n, guestFirewall(), "/usr/sbin/nft", "-f", "-"); e != nil {
		return e
	}
	if e = b.checkpointNetwork("firewall"); e != nil {
		return e
	}
	n.Enforced = true
	if e = b.write(*s); e != nil {
		return e
	}
	if e = namespaceCommand(ctx, n, "", "/usr/bin/ip", "link", "set", "dev", "tap0", "up"); e != nil {
		return e
	}
	return b.checkpointNetwork("enabled")
}

func (b *linuxBackend) checkpointNetwork(stage string) error {
	if b.networkStage != nil {
		return b.networkStage(stage)
	}
	return nil
}

// Never let a changed network namespace escape onto a Go worker thread. The
// goroutine exits without unlocking its OS thread if restoration fails.
func inNamespace(n *hostNetwork, fn func() error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		old, e := os.Open("/proc/self/task/" + strconv.Itoa(unix.Gettid()) + "/ns/net")
		if e != nil {
			runtime.UnlockOSThread()
			done <- e
			return
		}
		defer old.Close()
		target, e := os.Open(namespacePath(n))
		if e != nil {
			runtime.UnlockOSThread()
			done <- e
			return
		}
		defer target.Close()
		info, e := target.Stat()
		if e != nil {
			runtime.UnlockOSThread()
			done <- e
			return
		}
		st := info.Sys().(*syscall.Stat_t)
		if st.Ino != n.Ino || uint64(st.Dev) != n.Dev || n.Ino == 0 {
			runtime.UnlockOSThread()
			done <- ErrConflict
			return
		}
		if e = unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); e != nil {
			runtime.UnlockOSThread()
			done <- e
			return
		}
		e = fn()
		if restore := unix.Setns(int(old.Fd()), unix.CLONE_NEWNET); restore != nil {
			done <- ErrUnavailable
			return
		}
		runtime.UnlockOSThread()
		done <- e
	}()
	return <-done
}
func openGuestTAP(s hostMachine) (*os.File, error) {
	if validateNetworkState(s) != nil || s.Network == nil || !s.Network.Enforced || s.Network.Removed {
		return nil, ErrInvalid
	}
	var tap *os.File
	e := inNamespace(s.Network, func() error {
		f, e := os.OpenFile("/dev/net/tun", os.O_RDWR|unix.O_CLOEXEC, 0)
		if e != nil {
			return e
		}
		req, e := unix.NewIfreq("tap0")
		if e == nil {
			req.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI)
			e = unix.IoctlIfreq(int(f.Fd()), unix.TUNSETIFF, req)
		}
		if e != nil {
			f.Close()
			return e
		}
		tap = f
		return nil
	})
	if e != nil {
		if tap != nil {
			tap.Close()
		}
		return nil, e
	}
	return tap, nil
}
func attachGuestTAP(q *exec.Cmd, tap *os.File) {
	// Do not attach scripts, bridges, user networking or QEMU network privileges.
	args := make([]string, 0, len(q.Args)+4)
	for i := 0; i < len(q.Args); i++ {
		if q.Args[i] == "-nic" && i+1 < len(q.Args) {
			i++
			continue
		}
		args = append(args, q.Args[i])
	}
	q.Args = append(args, "-netdev", "tap,id=egress,fd=5", "-device", "virtio-net-pci,netdev=egress,mac="+guestMAC)
	q.ExtraFiles = append(q.ExtraFiles, tap)
}
func guestServiceProperties(ttl time.Duration, network bool) []string {
	props := serviceProperties(ttl)
	if !network {
		return props
	}
	for i, p := range props {
		if strings.HasPrefix(p, "CapabilityBoundingSet=") {
			props[i] = "CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_KILL CAP_SYS_ADMIN CAP_NET_ADMIN"
		}
		if p == "RestrictNamespaces=yes" {
			props[i] = "RestrictNamespaces=net"
		}
	}
	return append(props, "DeviceAllow=/dev/net/tun rw")
}
func (b *linuxBackend) startBroker(ctx context.Context, s hostMachine) error {
	remaining := time.Until(s.Machine.Lease.ExpiresAt)
	if remaining <= 0 {
		return ErrUnavailable
	}
	args := []string{"--quiet", "--no-block", "--unit=" + brokerUnit(s.Machine.Lease.JobID), "--description=" + ownerDescription(s.Machine)}
	props := []string{"Type=notify", "NotifyAccess=main", "TimeoutStartSec=15s", "Restart=no", "KillMode=control-group", "TimeoutStopSec=2s", "RuntimeMaxSec=" + strconv.FormatFloat(remaining.Seconds(), 'f', 3, 64), "CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_SYS_ADMIN", "RestrictNamespaces=net", "PrivateTmp=yes", "PrivateDevices=yes", "ProtectSystem=strict", "ProtectHome=yes", "NoNewPrivileges=yes", "ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectControlGroups=yes", "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX", "MemoryMax=256M", "TasksMax=32", "LimitNOFILE=256", "UMask=0077", "StandardOutput=null", "StandardError=journal", "LogRateLimitIntervalSec=30s", "LogRateLimitBurst=100"}
	for _, p := range props {
		args = append(args, "--property="+p)
	}
	args = append(args, "--property=ReadWritePaths="+filepath.Join(b.c.Root, "host.lock"), "--", b.c.Executable, "-mode", "host-broker", "-linux-config", filepath.Join(b.c.Root, "backend.json"), "-host-job", s.Machine.Lease.JobID)
	_, e := hostCommand(ctx, "/usr/bin/systemd-run", args...)
	return e
}
func waitBrokerReady(ctx context.Context, b *linuxBackend, m Machine) error {
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		out, e := hostCommand(ctx, "/usr/bin/systemctl", "show", brokerUnit(m.Lease.JobID), "--property=Description,ActiveState,SubState")
		if e != nil {
			return ErrUnavailable
		}
		fields := map[string]string{}
		for _, l := range strings.Split(out, "\n") {
			k, v, ok := strings.Cut(l, "=")
			if ok {
				fields[k] = v
			}
		}
		if fields["Description"] != ownerDescription(m) {
			return ErrConflict
		}
		if fields["ActiveState"] == "active" && fields["SubState"] == "running" {
			return nil
		}
		if fields["ActiveState"] == "failed" || fields["ActiveState"] == "inactive" {
			return ErrUnavailable
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return ErrUnavailable
		case <-ticker.C:
		}
	}
}
func (b *linuxBackend) stopBroker(ctx context.Context, s hostMachine) error {
	if s.Network == nil {
		return nil
	}
	exists, active, e := b.namedUnit(ctx, s.Machine, brokerUnit(s.Machine.Lease.JobID))
	if e != nil {
		return e
	}
	if exists && active {
		if _, e = hostCommand(ctx, "/usr/bin/systemctl", "stop", brokerUnit(s.Machine.Lease.JobID)); e != nil {
			return e
		}
	}
	_, active, e = b.namedUnit(ctx, s.Machine, brokerUnit(s.Machine.Lease.JobID))
	if e != nil || active {
		return ErrCleanup
	}
	// An inactive systemd service alone is not proof that its children are gone.
	if e = confirmServiceGroupEmpty(brokerUnit(s.Machine.Lease.JobID)); e != nil {
		return e
	}
	return nil
}
func (b *linuxBackend) cleanupNetwork(ctx context.Context, s hostMachine) error {
	n := s.Network
	if n == nil {
		return nil
	}
	if e := validateNetworkState(s); e != nil {
		return e
	}
	if e := b.stopBroker(ctx, s); e != nil {
		return e
	}
	if _, e := os.Lstat(namespacePath(n)); os.IsNotExist(e) {
		n.Removed = true
		return b.write(s)
	} else if e != nil {
		return e
	}
	if n.Removed {
		return ErrConflict
	}
	if e := verifyNamespace(n); e != nil {
		return ErrCleanup
	}
	// No root commands run inside an unverified namespace. Deletion removes only
	// this namespace; host nft tables, links and foreign namespaces are untouched.
	if _, e := hostCommand(ctx, "/usr/bin/ip", "netns", "delete", n.Namespace); e != nil {
		return e
	}
	if _, e := os.Lstat(namespacePath(n)); !os.IsNotExist(e) {
		return ErrCleanup
	}
	n.Removed = true
	return b.write(s)
}
func confirmServiceGroupEmpty(unit string) error {
	entries, e := os.ReadDir(filepath.Join("/sys/fs/cgroup/system.slice", unit))
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	_ = entries
	data, e := os.ReadFile(filepath.Join("/sys/fs/cgroup/system.slice", unit, "cgroup.events"))
	if e != nil {
		return e
	}
	for _, l := range strings.Split(string(data), "\n") {
		if l == "populated 0" {
			return nil
		}
	}
	return ErrCleanup
}

func runLinuxBroker(ctx context.Context, config, job string) error {
	if !identifier.MatchString(job) || os.Geteuid() != 0 {
		return ErrInvalid
	}
	c, e := loadLinuxConfig(config)
	if e != nil || validateLinuxConfig(c) != nil || c.NetworkMode != "broker-v1" || config != filepath.Join(c.Root, "backend.json") {
		return ErrInvalid
	}
	cg, e := os.ReadFile("/proc/self/cgroup")
	if e != nil || !strings.Contains(string(cg), "/"+brokerUnit(job)+"\n") {
		return ErrUnavailable
	}
	if e = preflightBroker(c); e != nil {
		return e
	}
	b := &linuxBackend{c: c}
	lock, e := b.lock(ctx)
	if e != nil {
		return e
	}
	defer func() {
		if lock != nil {
			unlock(lock)
		}
	}()
	s, e := b.read(job)
	if e != nil || s.Fenced || s.Network == nil || !s.Network.Enforced || s.Network.Removed || s.Network.PolicyHash != c.EgressPolicyHash || !validMachine(s.Machine, c) {
		return ErrConflict
	}
	boot, e := bootID()
	if e != nil || boot != s.BootID {
		return ErrUnavailable
	}
	now, e := bootNow()
	if e != nil || now >= s.Deadline || !time.Now().Before(s.Machine.Lease.ExpiresAt) {
		return ErrUnavailable
	}
	var listenerFile *os.File
	e = inNamespace(s.Network, func() error {
		ln, e := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 8443})
		if e != nil {
			return e
		}
		defer ln.Close()
		listenerFile, e = ln.File()
		return e
	})
	if e != nil {
		if listenerFile != nil {
			listenerFile.Close()
		}
		return e
	}
	defer listenerFile.Close()
	files := []*os.File{listenerFile}
	for _, path := range []string{c.EgressPolicy, c.EgressCA, c.EgressKey} {
		f, e := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
		if e != nil {
			return e
		}
		defer f.Close()
		files = append(files, f)
	}
	readyR, readyW, e := os.Pipe()
	if e != nil {
		return e
	}
	defer readyR.Close()
	defer readyW.Close()
	files = append(files, readyW)
	cmd := exec.Command(c.BrokerExecutable, "-listener-fd", "3", "-policy", "/proc/self/fd/4", "-ca-cert", "/proc/self/fd/5", "-ca-key", "/proc/self/fd/6", "-ready-fd", "7", "-policy-hash", s.Network.PolicyHash, "-ca-hash", c.EgressCAHash, "-guest", guestIP, "-expires", s.Machine.Lease.ExpiresAt.UTC().Format(time.RFC3339Nano), "-resolver", c.EgressResolver)
	cmd.ExtraFiles = files
	cmd.Env = []string{"PATH=/usr/bin", "LANG=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: c.BrokerUID, Gid: c.BrokerGID, Groups: []uint32{}}, Pdeathsig: syscall.SIGKILL}
	if e = cmd.Start(); e != nil {
		return ErrUnavailable
	}
	readyW.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() { cmd.Process.Kill(); <-done }()
	// Pipe reads are cancellable even if the child never signals readiness.
	ready := make(chan bool, 1)
	go func() { var v [1]byte; _, e := io.ReadFull(readyR, v[:]); ready <- e == nil && v[0] == 1 }()
	select {
	case ok := <-ready:
		if !ok {
			return ErrUnavailable
		}
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(10 * time.Second):
		return ErrUnavailable
	}
	sock := os.Getenv("NOTIFY_SOCKET")
	if sock == "" {
		return ErrUnavailable
	}
	u, e := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: sock, Net: "unixgram"})
	if e != nil {
		return e
	}
	_, e = u.Write([]byte("READY=1"))
	u.Close()
	if e != nil {
		return e
	}
	unlock(lock)
	lock = nil
	// The child's wall/monotonic deadline is backed by systemd RuntimeMaxSec and
	// M04's independent CLOCK_BOOTTIME expiry timer, which also kills this unit.
	select {
	case e := <-done:
		done <- e
		return ErrUnavailable
	case <-ctx.Done():
		return ctx.Err()
	}
}
func preflightBroker(c LinuxConfig) error {
	// Broker service PrivateDevices hides KVM/TUN intentionally. Validate only
	// its executable, policy and CA here, rather than VM device capabilities.
	p, e := loadEgressPolicy(c)
	if e != nil {
		return e
	}
	for _, path := range []string{c.EgressCA, c.EgressKey, c.BrokerExecutable} {
		i, e := trustedPath(path, path != c.BrokerExecutable)
		if e != nil || !i.Mode().IsRegular() || i.Size() > 16<<20 {
			return ErrInvalid
		}
	}
	ca, e := tls.LoadX509KeyPair(c.EgressCA, c.EgressKey)
	if e != nil {
		return ErrInvalid
	}
	h := sha256.Sum256(ca.Certificate[0])
	if hex.EncodeToString(h[:]) != c.EgressCAHash {
		return ErrInvalid
	}
	_, e = egress.New(p, ca, net.DefaultResolver, func(netip.Addr) (egress.Lease, bool) { return egress.Lease{}, false })
	return e
}
