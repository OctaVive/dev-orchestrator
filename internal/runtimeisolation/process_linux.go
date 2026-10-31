package runtimeisolation

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/runtimeagent"
)

type ProcessLimits struct {
	UID, GID  int
	Resources contracts.Resources
}
type ProcessMeasurement struct {
	UserNamespace    string `json:"user_namespace"`
	NetworkNamespace string `json:"network_namespace"`
	UIDMapHash       string `json:"uid_map_hash"`
	GIDMapHash       string `json:"gid_map_hash"`
	MAC              string `json:"mac"`
	Seccomp          int    `json:"seccomp"`
	CgroupHash       string `json:"cgroup_hash"`
	TmpBytes         int64  `json:"tmp_bytes"`
	WritableBytes    int64  `json:"writable_bytes"`
}

func scalar(path string) (string, error) {
	b, err := ReadSmall(path, 4096)
	return strings.TrimSpace(string(b)), err
}
func fields(raw []byte) map[string][]string {
	m := map[string][]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		a, v, ok := strings.Cut(line, ":")
		if ok {
			m[a] = strings.Fields(v)
		}
	}
	return m
}
func number(path string, want int64) bool {
	s, err := scalar(path)
	if err != nil {
		return false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return err == nil && n == want
}

// VerifyProcess is used by the fixed root measurement helper inside a runtime VM.
// pid must be resolved independently from the enrolled daemon's exact container
// ID and ownership, never taken from an execution-command payload.
func VerifyProcess(e Enrollment, pid int, limits ProcessLimits) (ProcessMeasurement, error) {
	stage := "identity"
	deny := func() (ProcessMeasurement, error) {
		return ProcessMeasurement{}, fmt.Errorf("runtime_measurement_%s_denied", stage)
	}
	if os.Geteuid() != 0 || !e.Valid() || pid <= 1 || limits.UID <= 0 || limits.GID <= 0 {
		return deny()
	}
	b := e.Backend
	boot, err := scalar("/proc/sys/kernel/random/boot_id")
	if err != nil || boot != b.BootID {
		return deny()
	}
	initial, err := os.Readlink("/proc/1/ns/user")
	if err != nil || initial != b.InitialUserNamespace {
		return deny()
	}
	proc := fmt.Sprintf("/proc/%d", pid)
	daemon := fmt.Sprintf("/proc/%d", b.DaemonPID)
	startRaw, err := ReadSmall(proc+"/stat", 4096)
	if err != nil {
		return deny()
	}
	start, err := StartTicks(startRaw)
	if err != nil {
		return deny()
	}
	daemonRaw, err := ReadSmall(daemon+"/stat", 4096)
	if err != nil {
		return deny()
	}
	ticks, err := StartTicks(daemonRaw)
	if err != nil || ticks != b.DaemonStartTicks {
		return deny()
	}
	ns, err := os.Readlink(proc + "/ns/user")
	if err != nil || ns != b.UserNamespace || ns == initial {
		return deny()
	}
	var containerNet string
	stage = "namespaces"
	for _, kind := range []string{"pid", "ipc", "mnt", "uts", "net", "cgroup"} {
		own, err := os.Readlink(proc + "/ns/" + kind)
		if err != nil {
			return deny()
		}
		if kind == "net" {
			containerNet = own
		}
		parent, err := os.Readlink(daemon + "/ns/" + kind)
		if err != nil || own == parent {
			return deny()
		}
		host, err := os.Readlink("/proc/1/ns/" + kind)
		if err != nil || own == host {
			return deny()
		}
	}
	stage = "mappings"
	uidRaw, err := ReadSmall(proc+"/uid_map", 4096)
	if err != nil || contracts.Digest(uidRaw) != b.UIDMapHash {
		return deny()
	}
	gidRaw, err := ReadSmall(proc+"/gid_map", 4096)
	if err != nil || contracts.Digest(gidRaw) != b.GIDMapHash {
		return deny()
	}
	hostUID, err := MappedID(uidRaw, uint64(limits.UID))
	if err != nil {
		return deny()
	}
	hostGID, err := MappedID(gidRaw, uint64(limits.GID))
	if err != nil {
		return deny()
	}
	stage = "process_status"
	raw, err := ReadSmall(proc+"/status", 16384)
	if err != nil {
		return deny()
	}
	status := fields(raw)
	for name, want := range map[string]uint64{"Uid": hostUID, "Gid": hostGID} {
		if len(status[name]) != 4 {
			return deny()
		}
		for _, s := range status[name] {
			n, err := strconv.ParseUint(s, 10, 32)
			if err != nil || n != want {
				return deny()
			}
		}
	}
	if len(status["Groups"]) > 1 {
		return deny()
	}
	if len(status["Groups"]) == 1 {
		n, err := strconv.ParseUint(status["Groups"][0], 10, 32)
		if err != nil || n != hostGID {
			return deny()
		}
	}
	for _, name := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		if len(status[name]) != 1 {
			return deny()
		}
		n, err := strconv.ParseUint(status[name][0], 16, 64)
		if err != nil || n != 0 {
			return deny()
		}
	}
	if strings.Join(status["NoNewPrivs"], "") != "1" || strings.Join(status["Seccomp"], "") != "2" {
		return deny()
	}
	stage = "mac"
	mac, err := scalar(proc + "/attr/current")
	if err != nil || mac != "tap-runtime (enforce)" {
		return deny()
	}
	stage = "cgroups"
	cg, err := scalar(proc + "/cgroup")
	if err != nil || !strings.HasPrefix(cg, "0::/") || strings.Contains(cg, "\n") {
		return deny()
	}
	rel := strings.TrimPrefix(cg, "0::/")
	if rel == "" || filepath.Clean(rel) != rel || strings.HasPrefix(rel, "../") {
		return deny()
	}
	root, err := os.OpenRoot("/sys/fs/cgroup")
	if err != nil {
		return deny()
	}
	defer root.Close()
	// Cgroup paths come from the kernel and stay beneath this root. os.Root
	// forbids escaping via symlinks even if an unexpected component appears.
	readCG := func(name string) (string, error) {
		f, err := root.Open(rel + "/" + name)
		if err != nil {
			return "", err
		}
		defer f.Close()
		buf := make([]byte, 4097)
		n, err := f.Read(buf)
		if err != nil || n > 4096 {
			return "", runtimeagent.ErrUnsupported
		}
		return strings.TrimSpace(string(buf[:n])), nil
	}
	for file, want := range map[string]int64{"memory.max": limits.Resources.MemoryBytes, "memory.swap.max": 0, "pids.max": int64(limits.Resources.PIDs)} {
		s, err := readCG(file)
		if err != nil {
			return deny()
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n != want {
			return deny()
		}
	}
	cpu, err := readCG("cpu.max")
	if err != nil {
		return deny()
	}
	parts := strings.Fields(cpu)
	if len(parts) != 2 {
		return deny()
	}
	quota, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || quota < 1 {
		return deny()
	}
	period, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || period < 1 || period > 1000000 || quota > 4000000 || quota*1000 != period*int64(limits.Resources.CPUMillis) {
		return deny()
	}
	stage = "filesystems"
	mounts, err := ReadSmall(proc+"/mountinfo", 65536)
	if err != nil {
		return deny()
	}
	rootRO := false
	observedTmp := map[string]int64{}
	tmp := map[string]bool{"/tmp": false, "/run": false}
	for _, line := range strings.Split(string(mounts), "\n") {
		f := strings.Fields(line)
		if len(f) < 7 {
			continue
		}
		if f[4] == "/" {
			rootRO = strings.Contains(","+f[5]+",", ",ro,")
		}
		if _, ok := tmp[f[4]]; ok {
			tail := strings.SplitN(line, " - ", 2)
			if len(tail) != 2 || !strings.HasPrefix(tail[1], "tmpfs ") {
				return deny()
			}
			for _, flag := range []string{"noexec", "nosuid", "nodev"} {
				if !strings.Contains(","+f[5]+",", ","+flag+",") {
					return deny()
				}
			}
			// The kernel mount table reports the effective tmpfs superblock size.
			// Root cannot traverse an unprivileged FUSE root for statfs without joining
			// the workload's namespaces; do not substitute engine configuration flags.
			super := strings.Fields(tail[1])
			if len(super) < 3 {
				return deny()
			}
			actual, err := TmpfsSize(super[2])
			if err != nil {
				return deny()
			}
			budget := limits.Resources.TmpBytes
			if f[4] == "/run" {
				budget = limits.Resources.WritableBytes
			}
			if budget <= 0 || actual > budget {
				return deny()
			}
			observedTmp[f[4]] = actual
			tmp[f[4]] = true
		}
	}
	if !rootRO || !tmp["/tmp"] || !tmp["/run"] {
		return deny()
	}
	stage = "process_identity"
	after, err := ReadSmall(proc+"/stat", 4096)
	if err != nil {
		return deny()
	}
	again, err := StartTicks(after)
	if err != nil || again != start {
		return deny()
	}
	return ProcessMeasurement{UserNamespace: ns, NetworkNamespace: containerNet, UIDMapHash: contracts.Digest(uidRaw), GIDMapHash: contracts.Digest(gidRaw), MAC: mac, Seccomp: 2, CgroupHash: contracts.Digest([]byte(cg)), TmpBytes: observedTmp["/tmp"], WritableBytes: observedTmp["/run"]}, nil
}

// TmpfsSize parses the actual kernel superblock options from mountinfo. An
// absent/default/ambiguous or unbounded size is unsupported.
func TmpfsSize(options string) (int64, error) {
	var size int64
	found := false
	for _, option := range strings.Split(options, ",") {
		if !strings.HasPrefix(option, "size=") {
			continue
		}
		if found {
			return 0, runtimeagent.ErrUnsupported
		}
		found = true
		raw := strings.TrimPrefix(option, "size=")
		multiplier := int64(1)
		for _, suffix := range []struct {
			s string
			n int64
		}{{"k", 1 << 10}, {"m", 1 << 20}, {"g", 1 << 30}} {
			if strings.HasSuffix(raw, suffix.s) {
				raw = strings.TrimSuffix(raw, suffix.s)
				multiplier = suffix.n
				break
			}
		}
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 1 || n > (10<<30)/multiplier {
			return 0, runtimeagent.ErrUnsupported
		}
		size = n * multiplier
	}
	if !found {
		return 0, runtimeagent.ErrUnsupported
	}
	return size, nil
}
