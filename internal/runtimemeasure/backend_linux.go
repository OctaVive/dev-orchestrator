package runtimemeasure

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"dev-orchestrator/internal/runtimeagent"
	"dev-orchestrator/internal/runtimehost"
	"dev-orchestrator/internal/runtimeisolation"
	"dev-orchestrator/internal/runtimeobservation"
	"golang.org/x/sys/unix"
)

func text(path string, limit int64) (string, error) {
	b, err := runtimeisolation.ReadSmall(path, limit)
	return strings.TrimSpace(string(b)), err
}
func scalar(path string) (int64, error) {
	s, err := text(path, 4096)
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v < 0 {
		return 0, runtimeagent.ErrUnsupported
	}
	return v, nil
}
func appCgroup(app runtimehost.App) (string, error) {
	root := "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service"
	target := app.Slice()
	var found string
	visited := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return runtimeagent.ErrUnsupported
		}
		visited++
		if visited > 4096 {
			return runtimeagent.ErrUnsupported
		}
		if !d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return runtimeagent.ErrUnsupported
		}
		if strings.Count(rel, string(filepath.Separator)) > 10 {
			return filepath.SkipDir
		}
		if d.Name() == target {
			if found != "" {
				return runtimeagent.ErrUnsupported
			}
			found = path
			return filepath.SkipDir
		}
		// Only follow the manager's bounded slice hierarchy, never container scopes.
		if path != root && !strings.HasSuffix(d.Name(), ".slice") {
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil || found == "" {
		return "", runtimeagent.ErrUnsupported
	}
	return found, nil
}
func backendProof(profile runtimehost.Profile, app runtimehost.App, e runtimeisolation.Enrollment) (runtimeobservation.BackendProof, error) {
	stage := "profile"
	live, liveErr := runtimehost.Load()
	if liveErr != nil || live.Hash() != profile.Hash() || profile.VerifyPolicy() != nil {
		return runtimeobservation.BackendProof{}, fmt.Errorf("runtime_measure_backend_profile_denied")
	}
	stage = "disk"
	fail := func() (runtimeobservation.BackendProof, error) {
		return runtimeobservation.BackendProof{}, fmt.Errorf("runtime_measure_backend_%s_denied", stage)
	}
	mount := app.MountDirectory()
	disk := runtimehost.Root + "/disks/" + app.ID + ".ext4"
	var backing, fs, engine, host unix.Stat_t
	if unix.Lstat(disk, &backing) != nil || backing.Mode&unix.S_IFMT != unix.S_IFREG || backing.Uid != 0 || backing.Mode&0077 != 0 || backing.Size != app.DiskBytes() || backing.Blocks < backing.Size/512 {
		return fail()
	}
	if unix.Stat(mount, &fs) != nil || unix.Stat(e.Backend.DataRoot, &engine) != nil || unix.Stat("/", &host) != nil || fs.Dev == host.Dev || fs.Dev != engine.Dev {
		return fail()
	}
	var statfs unix.Statfs_t
	if unix.Statfs(mount, &statfs) != nil || uint64(statfs.Type) != unix.EXT4_SUPER_MAGIC || statfs.Bsize <= 0 || statfs.Blocks > uint64(app.DiskBytes())/uint64(statfs.Bsize) {
		return fail()
	}
	for _, other := range profile.Apps {
		if other.ID == app.ID {
			continue
		}
		var st unix.Stat_t
		if unix.Stat(other.MountDirectory(), &st) != nil || st.Dev == fs.Dev {
			return fail()
		}
	}
	stage = "parent_cgroup"
	cg, err := appCgroup(app)
	if err != nil {
		return fail()
	}
	for name, want := range map[string]int64{"memory.max": app.MemoryBytes + runtimehost.DaemonMemory, "memory.swap.max": 0, "pids.max": int64(app.PIDs + runtimehost.DaemonPIDs)} {
		n, err := scalar(cg + "/" + name)
		if err != nil || n != want {
			return fail()
		}
	}
	quota, err := text(cg+"/cpu.max", 4096)
	if err != nil {
		return fail()
	}
	f := strings.Fields(quota)
	if len(f) != 2 {
		return fail()
	}
	q, err := strconv.ParseInt(f[0], 10, 64)
	if err != nil || q <= 0 || q > 16000000 {
		return fail()
	}
	period, err := strconv.ParseInt(f[1], 10, 64)
	cpu := app.CPUMillis + runtimehost.DaemonCPU
	if err != nil || period < 1 || period > 1000000 || q*1000 != period*int64(cpu) {
		return fail()
	}
	// The daemon and all workload scopes must be charged under this same parent.
	daemonCG, err := text(fmt.Sprintf("/proc/%d/cgroup", e.Backend.DaemonPID), 4096)
	if err != nil || !strings.HasPrefix(daemonCG, "0::/") || !strings.Contains(daemonCG, "/"+app.Slice()+"/") {
		return fail()
	}
	stage = "network"
	netns, err := noUplink(e)
	if err != nil {
		return fail()
	}
	for _, other := range profile.Apps {
		if other.ID == app.ID {
			continue
		}
		enrolled, err := runtimeisolation.ReadEnrollment(other.ID)
		if err != nil {
			return fail()
		}
		otherNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", enrolled.Backend.DaemonPID))
		if err != nil || otherNS == netns {
			return fail()
		}
	}
	return runtimeobservation.BackendProof{DiskBytes: backing.Size, PhysicalBytes: backing.Blocks * 512, MemoryBytes: app.MemoryBytes + runtimehost.DaemonMemory, CPUMillis: cpu, PIDs: app.PIDs + runtimehost.DaemonPIDs, NetworkNamespace: netns, NoUplink: true}, nil
}
func noUplink(e runtimeisolation.Enrollment) (string, error) {
	fail := func() (string, error) { return "", runtimeagent.ErrUnsupported }
	proc := fmt.Sprintf("/proc/%d", e.Backend.DaemonPID)
	ns, err := os.Readlink(proc + "/ns/net")
	if err != nil {
		return fail()
	}
	initial, err := os.Readlink("/proc/1/ns/net")
	if err != nil || ns == initial {
		return fail()
	}
	exe, err := os.Readlink(proc + "/exe")
	if err != nil || exe != "/usr/local/bin/dockerd" {
		return fail()
	}
	status, err := text(proc+"/status", 16384)
	if err != nil {
		return fail()
	}
	parent := 0
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, "PPid:") {
			parent, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
		}
	}
	if parent <= 1 {
		return fail()
	}
	parentProc := fmt.Sprintf("/proc/%d", parent)
	exe, err = os.Readlink(parentProc + "/exe")
	if err != nil || exe != "/usr/local/bin/rootlesskit" {
		return fail()
	}
	args, err := runtimeisolation.ReadSmall(parentProc+"/cmdline", 8192)
	if err != nil {
		return fail()
	}
	netNone, portNone := false, false
	for _, arg := range strings.Split(string(args), "\x00") {
		if arg == "--net=none" {
			netNone = true
		}
		if arg == "--port-driver=none" {
			portNone = true
		}
		if arg == "--detach-netns" || arg == "--detach-netns=true" {
			return fail()
		}
	}
	if !netNone || !portNone {
		return fail()
	}
	routes, err := text(proc+"/net/route", 16384)
	if err != nil {
		return fail()
	}
	for _, line := range strings.Split(routes, "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 8 {
			return fail()
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil {
			return fail()
		}
		if f[1] == "00000000" && f[7] == "00000000" && flags&1 != 0 && flags&0x200 == 0 {
			return fail()
		}
	}
	ipv6, err := text(proc+"/net/ipv6_route", 16384)
	if err != nil {
		return fail()
	}
	if ipv6 != "" {
		for _, line := range strings.Split(ipv6, "\n") {
			f := strings.Fields(line)
			if len(f) != 10 {
				return fail()
			}
			flags, err := strconv.ParseUint(f[8], 16, 32)
			if err != nil {
				return fail()
			}
			if f[0] == strings.Repeat("0", 32) && f[1] == "00" && flags&1 != 0 && flags&0x200 == 0 {
				return fail()
			}
		}
	}
	dev, err := text(proc+"/net/dev", 16384)
	if err != nil {
		return fail()
	}
	count := 0
	for _, line := range strings.Split(dev, "\n")[2:] {
		name, _, ok := strings.Cut(line, ":")
		if !ok {
			return fail()
		}
		name = strings.TrimSpace(name)
		if name != "lo" && name != "docker0" && !strings.HasPrefix(name, "br-") && !strings.HasPrefix(name, "veth") {
			return fail()
		}
		count++
	}
	if count < 1 || count > 64 {
		return fail()
	}
	return ns, nil
}
