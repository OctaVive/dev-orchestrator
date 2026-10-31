package runtimeengine

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/runtimeagent"
	"dev-orchestrator/internal/runtimeisolation"
	"golang.org/x/sys/unix"
)

// LinuxObserver measures app daemons from the VM's initial user namespace. Run
// as the dedicated runtime account. It never joins namespaces or runs commands.
// This verifies backend identity only, not workload security/readiness.
type LinuxObserver struct{}

func smallFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, runtimeagent.ErrUnsupported
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) > 4096 {
		return nil, runtimeagent.ErrUnsupported
	}
	return b, nil
}
func startTicks(raw []byte) (uint64, error) { return runtimeisolation.StartTicks(raw) }
func safeMapping(raw []byte) bool           { _, err := runtimeisolation.ParseMappings(raw); return err == nil }

// backendArgs checks the fixed ownership options of the running daemon. More
// than one listener/data root is not an app-scoped backend.
func backendArgs(raw []byte, b runtimeagent.BackendBinding) bool {
	args := strings.Split(string(raw), "\x00")
	roots, hosts := 0, 0
	for i := 1; i < len(args); i++ {
		a := args[i]
		for _, option := range []string{"--data-root", "--host", "-H"} {
			value := ""
			if a == option {
				i++
				if i >= len(args) {
					return false
				}
				value = args[i]
			} else if strings.HasPrefix(a, option+"=") {
				value = strings.TrimPrefix(a, option+"=")
			} else {
				continue
			}
			if option == "--data-root" {
				roots++
				if value != b.DataRoot {
					return false
				}
			} else {
				hosts++
				if value != "unix://"+b.Socket {
					return false
				}
			}
			break
		}
	}
	return roots == 1 && hosts == 1
}
func privatePath(path string, socket bool) bool {
	for p := path; ; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil || st.Mode()&os.ModeSymlink != 0 {
			return false
		}
		var parent unix.Stat_t
		if unix.Lstat(p, &parent) != nil || (parent.Uid != uint32(os.Geteuid()) && parent.Uid != 0) || (st.Mode().Perm()&0022 != 0 && !(parent.Uid == 0 && st.Mode()&os.ModeSticky != 0)) {
			return false
		}
		if p == path || p == filepath.Dir(path) && socket {
			var u unix.Stat_t
			if unix.Lstat(p, &u) != nil || u.Uid != uint32(os.Geteuid()) || st.Mode().Perm()&0077 != 0 {
				return false
			}
		}
		if p == path && socket {
			if st.Mode()&os.ModeSocket == 0 {
				return false
			}
		} else if !st.IsDir() {
			return false
		}
		if p == filepath.Dir(p) {
			return true
		}
	}
}
func (LinuxObserver) VerifyBackend(ctx context.Context, b runtimeagent.BackendBinding) error {
	stage := "paths"
	fail := func() error { return fmt.Errorf("runtime_backend_%s_denied", stage) }
	if ctx.Err() != nil || !b.Valid() || os.Geteuid() == 0 || !privatePath(b.Socket, true) || !privatePath(b.DataRoot, false) {
		return fail()
	}
	stage = "boot"
	boot, err := smallFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) != b.BootID {
		return fail()
	}
	// The initial identity is enrolled by the trusted VM provisioner. An
	// unprivileged account cannot generally read /proc/1/ns/user (ptrace access
	// checks), so compare its own namespace with that boot-bound identity.
	stage = "namespace"
	initial := b.InitialUserNamespace
	self, err := os.Readlink("/proc/self/ns/user")
	if err != nil || self != initial {
		return fail()
	}
	proc := fmt.Sprintf("/proc/%d", b.DaemonPID)
	stage = "process"
	verify := func() error {
		args, err := smallFile(proc + "/cmdline")
		if err != nil || !backendArgs(args, b) {
			return fail()
		}
		raw, err := smallFile(proc + "/stat")
		if err != nil {
			return fail()
		}
		start, err := startTicks(raw)
		if err != nil || start != b.DaemonStartTicks {
			return fail()
		}
		ns, err := os.Readlink(proc + "/ns/user")
		if err != nil || ns != b.UserNamespace || ns == initial {
			return fail()
		}
		for _, m := range []struct{ name, hash string }{{"uid_map", b.UIDMapHash}, {"gid_map", b.GIDMapHash}} {
			raw, err := smallFile(proc + "/" + m.name)
			if err != nil || !safeMapping(raw) || contracts.Digest(raw) != m.hash {
				return fail()
			}
		}
		return nil
	}
	if verify() != nil {
		return fail()
	}
	stage = "socket"
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", b.Socket)
	if err != nil {
		return fail()
	}
	defer conn.Close()
	u, ok := conn.(*net.UnixConn)
	if !ok {
		return fail()
	}
	raw, err := u.SyscallConn()
	if err != nil {
		return fail()
	}
	var cred *unix.Ucred
	var credErr error
	if raw.Control(func(fd uintptr) { cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }) != nil || credErr != nil || cred == nil || int(cred.Pid) != b.DaemonPID || cred.Uid != uint32(os.Geteuid()) {
		return fail()
	}
	if verify() != nil || ctx.Err() != nil {
		return fail()
	}
	return nil
}
