// Package runtimeisolation measures Linux runtime identities. Enrollment is
// provisioner-owned guest state, never an execution-command payload.
package runtimeisolation

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/runtimeagent"
	"golang.org/x/sys/unix"
)

const EnrollmentRoot = "/var/lib/tap-runtime/enrollments"

// Enrollment is written by the VM provisioner after reserving and measuring the
// app daemon. Rootless engine processes can read but cannot write this tree.
type Enrollment struct {
	Version     int                         `json:"version"`
	WorkerID    string                      `json:"worker_id"`
	Incarnation string                      `json:"incarnation"`
	Backend     runtimeagent.BackendBinding `json:"backend"`
}

func (e Enrollment) Valid() bool {
	return e.Version == 1 && contracts.ValidJobID(e.WorkerID) && contracts.ValidJobID(e.Incarnation) && e.Backend.Valid()
}
func ReadSmall(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, runtimeagent.ErrUnsupported
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, runtimeagent.ErrUnsupported
	}
	return b, nil
}
func ReadEnrollment(app string) (Enrollment, error) {
	var e Enrollment
	if !contracts.ValidJobID(app) {
		return e, runtimeagent.ErrDenied
	}
	// In an inherited rootless namespace the initial root appears as overflowuid.
	// Require the owner of the immutable VM root, not namespace UID zero. Validate
	// every ancestor so a writable directory cannot substitute the enrollment.
	var rootStat unix.Stat_t
	if unix.Stat("/", &rootStat) != nil {
		return e, runtimeagent.ErrDenied
	}
	path := EnrollmentRoot + "/" + app + ".json"
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		var st unix.Stat_t
		if unix.Lstat(p, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != rootStat.Uid || st.Mode&0022 != 0 {
			return e, runtimeagent.ErrDenied
		}
		if p == "/" {
			break
		}
	}
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return e, runtimeagent.ErrDenied
	}
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != rootStat.Uid || st.Mode&0022 != 0 || st.Size > 8192 {
		return e, runtimeagent.ErrDenied
	}
	b, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil || len(b) > 8192 {
		return e, runtimeagent.ErrDenied
	}
	e, err = contracts.DecodeConfiguration[Enrollment](strings.NewReader(string(b)))
	if err != nil || !e.Valid() || e.Backend.AppID != app {
		return Enrollment{}, runtimeagent.ErrDenied
	}
	return e, nil
}

func StartTicks(raw []byte) (uint64, error) {
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return 0, runtimeagent.ErrDenied
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 20 {
		return 0, runtimeagent.ErrDenied
	}
	n, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || n == 0 {
		return 0, runtimeagent.ErrDenied
	}
	return n, nil
}

type Mapping struct{ Inner, Outer, Size uint64 }

func ParseMappings(raw []byte) ([]Mapping, error) {
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) < 1 || len(lines) > 8 {
		return nil, runtimeagent.ErrDenied
	}
	var seen []Mapping
	hasUser := false
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) != 3 {
			return nil, runtimeagent.ErrDenied
		}
		var v [3]uint64
		for i, s := range f {
			n, err := strconv.ParseUint(s, 10, 32)
			if err != nil {
				return nil, runtimeagent.ErrDenied
			}
			v[i] = n
		}
		m := Mapping{v[0], v[1], v[2]}
		if m.Outer == 0 || m.Size == 0 || m.Inner+m.Size > 1<<32 || m.Outer+m.Size > 1<<32 {
			return nil, runtimeagent.ErrDenied
		}
		for _, p := range seen {
			if m.Inner < p.Inner+p.Size && p.Inner < m.Inner+m.Size || m.Outer < p.Outer+p.Size && p.Outer < m.Outer+m.Size {
				return nil, runtimeagent.ErrDenied
			}
		}
		if m.Inner <= 1000 && 1000 < m.Inner+m.Size {
			hasUser = true
		}
		seen = append(seen, m)
	}
	if !hasUser {
		return nil, runtimeagent.ErrDenied
	}
	return seen, nil
}
func MappedID(raw []byte, id uint64) (uint64, error) {
	maps, err := ParseMappings(raw)
	if err != nil {
		return 0, err
	}
	for _, m := range maps {
		if id >= m.Inner && id < m.Inner+m.Size {
			return m.Outer + id - m.Inner, nil
		}
	}
	return 0, runtimeagent.ErrDenied
}

// VerifyInherited measures the wrapper's effective namespace and mappings; it
// never synthesizes mappings from OCI defaults or joins a caller-selected path.
func VerifyInherited(e Enrollment) error {
	if !e.Valid() {
		return runtimeagent.ErrDenied
	}
	b := e.Backend
	boot, err := ReadSmall("/proc/sys/kernel/random/boot_id", 128)
	if err != nil || strings.TrimSpace(string(boot)) != b.BootID {
		return runtimeagent.ErrDenied
	}
	ns, err := os.Readlink("/proc/self/ns/user")
	if err != nil || ns != b.UserNamespace || ns == b.InitialUserNamespace {
		return runtimeagent.ErrDenied
	}
	for _, m := range []struct{ name, hash string }{{"uid_map", b.UIDMapHash}, {"gid_map", b.GIDMapHash}} {
		raw, err := ReadSmall("/proc/self/"+m.name, 4096)
		if err != nil || contracts.Digest(raw) != m.hash {
			return runtimeagent.ErrDenied
		}
		if _, err = ParseMappings(raw); err != nil {
			return runtimeagent.ErrDenied
		}
	}
	raw, err := ReadSmall("/proc/"+strconv.Itoa(b.DaemonPID)+"/stat", 4096)
	if err != nil {
		return runtimeagent.ErrDenied
	}
	ticks, err := StartTicks(raw)
	if err != nil || ticks != b.DaemonStartTicks {
		return runtimeagent.ErrDenied
	}
	daemonNS, err := os.Readlink("/proc/" + strconv.Itoa(b.DaemonPID) + "/ns/user")
	if err != nil || daemonNS != ns {
		return runtimeagent.ErrDenied
	}
	return nil
}

// EncodeEnrollment is for the root provisioner, not a runtime RPC. Atomic
// installation is performed by provisioning after private directory validation.
func EncodeEnrollment(e Enrollment) ([]byte, error) {
	if !e.Valid() {
		return nil, runtimeagent.ErrDenied
	}
	return json.Marshal(e)
}
