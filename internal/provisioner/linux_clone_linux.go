//go:build linux

package provisioner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"dev-orchestrator/internal/contracts"
	"golang.org/x/sys/unix"
)

const cloneSerialLimit = 3 * (contracts.MaxCloneResultBytes + 5)

func validateCloneMachine(m Machine, c LinuxConfig, now time.Time) error {
	if m.Clone == nil {
		return nil
	}
	j := m.Clone
	if !c.CloneEnabled || c.NetworkMode != "broker-v1" || j.Validate(now) != nil || j.JobID != m.Lease.JobID || j.LeaseID != m.Lease.CommandID || j.DeploymentID != m.Lease.DeploymentID || j.TemplateDigest != m.Lease.Template.Digest || j.ExpiresAt.After(m.Lease.ExpiresAt) {
		return ErrInvalid
	}
	p, e := loadEgressPolicy(c)
	if e != nil {
		return e
	}
	if j.Build != nil {
		if j.Build.Policy.EgressPolicyHash != c.EgressPolicyHash {
			return ErrInvalid
		}
		u, _ := url.Parse(j.Build.Policy.UploadOrigin)
		found := false
		for _, host := range p.Hosts {
			if host == u.Hostname() {
				found = true
			}
		}
		if !found {
			return ErrInvalid
		}
	}
	for _, host := range j.Policy.Hosts {
		found := false
		for _, approved := range p.Hosts {
			if host == approved {
				found = true
			}
		}
		if !found {
			return ErrInvalid
		}
	}
	return nil
}

func cloneInputFD(j contracts.CloneJob) (*os.File, error) {
	data, e := contracts.CloneInput(j, time.Now())
	if e != nil {
		return nil, ErrInvalid
	}
	fd, e := unix.MemfdCreate("clone-input", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "clone-input")
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
		}
	}()
	if _, e = f.Write(data); e != nil {
		return nil, e
	}
	if _, e = f.Seek(0, 0); e != nil {
		return nil, e
	}
	if _, e = unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_SEAL); e != nil {
		return nil, e
	}
	readonly, e := os.Open("/proc/self/fd/" + strconv.Itoa(fd))
	if e != nil {
		return nil, e
	}
	_ = f.Close()
	ok = true
	return readonly, nil
}

func attachClone(q *exec.Cmd, input *os.File) {
	fd := len(q.ExtraFiles) + 3
	q.ExtraFiles = append(q.ExtraFiles, input)
	q.Args = append(q.Args, "-add-fd", "fd="+strconv.Itoa(fd)+",set=2", "-drive", "file=/dev/fdset/2,format=raw,if=virtio,readonly=on")
	// ttyS0 remains disabled; ttyS1 carries only framed runner results.
	q.Args = append(q.Args, "-chardev", "stdio,id=clone,mux=off,signal=off", "-device", "isa-serial,chardev=clone,index=1")
}

// cloneSerial drains at most a fixed cap into the already-owned readiness file.
// Overflow kills this QEMU, and is never treated as a complete result.
type cloneSerial struct {
	mu       sync.Mutex
	data     []byte
	file     *os.File
	overflow bool
}

func (s *cloneSerial) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.overflow || len(p) > cloneSerialLimit-len(s.data) {
		s.overflow = true
		return 0, ErrInvalid
	}
	s.data = append(s.data, p...)
	if s.file != nil {
		if _, e := s.file.Write(p); e != nil {
			return 0, e
		}
		if e := s.file.Sync(); e != nil {
			return 0, e
		}
	}
	return len(p), nil
}
func (s *cloneSerial) publish(f *os.File) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.overflow {
		return ErrInvalid
	}
	s.file = f
	if _, e := f.Write(s.data); e != nil {
		return e
	}
	return f.Sync()
}

// CloneResults reads guest assertions, after verifying the owned journal and
// result inode. An incomplete frame is pending; malformed or excess data denies.
func (b *linuxBackend) CloneResults(ctx context.Context, m Machine) ([]contracts.CloneResult, error) {
	if !validMachine(m, b.c) {
		return nil, ErrInvalid
	}
	l, e := b.lock(ctx)
	if e != nil {
		return nil, e
	}
	defer unlock(l)
	s, e := b.read(m.Lease.JobID)
	if e != nil || s.Fenced || !sameMachine(s.Machine, m) || s.Machine.Clone == nil || !time.Now().Before(s.Machine.Clone.ExpiresAt) {
		return nil, ErrConflict
	}
	f, e := os.OpenFile(filepath.Join(b.c.Root, m.Lease.JobID+".ready"), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	i, e := f.Stat()
	if e != nil || !i.Mode().IsRegular() || i.Size() > cloneSerialLimit {
		return nil, ErrInvalid
	}
	if e = verifyOwnedFile(f, i, s.ReadyDev, s.ReadyIno, s.ReadyFSUUID); e != nil {
		return nil, e
	}
	data, e := io.ReadAll(io.LimitReader(f, cloneSerialLimit+1))
	if e != nil || len(data) > cloneSerialLimit {
		return nil, ErrInvalid
	}
	frames, e := parseCloneFrames(data, *s.Machine.Clone)
	if e != nil {
		return nil, e
	}
	if _, active, e := b.unit(ctx, m); e != nil || !active {
		return nil, ErrUnavailable
	}
	return frames, nil
}
func parseCloneFrames(data []byte, j contracts.CloneJob) ([]contracts.CloneResult, error) {
	var result []contracts.CloneResult
	for len(data) > 0 {
		line, rest, ok := bytes.Cut(data, []byte{'\n'})
		if !ok {
			if len(line) > contracts.MaxCloneResultBytes+4 {
				return nil, ErrInvalid
			}
			break
		}
		data = rest
		if bytes.HasPrefix(line, []byte("M07 ")) && j.Build != nil {
			if len(result) != 2 || result[1].Outcome != "success" || len(line) > 1028 || len(data) > 0 {
				return nil, ErrInvalid
			}
			var job contracts.BuildJob
			job.Clone = j
			job.PolicyHash = j.Build.Policy.Hash()
			if _, e := contracts.DecodeBuildResult(bytes.NewReader(line[4:]), job); e != nil {
				return nil, ErrInvalid
			}
			continue
		}
		if !bytes.HasPrefix(line, []byte("M06 ")) {
			return nil, ErrInvalid
		}
		r, e := contracts.DecodeCloneResult(bytes.NewReader(line[4:]), j)
		if e != nil {
			return nil, ErrInvalid
		}
		if len(result) > 1 || len(result) == 1 && (result[0].Outcome != "resolved" || r.Outcome == "resolved" || r.SHA != result[0].SHA) || len(result) == 0 && r.Outcome == "success" {
			return nil, ErrInvalid
		}
		result = append(result, r)
	}
	return result, nil
}

func cloneEqual(a, b *contracts.CloneJob) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
