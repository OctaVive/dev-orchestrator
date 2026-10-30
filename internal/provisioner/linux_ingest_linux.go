//go:build linux

package provisioner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"dev-orchestrator/internal/contracts"
	"encoding/hex"
	"encoding/json"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func validateIngestMachine(m Machine, c LinuxConfig, now time.Time) error {
	if m.Ingest == nil {
		return nil
	}
	if !c.IngestEnabled || m.Clone != nil || m.Ingest.Validate(now) != nil || m.Lease.DeploymentID != m.Ingest.Build.Clone.DeploymentID || m.Lease.ExpiresAt.After(m.Ingest.Build.ExpiresAt) {
		return ErrInvalid
	}
	st, e := trustedPath(c.ArtifactRoot, true)
	if e != nil || !st.IsDir() {
		return ErrInvalid
	}
	root, e := os.Stat(c.Root)
	if e != nil || st.Sys().(*syscall.Stat_t).Dev != root.Sys().(*syscall.Stat_t).Dev {
		return ErrInvalid
	}
	db, e := openIngestDatabase(c)
	if e != nil {
		return e
	}
	db.Close()
	return nil
}
func ingestInputFD(j contracts.BuildJob) (*os.File, error) {
	data, e := contracts.BuildInput(j, time.Now())
	if e != nil {
		return nil, e
	}
	fd, e := unix.MemfdCreate("ingest-input", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "ingest-input")
	defer f.Close()
	if _, e = f.Write(data); e != nil {
		return nil, e
	}
	if _, e = unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_SEAL); e != nil {
		return nil, e
	}
	return os.Open("/proc/self/fd/" + strconv.Itoa(fd))
}
func openIngestArtifact(c LinuxConfig, j contracts.IngestJob) (*os.File, error) {
	if j.Validate(time.Now()) != nil {
		return nil, ErrInvalid
	}
	f, e := os.OpenFile(filepath.Join(c.ArtifactRoot, j.ObjectID), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() != j.Bytes {
		f.Close()
		return nil, ErrInvalid
	}
	h := sha256.New()
	_, e = io.Copy(h, f)
	if e != nil || "sha256:"+hex.EncodeToString(h.Sum(nil)) != j.ArchiveDigest {
		f.Close()
		return nil, ErrInvalid
	}
	if _, e = f.Seek(0, 0); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func attachIngest(q *exec.Cmd, input, artifact *os.File) {
	attachClone(q, input)
	fd := len(q.ExtraFiles) + 3
	q.ExtraFiles = append(q.ExtraFiles, artifact)
	q.Args = append(q.Args, "-add-fd", "fd="+strconv.Itoa(fd)+",set=3", "-drive", "file=/dev/fdset/3,format=raw,if=virtio,readonly=on")
}
func ingestEqual(a, b *contracts.IngestJob) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
func (b *linuxBackend) IngestResult(ctx context.Context, m Machine) (contracts.ArtifactResult, bool, error) {
	l, e := b.lock(ctx)
	if e != nil {
		return contracts.ArtifactResult{}, false, e
	}
	defer unlock(l)
	s, e := b.read(m.Lease.JobID)
	if e != nil || s.Fenced || m.Ingest == nil || !sameMachine(s.Machine, m) || !time.Now().Before(m.Lease.ExpiresAt) {
		return contracts.ArtifactResult{}, false, ErrConflict
	}
	if _, active, e := b.unit(ctx, m); e != nil || !active {
		return contracts.ArtifactResult{}, false, ErrUnavailable
	}
	f, e := os.OpenFile(filepath.Join(b.c.Root, m.Lease.JobID+".ready"), os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if e != nil {
		return contracts.ArtifactResult{}, false, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > contracts.MaxBuildResultBytes+5 {
		return contracts.ArtifactResult{}, false, ErrInvalid
	}
	if e = verifyOwnedFile(f, st, s.ReadyDev, s.ReadyIno, s.ReadyFSUUID); e != nil {
		return contracts.ArtifactResult{}, false, e
	}
	data, e := io.ReadAll(io.LimitReader(f, contracts.MaxBuildResultBytes+6))
	if e != nil {
		return contracts.ArtifactResult{}, false, e
	}
	if !bytes.HasSuffix(data, []byte{'\n'}) {
		return contracts.ArtifactResult{}, false, nil
	}
	if !bytes.HasPrefix(data, []byte("M07 ")) || bytes.Count(data, []byte{'\n'}) != 1 {
		return contracts.ArtifactResult{}, false, ErrInvalid
	}
	r, e := contracts.DecodeArtifactResult(bytes.NewReader(data[4:len(data)-1]), m.Ingest.Build)
	if e == nil && r.Outcome == "admitted" && r.ArchiveDigest != m.Ingest.ArchiveDigest {
		e = ErrInvalid
	}
	return r, e == nil, e
}

func openIngestDatabase(c LinuxConfig) (*os.File, error) {
	st, e := trustedPath(c.IngestDatabase, true)
	root, rootErr := os.Stat(c.Root)
	if e != nil || rootErr != nil || st.Sys().(*syscall.Stat_t).Dev != root.Sys().(*syscall.Stat_t).Dev {
		return nil, ErrInvalid
	}

	if e != nil || !st.Mode().IsRegular() || st.Size() > 2<<30 || !contracts.ValidDigest(c.IngestDatabaseDigest) {
		return nil, ErrInvalid
	}
	f, e := os.OpenFile(c.IngestDatabase, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	h := sha256.New()
	_, e = io.Copy(h, f)
	if e != nil || "sha256:"+hex.EncodeToString(h.Sum(nil)) != c.IngestDatabaseDigest {
		f.Close()
		return nil, ErrInvalid
	}
	if _, e = f.Seek(0, 0); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func attachIngestDatabase(q *exec.Cmd, f *os.File) {
	fd := len(q.ExtraFiles) + 3
	q.ExtraFiles = append(q.ExtraFiles, f)
	q.Args = append(q.Args, "-add-fd", "fd="+strconv.Itoa(fd)+",set=4", "-drive", "file=/dev/fdset/4,format=raw,if=virtio,readonly=on")
}

// CleanupIngests reconciles only exact original build bindings in this scanner
// backend. It preserves foreign jobs and verifies each persisted ownership proof.
func (b *linuxBackend) CleanupIngests(ctx context.Context, j contracts.BuildJob) error {
	if !contracts.ValidJobID(j.Clone.JobID) || !contracts.ValidDigest(j.PolicyHash) {
		return ErrInvalid
	}
	dir, e := os.Open(b.c.Root)
	if e != nil {
		return e
	}
	defer dir.Close()
	expected, _ := json.Marshal(j)
	for {
		entries, e := dir.ReadDir(128)
		if e != nil && e != io.EOF {
			return e
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			id := strings.TrimSuffix(entry.Name(), ".json")
			if !contracts.ValidJobID(id) {
				continue
			}
			l, e := b.lock(ctx)
			if e != nil {
				return e
			}
			s, e := b.read(id)
			unlock(l)
			if e != nil {
				return e
			}
			if s.Machine.Ingest == nil {
				continue
			}
			actual, _ := json.Marshal(s.Machine.Ingest.Build)
			if !bytes.Equal(expected, actual) {
				continue
			}
			r, e := b.Cleanup(ctx, s.Machine)
			if e != nil || !r.VMAbsent || !r.ArtifactsAbsent || !r.StartFenced {
				return ErrCleanup
			}
		}
		if e == io.EOF {
			break
		}
	}
	return nil
}
