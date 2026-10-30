//go:build linux

package provisioner

import (
	"bytes"
	"context"
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/policy"
	"encoding/json"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"time"
)

// AuthorizeBuild sends only a predeclared, identity-bound build. The control
// file is host-owned, private, capped and removed with the owned VM resources.
func (b *linuxBackend) AuthorizeBuild(ctx context.Context, m Machine, a contracts.BuildAuthorization) error {
	if m.Clone == nil || a.Validate(*m.Clone, time.Now()) != nil {
		return ErrInvalid
	}
	frames, e := b.CloneResults(ctx, m)
	if e != nil {
		return e
	}
	if len(frames) != 2 || frames[1].Outcome != "success" || frames[1].SHA != a.Job.SHA || frames[1].ContextID != a.Job.ContextID || (a.Job.Clone.Configuration != nil && (frames[1].Plan == nil || policy.PlanHash(*frames[1].Plan) != a.Job.PlanHash)) {
		return ErrConflict
	}
	if frames[1].Plan != nil {
		selected, e := policy.BuildPath(*frames[1].Plan)
		if e != nil || selected != a.Job.Dockerfile {
			return ErrConflict
		}
	}
	l, e := b.lock(ctx)
	if e != nil {
		return e
	}
	defer unlock(l)
	s, e := b.read(m.Lease.JobID)
	if e != nil || s.Fenced || !sameMachine(s.Machine, m) {
		return ErrConflict
	}
	if _, active, e := b.unit(ctx, m); e != nil || !active {
		return ErrUnavailable
	}
	f, e := os.OpenFile(filepath.Join(b.c.Root, m.Lease.JobID+".authorize"), os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return ErrUnavailable
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > contracts.MaxBuildJobBytes+513 {
		return ErrConflict
	}
	if e = verifyOwnedFile(f, st, s.AuthDev, s.AuthIno, s.AuthFSUUID); e != nil {
		return e
	}
	data, e := json.Marshal(a)
	if e != nil || len(data) > contracts.MaxBuildJobBytes+512 {
		return ErrInvalid
	}
	data = append(data, '\n')
	if st.Size() > 0 {
		prior, e := io.ReadAll(io.LimitReader(f, int64(len(data))+1))
		if e == nil && bytes.Equal(prior, data) {
			return nil
		}
		return ErrConflict
	}
	if _, e = f.Write(data); e != nil {
		return e
	}
	return f.Sync()
}
func (b *linuxBackend) BuildResult(ctx context.Context, m Machine, j contracts.BuildJob) (contracts.BuildResult, bool, error) {
	if _, e := b.CloneResults(ctx, m); e != nil {
		return contracts.BuildResult{}, false, e
	}
	l, e := b.lock(ctx)
	if e != nil {
		return contracts.BuildResult{}, false, e
	}
	defer unlock(l)
	s, e := b.read(m.Lease.JobID)
	if e != nil || s.Fenced || !sameMachine(s.Machine, m) {
		return contracts.BuildResult{}, false, ErrConflict
	}
	f, e := os.OpenFile(filepath.Join(b.c.Root, m.Lease.JobID+".ready"), os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if e != nil {
		return contracts.BuildResult{}, false, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || st.Size() > cloneSerialLimit {
		return contracts.BuildResult{}, false, ErrInvalid
	}
	if e = verifyOwnedFile(f, st, s.ReadyDev, s.ReadyIno, s.ReadyFSUUID); e != nil {
		return contracts.BuildResult{}, false, e
	}
	data, e := io.ReadAll(io.LimitReader(f, cloneSerialLimit+1))
	if e != nil {
		return contracts.BuildResult{}, false, e
	}
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if bytes.HasPrefix(line, []byte("M07 ")) {
			r, e := contracts.DecodeBuildResult(bytes.NewReader(line[4:]), j)
			return r, e == nil, e
		}
	}
	return contracts.BuildResult{}, false, nil
}
