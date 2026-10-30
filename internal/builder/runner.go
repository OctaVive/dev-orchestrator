//go:build linux

// Package builder executes only within a disposable build guest.
package builder

import (
	"bytes"
	"context"
	"dev-orchestrator/internal/configguest"
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/policy"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

var ErrDenied = errors.New("build denied")
var ErrLimit = errors.New("build limit")
var ErrPolicy = errors.New("build policy")
var ErrDaemon = errors.New("build daemon")
var ErrExecution = errors.New("build execution")

// ValidateDockerfile is a deliberately small M07 fixture profile. M08 owns a
// general normalizer. The fixed frontend and daemon remain separate boundaries.
func ValidateDockerfile(data []byte) error {
	if len(data) == 0 || len(data) > 64<<10 || bytes.ContainsAny(data, "\x00\r\\`") {
		return ErrDenied
	}
	from := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			return ErrDenied
		}
		words := strings.Fields(line)
		if len(words) < 2 {
			return ErrDenied
		}
		op := strings.ToUpper(words[0])
		arg := strings.TrimSpace(line[len(words[0]):])
		if strings.HasPrefix(arg, "--") || strings.Contains(arg, "<<") {
			return ErrDenied
		}
		switch op {
		case "FROM":
			if from || len(words) != 2 {
				return ErrDenied
			}
			from = true
			if words[1] != "scratch" {
				at := strings.LastIndex(words[1], "@")
				if at < 1 || !contracts.ValidDigest(words[1][at+1:]) || strings.ContainsAny(words[1], "$\\") {
					return ErrDenied
				}
			}
		case "COPY", "RUN", "USER", "WORKDIR", "ENV", "EXPOSE", "CMD", "ENTRYPOINT", "LABEL":
			if !from {
				return ErrDenied
			}
		default:
			return ErrDenied
		}
	}
	if !from {
		return ErrDenied
	}
	return nil
}

type output struct {
	mu     sync.Mutex
	n      int
	max    int
	cancel context.CancelFunc
	over   bool
}

func (o *output) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(p) > o.max-o.n {
		o.over = true
		o.cancel()
		return 0, ErrLimit
	}
	o.n += len(p)
	return len(p), nil
}
func command(ctx context.Context, cancel context.CancelFunc, env []string, exe string, args ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, exe, args...)
	c.Env = env
	c.Dir = "/work"
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	c.Cancel = func() error {
		if c.Process != nil {
			return syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	c.WaitDelay = time.Second
	c.Stdout = &output{max: 256 << 10, cancel: cancel}
	c.Stderr = &output{max: 256 << 10, cancel: cancel}
	return c
}

// Run returns a guest-local opaque export path to the uploader in this same
// process trust domain; it is never sent to management as a filesystem path.
func Run(parent context.Context, j contracts.BuildJob) (string, error) {
	if j.Validate(time.Now()) != nil || os.Geteuid() == 0 {
		return "", ErrDenied
	}
	marker, e := os.Lstat("/run/orchestrator-build-worker")
	if e != nil || !marker.IsDir() || marker.Mode()&0022 != 0 || marker.Sys().(*syscall.Stat_t).Uid != 0 {
		return "", ErrDenied
	}
	handoff, e := os.ReadFile("/work/context-ready")
	if e != nil || len(handoff) > 8192 {
		return "", ErrDenied
	}
	parts := strings.Split(strings.TrimSuffix(string(handoff), "\n"), "\n")
	if len(parts) != 2 || parts[0] != j.ContextID || !strings.HasPrefix(parts[1], "/work/clone-") {
		return "", ErrDenied
	}
	contextDir := parts[1]
	resolved, e := filepath.EvalSymlinks(contextDir)
	if e != nil || resolved != contextDir {
		return "", ErrDenied
	}
	filename := j.Dockerfile
	if j.Clone.Configuration != nil {
		config := j.Clone.ConfigPath
		if j.Clone.BuildContext != "." {
			config = strings.TrimPrefix(config, j.Clone.BuildContext+"/")
		}
		p, e := configguest.Analyze(parent, contextDir, j.Clone.Configuration.Mode, config)
		if e != nil || policy.PlanHash(p) != j.PlanHash {
			return "", ErrPolicy
		}
		found := false
		for _, s := range p.Services {
			if s.Build != nil {
				if filepath.Join(s.Build.Context, s.Build.Dockerfile) != j.Dockerfile {
					return "", ErrPolicy
				}
				contextDir = filepath.Join(contextDir, s.Build.Context)
				filename = s.Build.Dockerfile
				found = true
			}
		}
		if !found {
			return "", ErrPolicy
		}
	}
	dockerfile := filepath.Join(contextDir, filename)
	f, e := os.Open(dockerfile)
	if e != nil {
		return "", ErrDenied
	}
	data, e := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	f.Close()
	validate := ValidateDockerfile
	if j.Clone.Configuration != nil {
		validate = configguest.Dockerfile
	}
	if e != nil || validate(data) != nil {
		return "", ErrPolicy
	}
	deadline := time.Now().Add(time.Duration(j.Policy.BuildSeconds) * time.Second)
	if j.ExpiresAt.Before(deadline) {
		deadline = j.ExpiresAt
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	work, e := os.MkdirTemp("/work", "build-")
	if e != nil {
		return "", e
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(work)
		}
	}()
	env := []string{"PATH=/usr/bin:/bin", "HOME=" + work, "XDG_RUNTIME_DIR=/run/user/1000", "LANG=C", "SSL_CERT_FILE=/build-ca.pem", "HTTPS_PROXY=http://192.0.2.1:8443", "HTTP_PROXY=http://192.0.2.1:8443", "NO_PROXY="}
	sourcePolicy := filepath.Join(work, "source-policy.json")
	policy := []byte(`{"version":1,"rules":[{"action":"DENY","selector":{"identifier":"*"}},{"action":"ALLOW","selector":{"identifier":"local://context","match_type":"EXACT"}},{"action":"ALLOW","selector":{"identifier":"local://dockerfile","match_type":"EXACT"}},{"action":"ALLOW","selector":{"identifier":"^docker-image://[^@]+@sha256:[a-f0-9]{64}$","match_type":"REGEX"}}]}`)
	if os.WriteFile(sourcePolicy, policy, 0400) != nil {
		return "", ErrPolicy
	}
	socket := filepath.Join(work, "buildkit.sock")
	daemon := command(ctx, cancel, env, "/usr/bin/rootlesskit", "--copy-up=/etc", "--copy-up=/run", "--state-dir="+filepath.Join(work, "rootless"), "/usr/bin/buildkitd", "--rootless", "--root", filepath.Join(work, "state"), "--addr", "unix://"+socket, "--oci-worker=true", "--containerd-worker=false", "--oci-worker-snapshotter=native", "--oci-worker-binary=/usr/bin/buildkit-runc", "--oci-worker-net=host", "--oci-worker-platform=linux/amd64", "--cdi-disabled")
	if e = daemon.Start(); e != nil {
		return "", ErrDaemon
	}
	done := make(chan error, 1)
	go func() { done <- daemon.Wait() }()
	defer func() { cancel(); syscall.Kill(-daemon.Process.Pid, syscall.SIGKILL); <-done }()
	ready := false
	for n := 0; n < 100; n++ {
		if st, e := os.Lstat(socket); e == nil && st.Mode()&os.ModeSocket != 0 {
			ready = true
			break
		}
		select {
		case <-ctx.Done():
			return "", ErrDenied
		case <-time.After(100 * time.Millisecond):
		}
	}
	if !ready {
		return "", ErrDaemon
	}
	dest := filepath.Join(work, "image.tar")
	build := command(ctx, cancel, env, "/usr/bin/buildctl", "--addr", "unix://"+socket, "build", "--source-policy-file", sourcePolicy, "--frontend=dockerfile.v0", "--local", "context="+contextDir, "--local", "dockerfile="+contextDir, "--opt", "filename="+filename, "--opt", "cmdline=", "--opt", "platform=linux/amd64", "--opt", "force-network-mode=none", "--output", "type=oci,dest="+dest+",oci-mediatypes=true,compression=gzip")
	if e = build.Run(); e != nil {
		return "", ErrExecution
	}
	st, e := os.Stat(dest)
	if e != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > j.Policy.Limits.UploadBytes {
		return "", ErrLimit
	}
	ok = true
	return dest, nil
}
