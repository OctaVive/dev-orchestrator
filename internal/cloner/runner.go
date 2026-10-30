//go:build linux

// Package cloner parses untrusted Git data only inside a disposable build VM.
// It must never be used as a management-host clone implementation.
package cloner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"dev-orchestrator/internal/contracts"
)

var errDenied = errors.New("clone denied")
var errLimit = errors.New("clone limit")

type boundedBuffer struct {
	buffer   bytes.Buffer
	limit    int64
	cancel   context.CancelFunc
	exceeded bool
}

func (b *boundedBuffer) Len() int      { return b.buffer.Len() }
func (b *boundedBuffer) Bytes() []byte { return b.buffer.Bytes() }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if int64(b.Len()+len(p)) > b.limit {
		b.exceeded = true
		b.cancel()
		return 0, errLimit
	}
	return b.buffer.Write(p)
}

type runner struct {
	ctx    context.Context
	cancel context.CancelFunc
	env    []string
	dir    string
	limits contracts.CloneLimits
}

func (r *runner) git(limit int64, args ...string) ([]byte, error) {
	fixed := []string{"-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "-c", "credential.helper=", "-c", "core.hooksPath=/dev/null", "-c", "core.attributesFile=/dev/null", "-c", "http.followRedirects=false", "-c", "http.sslVerify=true", "-c", "http.sslCAInfo=/build-ca.pem", "-c", "http.maxRequests=1", "-c", "http.lowSpeedLimit=1", "-c", "http.lowSpeedTime=15", "-c", "submodule.recurse=false", "-c", "fetch.recurseSubmodules=false", "-c", "fetch.fsckObjects=true", "-c", "transfer.fsckObjects=true", "-c", "gc.auto=0", "-c", "maintenance.auto=false", "-c", "protocol.version=2"}
	c := exec.CommandContext(r.ctx, "/usr/bin/git", append(fixed, args...)...)
	c.Dir = r.dir
	c.Env = r.env
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	c.Cancel = func() error {
		if c.Process != nil {
			return syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	c.WaitDelay = time.Second
	out := &boundedBuffer{limit: limit, cancel: r.cancel}
	diagnostic := &boundedBuffer{limit: 64 << 10, cancel: r.cancel}
	c.Stdout = out
	c.Stderr = diagnostic
	e := c.Run()
	if out.exceeded || diagnostic.exceeded {
		return nil, errLimit
	}
	if e != nil {
		return nil, errDenied
	}
	return out.Bytes(), nil
}

// Run requires the unprivileged, template-created guest workspace marker. emit
// receives resolution before fetch and one final frame. No build runs here.
func Run(parent context.Context, j contracts.CloneJob, emit func(contracts.CloneResult) error) contracts.CloneResult {
	result := contracts.NewCloneResult(j)
	if j.Validate(time.Now()) != nil {
		result.Outcome = "denied"
		return result
	}
	marker, e := os.Lstat("/run/orchestrator-clone-worker")
	if e != nil || !marker.IsDir() || marker.Mode()&0022 != 0 || marker.Sys().(*syscall.Stat_t).Uid != 0 || os.Geteuid() == 0 {
		result.Outcome = "denied"
		return result
	}
	deadline := time.Now().Add(time.Duration(j.Policy.Limits.Seconds) * time.Second)
	if j.ExpiresAt.Before(deadline) {
		deadline = j.ExpiresAt
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	work, e := os.MkdirTemp("/work", "clone-")
	if e != nil {
		return result
	}
	// /work is guest-owned ephemeral storage. Failure never publishes a context.
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(work)
		}
	}()
	home := filepath.Join(work, "home")
	repo := filepath.Join(work, "repo")
	empty := filepath.Join(work, "empty")
	for _, p := range []string{home, repo, empty} {
		if os.Mkdir(p, 0700) != nil {
			return result
		}
	}
	u, _ := url.Parse(j.RepositoryURL)
	proxy, e := newMeterProxy(ctx, u.Hostname()+":443", j.Policy.Limits.AdvertisementBytes, cancel)
	if e != nil {
		return result
	}
	defer proxy.close()
	r := runner{ctx: ctx, cancel: cancel, dir: repo, limits: j.Policy.Limits, env: []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=" + home, "XDG_CONFIG_HOME=" + home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=/bin/false", "GIT_NO_REPLACE_OBJECTS=1", "GIT_LFS_SKIP_SMUDGE=1", "GIT_ATTR_NOSYSTEM=1", "GIT_EXEC_PATH=/usr/lib/git-core", "https_proxy=http://" + proxy.listener.Addr().String(), "no_proxy=", "GIT_CONFIG_COUNT=0"}}
	fail := func(err error) contracts.CloneResult {
		result.ContextID = ""
		result.Outcome = "denied"
		if errors.Is(err, errLimit) || proxy.exceeded.Load() {
			result.Outcome = "limit"
		} else if parent.Err() != nil {
			result.Outcome = "cancelled"
		} else if ctx.Err() != nil {
			result.Outcome = "timeout"
		}
		return result
	}
	if _, e = r.git(4096, "init", "--bare", "--object-format=sha1", "--template="+empty, "."); e != nil {
		return fail(e)
	}
	advertisement, e := r.git(j.Policy.Limits.AdvertisementBytes, "ls-remote", "--heads", "--", j.RepositoryURL)
	if e != nil {
		return fail(e)
	}
	sha, e := resolveBranch(advertisement, j.Branch, j.Policy.Limits.Refs)
	if e != nil {
		return fail(e)
	}
	result.SHA = sha
	result.Outcome = "resolved"
	if emit == nil || emit(result) != nil {
		return fail(errDenied)
	}
	proxy.maximum.Store(j.Policy.Limits.TransferBytes)
	if _, e = r.git(4096, "fetch", "--progress", "--depth=1", "--no-tags", "--no-recurse-submodules", "--no-write-fetch-head", "--", j.RepositoryURL, sha+":refs/heads/pinned"); e != nil {
		return fail(e)
	}
	format, e := r.git(128, "rev-parse", "--show-object-format")
	if e != nil || string(format) != "sha1\n" {
		return fail(errDenied)
	}
	actual, e := r.git(128, "rev-parse", "--verify", "refs/heads/pinned^{commit}")
	if e != nil || string(actual) != sha+"\n" {
		return fail(errDenied)
	}
	objects, e := r.git(int64(j.Policy.Limits.Objects)*96+1, "cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objecttype) %(objectsize)")
	if e != nil {
		return fail(e)
	}
	if e = validateObjects(objects, j.Policy.Limits); e != nil {
		return fail(e)
	}
	tree, e := r.git(int64(j.Policy.Limits.Entries)*(int64(j.Policy.Limits.PathBytes)+100)+1, "ls-tree", "-r", "-t", "-z", "--full-tree", sha)
	if e != nil {
		return fail(e)
	}
	entries, e := parseTree(tree, j.Policy.Limits)
	if e != nil {
		return fail(e)
	}
	contextDir := filepath.Join(work, "context")
	count, size, e := r.export(entries, j, contextDir)
	if e != nil {
		return fail(e)
	}
	if ctx.Err() != nil {
		return fail(ctx.Err())
	}
	h := sha256.Sum256([]byte(j.JobID + ":" + j.PolicyHash + ":" + sha + ":" + j.BuildContext))
	result.ContextID = hex.EncodeToString(h[:])
	result.Entries = count
	result.Bytes = size
	result.Outcome = "success"
	// Fixed guest-local descriptor for M07. Never accepted as a management path.
	manifest := []byte(result.ContextID + "\n" + contextDir + "\n")
	if os.WriteFile("/work/context-ready.new", manifest, 0600) != nil || os.Rename("/work/context-ready.new", "/work/context-ready") != nil {
		return fail(errDenied)
	}
	success = true
	return result
}

func resolveBranch(data []byte, branch string, max int) (string, error) {
	lines := bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
	if len(lines) > max {
		return "", errLimit
	}
	found := ""
	seen := map[string]bool{}
	for _, line := range lines {
		parts := bytes.Split(line, []byte("\t"))
		if len(parts) != 2 || !contracts.ValidSHA1(string(parts[0])) {
			return "", errDenied
		}
		ref := string(parts[1])
		if !strings.HasPrefix(ref, "refs/heads/") || seen[ref] || !contracts.ValidCloneInput("https://example.com/r", strings.TrimPrefix(ref, "refs/heads/"), "Dockerfile", ".") {
			return "", errDenied
		}
		seen[ref] = true
		if ref == "refs/heads/"+branch {
			found = string(parts[0])
		}
	}
	if found == "" {
		return "", errDenied
	}
	return found, nil
}
func validateObjects(data []byte, l contracts.CloneLimits) error {
	lines := bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
	if len(lines) > l.Objects {
		return errLimit
	}
	var expanded int64
	for _, line := range lines {
		p := strings.Fields(string(line))
		if len(p) != 3 || !contracts.ValidSHA1(p[0]) || (p[1] != "blob" && p[1] != "tree" && p[1] != "commit") {
			return errDenied
		}
		n, e := strconv.ParseInt(p[2], 10, 64)
		if e != nil || n < 0 {
			return errDenied
		}
		if n > l.ObjectBytes || n > l.ExpandedBytes-expanded {
			return errLimit
		}
		expanded += n
	}
	return nil
}
