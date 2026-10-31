// Package runtimenet provides a fixed private relay/health fixture. Only the
// privileged measurement service can pass an already validated namespace FD.
// No PID, namespace path, executable, host address or generic command is accepted.
package runtimenet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/policy"
	"dev-orchestrator/internal/runtimeagent"
	"golang.org/x/sys/unix"
)

const Binary = "/usr/local/bin/tap-runtime-net"
const RelayRoot = "/run/tap-runtime/relay"
const RelayUID = 1001

type Configuration struct {
	Mode      string    `json:"mode"`
	AppID     string    `json:"app_id"`
	OwnerID   string    `json:"owner_id"`
	Port      int       `json:"port"`
	Path      string    `json:"path"`
	ExpiresAt time.Time `json:"expires_at"`
}
type Response struct {
	Status     int    `json:"status"`
	BodyBase64 string `json:"body_base64"`
	SHA256     string `json:"sha256"`
}

func (c Configuration) Valid() bool {
	return (c.Mode == "health" || c.Mode == "relay") && contracts.ValidJobID(c.AppID) && contracts.ValidJobID(c.OwnerID) && c.Port > 0 && c.Port <= 65535 && len(c.Path) <= 256 && policy.ValidHealthURL(c.Path) && c.ExpiresAt.After(time.Now()) && !c.ExpiresAt.After(time.Now().Add(time.Minute))
}
func Socket(c Configuration) string { return RelayRoot + "/" + c.AppID + "/" + c.OwnerID + ".sock" }

// Start receives only an already opened, ownership-checked network namespace.
// The new executable drops identity/capabilities and execs again after setns so
// every Go runtime thread inherits the selected network namespace.
func Start(ctx context.Context, namespace *os.File, c Configuration) (*exec.Cmd, error) {
	if os.Geteuid() != 0 || namespace == nil || !c.Valid() {
		return nil, runtimeagent.ErrDenied
	}
	read, write, err := os.Pipe()
	if err != nil {
		return nil, runtimeagent.ErrUnsupported
	}
	raw, err := json.Marshal(c)
	if err != nil {
		read.Close()
		write.Close()
		return nil, runtimeagent.ErrUnsupported
	}
	if _, err = write.Write(raw); err != nil {
		read.Close()
		write.Close()
		return nil, runtimeagent.ErrUnsupported
	}
	write.Close()
	cmd := exec.CommandContext(ctx, Binary, "--enter")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	cmd.ExtraFiles = []*os.File{namespace, read}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	return cmd, nil
}
func Probe(ctx context.Context, namespace *os.File, c Configuration) (Response, error) {
	var r Response
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	c.Mode = "health"
	cmd, err := Start(ctx, namespace, c)
	if err != nil {
		return r, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		for _, f := range cmd.ExtraFiles[1:] {
			f.Close()
		}
		return r, runtimeagent.ErrUnsupported
	}
	// ExtraFiles must remain open until Start; Start constructs the command but
	// ownership of these descriptors is retained here until the child starts.
	if cmd.Start() != nil {
		for _, f := range cmd.ExtraFiles[1:] {
			f.Close()
		}
		return r, runtimeagent.ErrUnsupported
	}
	for _, f := range cmd.ExtraFiles[1:] {
		f.Close()
	}
	raw, err := io.ReadAll(io.LimitReader(out, 8193))
	if err != nil || len(raw) > 8192 {
		_ = cmd.Process.Kill()
	}
	wait := cmd.Wait()
	if err != nil || wait != nil || len(raw) > 8192 {
		return r, runtimeagent.ErrUnsupported
	}
	r, err = contracts.DecodeConfiguration[Response](bytes.NewReader(raw))
	if err != nil || r.Status != 200 || len(r.BodyBase64) > 4096 {
		return Response{}, runtimeagent.ErrUnsupported
	}
	body, err := base64.StdEncoding.Strict().DecodeString(r.BodyBase64)
	if err != nil || len(body) > 2048 {
		return Response{}, runtimeagent.ErrUnsupported
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != r.SHA256 {
		return Response{}, runtimeagent.ErrUnsupported
	}
	return r, nil
}
func readConfiguration() (Configuration, error) {
	f := os.NewFile(4, "configuration")
	if f == nil {
		return Configuration{}, runtimeagent.ErrDenied
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return Configuration{}, runtimeagent.ErrDenied
	}
	c, err := contracts.DecodeConfiguration[Configuration](bytes.NewReader(raw))
	if err != nil || !c.Valid() {
		return Configuration{}, runtimeagent.ErrDenied
	}
	return c, nil
}
func Enter() error {
	if os.Geteuid() != 0 {
		return runtimeagent.ErrDenied
	}
	runtime.LockOSThread()
	parent := os.Getppid()
	if unix.Setns(3, unix.CLONE_NEWNET) != nil {
		return runtimeagent.ErrDenied
	}
	unix.CloseOnExec(3)
	for cap := 0; cap <= 63; cap++ {
		err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(cap), 0, 0, 0)
		if err != nil && err != unix.EINVAL {
			return runtimeagent.ErrDenied
		}
	}
	if unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != nil || syscall.Setgroups(nil) != nil || syscall.Setgid(RelayUID) != nil || syscall.Setuid(RelayUID) != nil {
		return runtimeagent.ErrDenied
	}
	if unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(syscall.SIGKILL), 0, 0, 0) != nil || os.Getppid() != parent {
		return runtimeagent.ErrDenied
	}
	// Exec removes all threads created before setns. No networking happens until
	// the fresh runtime starts in the selected namespace under the relay identity.
	return syscall.Exec(Binary, []string{Binary, "--serve"}, []string{"PATH=/usr/bin:/bin", "LANG=C"})
}
func Serve() error {
	nnp, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil || nnp != 1 || os.Geteuid() != RelayUID {
		return runtimeagent.ErrDenied
	}
	c, err := readConfiguration()
	if err != nil {
		return err
	}
	transport := &http.Transport{Proxy: nil, MaxConnsPerHost: 2, MaxIdleConns: 2, ResponseHeaderTimeout: time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return runtimeagent.ErrDenied }}
	fetch := func(ctx context.Context, path string) (Response, error) {
		if len(path) > 256 || !policy.ValidHealthURL(path) {
			return Response{}, runtimeagent.ErrDenied
		}
		req, err := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:"+strconv.Itoa(c.Port)+path, nil)
		if err != nil {
			return Response{}, runtimeagent.ErrDenied
		}
		res, err := client.Do(req)
		if err != nil {
			return Response{}, runtimeagent.ErrUnsupported
		}
		defer res.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(res.Body, 2049))
		if err != nil || len(raw) > 2048 {
			return Response{}, runtimeagent.ErrUnsupported
		}
		sum := sha256.Sum256(raw)
		return Response{Status: res.StatusCode, BodyBase64: base64.StdEncoding.EncodeToString(raw), SHA256: hex.EncodeToString(sum[:])}, nil
	}
	if c.Mode == "health" {
		ctx, cancel := context.WithDeadline(context.Background(), c.ExpiresAt)
		defer cancel()
		r, err := fetch(ctx, c.Path)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(r)
	}
	listener, err := net.Listen("unix", Socket(c))
	if err != nil {
		return runtimeagent.ErrUnsupported
	}
	defer listener.Close()
	if os.Chmod(Socket(c), 0600) != nil {
		return runtimeagent.ErrDenied
	}
	active := make(chan struct{}, 2)
	server := &http.Server{ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 4096, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.RawQuery != "" {
			http.Error(w, "denied", 403)
			return
		}
		select {
		case active <- struct{}{}:
			defer func() { <-active }()
		default:
			http.Error(w, "denied", 503)
			return
		}
		response, err := fetch(r.Context(), r.URL.Path)
		if err != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(response.BodyBase64)
		if err != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		w.WriteHeader(response.Status)
		w.Write(raw)
	})}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	timer := time.NewTimer(time.Until(c.ExpiresAt))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-done:
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	server.Shutdown(ctx)
	return nil
}
