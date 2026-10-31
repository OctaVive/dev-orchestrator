package runtimemeasure

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"dev-orchestrator/internal/runtimeagent"
	"dev-orchestrator/internal/runtimenet"
	"dev-orchestrator/internal/runtimeobservation"
	"golang.org/x/sys/unix"
)

type relayEntry struct {
	cmd           *exec.Cmd
	cancel        context.CancelFunc
	done          chan struct{}
	configuration runtimenet.Configuration
	container     string
	network       string
	dev, ino      uint64
}
type relayManager struct {
	mu      sync.Mutex
	entries map[string]*relayEntry
}

func relayKey(app, owner, container string) string { return app + "/" + owner + "/" + container }
func relayDirectory(path string, uid int, mode os.FileMode) error {
	if err := os.Mkdir(path, mode); err != nil && !os.IsExist(err) {
		return runtimeagent.ErrUnsupported
	}
	var st unix.Stat_t
	if unix.Lstat(path, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || (st.Uid != 0 && st.Uid != uint32(uid)) {
		return runtimeagent.ErrUnsupported
	}
	if os.Chown(path, uid, uid) != nil || os.Chmod(path, mode) != nil {
		return runtimeagent.ErrUnsupported
	}
	return nil
}
func (m *relayManager) start(namespace *os.File, q runtimeobservation.Request, network string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.entries == nil {
		m.entries = map[string]*relayEntry{}
	}
	key := relayKey(q.AppID, q.OwnerID, q.ContainerID)
	if existing := m.entries[key]; existing != nil {
		if existing.container != q.ContainerID || existing.configuration.Port != q.Port {
			return runtimeagent.ErrUncertain
		}
		live := false
		select {
		case <-existing.done:
		default:
			live = true
		}
		if live && existing.network == network && existing.configuration.ExpiresAt.After(time.Now().Add(5*time.Second)) {
			return nil
		}
		if m.stopLocked(q.AppID, q.OwnerID, q.ContainerID) != nil {
			return runtimeagent.ErrUncertain
		}
	}

	if len(m.entries) >= 32 {
		return runtimeagent.ErrUnsupported
	}
	count := 0
	for _, entry := range m.entries {
		if entry.configuration.AppID == q.AppID && entry.configuration.OwnerID == q.OwnerID && entry.container != q.ContainerID {
			return runtimeagent.ErrDenied
		}
		if entry.configuration.AppID == q.AppID {
			count++
		}
	}
	if count >= 4 {
		return runtimeagent.ErrUnsupported
	}
	if relayDirectory(runtimenet.RelayRoot, 0, 0755) != nil || relayDirectory(runtimenet.RelayRoot+"/"+q.AppID, runtimenet.RelayUID, 0700) != nil {
		return runtimeagent.ErrUnsupported
	}
	c := runtimenet.Configuration{Mode: "relay", AppID: q.AppID, OwnerID: q.OwnerID, Port: q.Port, Path: q.Path, ExpiresAt: time.Now().Add(30 * time.Second)}
	lifetime, cancel := context.WithDeadline(context.Background(), c.ExpiresAt)
	cmd, err := runtimenet.Start(lifetime, namespace, c)
	if err != nil {
		cancel()
		return err
	}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		for _, f := range cmd.ExtraFiles[1:] {
			f.Close()
		}
		cancel()
		return runtimeagent.ErrUnsupported
	}
	for _, f := range cmd.ExtraFiles[1:] {
		f.Close()
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	entry := &relayEntry{cmd: cmd, cancel: cancel, done: done, configuration: c, container: q.ContainerID, network: network}
	m.entries[key] = entry
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		var st unix.Stat_t
		if unix.Lstat(runtimenet.Socket(c), &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFSOCK && st.Uid == runtimenet.RelayUID && st.Mode&0077 == 0 {
			ns, err := os.Readlink("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/ns/net")
			if err != nil || ns != network {
				cancel()
				return runtimeagent.ErrUncertain
			}
			entry.dev = uint64(st.Dev)
			entry.ino = st.Ino
			return nil
		}
		select {
		case <-deadline.C:
			cancel()
			return runtimeagent.ErrUncertain
		case <-time.After(20 * time.Millisecond):
		}
	}
}
func (m *relayManager) fetch(ctx context.Context, q runtimeobservation.Request) (runtimeobservation.Health, error) {
	m.mu.Lock()
	entry := m.entries[relayKey(q.AppID, q.OwnerID, q.ContainerID)]
	if entry == nil || entry.container != q.ContainerID {
		m.mu.Unlock()
		return runtimeobservation.Health{}, runtimeagent.ErrUnsupported
	}
	socket := runtimenet.Socket(entry.configuration)
	pid := entry.cmd.Process.Pid
	m.mu.Unlock()
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socket)
		if err != nil {
			return nil, runtimeagent.ErrUnsupported
		}
		u, ok := conn.(*net.UnixConn)
		if !ok {
			conn.Close()
			return nil, runtimeagent.ErrUnsupported
		}
		raw, err := u.SyscallConn()
		if err != nil {
			conn.Close()
			return nil, runtimeagent.ErrUnsupported
		}
		var cred *unix.Ucred
		var peerErr error
		if raw.Control(func(fd uintptr) { cred, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }) != nil || peerErr != nil || cred == nil || cred.Uid != runtimenet.RelayUID || int(cred.Pid) != pid {
			conn.Close()
			return nil, runtimeagent.ErrUnsupported
		}
		return conn, nil
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return runtimeagent.ErrDenied }}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://private-relay"+q.Path, nil)
	if err != nil {
		return runtimeobservation.Health{}, runtimeagent.ErrDenied
	}
	response, err := client.Do(req)
	if err != nil {
		return runtimeobservation.Health{}, runtimeagent.ErrUnsupported
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 2049))
	if err != nil || len(raw) > 2048 || response.StatusCode != 200 {
		return runtimeobservation.Health{}, runtimeagent.ErrUnsupported
	}
	sum := sha256.Sum256(raw)
	return runtimeobservation.Health{Status: response.StatusCode, BodyBase64: base64.StdEncoding.EncodeToString(raw), SHA256: hex.EncodeToString(sum[:])}, nil
}
func (m *relayManager) stop(app, owner, container string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopLocked(app, owner, container)
}
func (m *relayManager) stopLocked(app, owner, container string) error {
	key := relayKey(app, owner, container)
	entry := m.entries[key]
	if entry == nil {
		return nil
	}
	if entry.container != container {
		return runtimeagent.ErrDenied
	}
	entry.cancel()
	entry.cmd.Process.Kill()
	select {
	case <-entry.done:
	case <-time.After(2 * time.Second):
		return runtimeagent.ErrUncertain
	}
	path := runtimenet.Socket(entry.configuration)
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err == nil {
		if uint64(st.Dev) != entry.dev || st.Ino != entry.ino || st.Uid != runtimenet.RelayUID || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
			return runtimeagent.ErrUncertain
		}
		if os.Remove(path) != nil {
			return runtimeagent.ErrUncertain
		}
	} else if !os.IsNotExist(err) {
		return runtimeagent.ErrUncertain
	}
	delete(m.entries, key)
	return nil
}
func (s *Server) Close() {
	s.relays.mu.Lock()
	type identity struct{ app, owner, container string }
	var entries []identity
	for _, entry := range s.relays.entries {
		entries = append(entries, identity{entry.configuration.AppID, entry.configuration.OwnerID, entry.container})
	}
	s.relays.mu.Unlock()
	for _, entry := range entries {
		s.relays.stop(entry.app, entry.owner, entry.container)
	}
}
