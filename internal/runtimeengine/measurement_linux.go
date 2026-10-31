package runtimeengine

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/runtimeagent"
	"dev-orchestrator/internal/runtimeobservation"
	"golang.org/x/sys/unix"
)

// MeasurementClient reaches one fixed root-owned Unix helper. It exposes only
// enrolled backend/container measurement; no caller-selected socket, PID, path,
// executable, generic Docker operation or namespace join is transmitted.
type MeasurementClient struct {
	http        *http.Client
	binding     runtimeagent.BackendBinding
	profileHash string
}

func NewMeasurementClient(b runtimeagent.BackendBinding, profileHash string) (*MeasurementClient, error) {
	if !b.Valid() || !contracts.ValidDigest(profileHash) {
		return nil, runtimeagent.ErrDenied
	}
	transport := &http.Transport{Proxy: nil, MaxConnsPerHost: 2, MaxIdleConns: 2, ResponseHeaderTimeout: 3 * time.Second, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", runtimeobservation.Socket)
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
		if raw.Control(func(fd uintptr) { cred, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }) != nil || peerErr != nil || cred == nil || cred.Uid != 0 {
			conn.Close()
			return nil, runtimeagent.ErrUnsupported
		}
		return conn, nil
	}}
	return &MeasurementClient{http: &http.Client{Transport: transport, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return runtimeagent.ErrDenied }}, binding: b, profileHash: profileHash}, nil
}
func (m *MeasurementClient) Report(ctx context.Context, q runtimeobservation.Request) (runtimeobservation.Report, error) {
	fail := func() (runtimeobservation.Report, error) {
		return runtimeobservation.Report{}, runtimeagent.ErrUnsupported
	}
	if q.AppID != m.binding.AppID {
		return fail()
	}
	raw, err := json.Marshal(q)
	if err != nil || len(raw) > 8192 {
		return fail()
	}
	req, err := http.NewRequestWithContext(ctx, "POST", "http://measurement/runtime/v1/measure", bytes.NewReader(raw))
	if err != nil {
		return fail()
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := m.http.Do(req)
	if err != nil {
		return fail()
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fail()
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 8193))
	if err != nil || len(body) > 8192 {
		return fail()
	}
	report, err := contracts.DecodeConfiguration[runtimeobservation.Report](bytes.NewReader(body))
	if err != nil || report.Version != 1 || report.AppID != q.AppID || report.BackendHash != m.binding.Hash() || report.ProfileHash != m.profileHash || report.ContainerID != q.ContainerID {
		return fail()
	}
	return report, nil
}
func (m *MeasurementClient) Close() { m.http.CloseIdleConnections() }
