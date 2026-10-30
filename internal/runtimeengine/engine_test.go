package runtimeengine

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/policy"
	"dev-orchestrator/internal/runtimeagent"
)

func fixtureConfig(t *testing.T) ContainerConfig {
	t.Helper()
	c := runtimeagent.Command{ID: "11111111-1111-4111-8111-111111111111", WorkerID: "22222222-2222-4222-8222-222222222222", Incarnation: "33333333-3333-4333-8333-333333333333", AppID: "44444444-4444-4444-8444-444444444444", DeploymentID: "55555555-5555-4555-8555-555555555555", Generation: 1, SpecHash: contracts.Digest([]byte("spec"))}
	s := contracts.RuntimeServiceV2{Name: "web", Image: "registry.example.org/apps/web@sha256:" + strings.Repeat("a", 64), UID: 1000, GID: 1000, Command: []string{"/web"}, Environment: map[string]string{"MODE": "production"}, Expose: []int{8080}, Resources: policy.Defaults()}
	cfg, e := Config(c, s, strings.Repeat("b", 64), "tap-runtime")
	if e != nil {
		t.Fatal(e)
	}
	return cfg
}
func inspected(cfg ContainerConfig) Inspected {
	g := Inspected{ID: strings.Repeat("c", 64), Config: cfg, HostConfig: cfg.HostConfig, AppArmorProfile: "tap-runtime"}
	g.State.Running = true
	g.NetworkSettings.Networks = map[string]struct {
		NetworkID string
		Aliases   []string
		IPAddress string
	}{"app": {NetworkID: cfg.HostConfig.NetworkMode}}
	return g
}
func TestRequiredEngineConfiguration(t *testing.T) {
	cfg := fixtureConfig(t)
	h := cfg.HostConfig
	if cfg.User != "1000:1000" || !h.ReadonlyRootfs || h.Privileged || !equal(h.CapDrop, []string{"ALL"}) || len(h.CapAdd) > 0 || len(h.GroupAdd) > 0 || h.MemorySwap != h.Memory || h.PidsLimit != 128 || h.NanoCpus != 1000000000 || len(h.PortBindings) > 0 || h.PublishAllPorts || h.RestartPolicy.Name != "no" || h.IpcMode != "private" || h.CgroupnsMode != "private" {
		t.Fatal("hard profile missing")
	}
	if !strings.Contains(h.Tmpfs["/tmp"], "size=67108864") || h.LogConfig.Type != "local" || h.LogConfig.Config["max-file"] != "2" {
		t.Fatal("unbounded writable/log storage")
	}
	if Verify(cfg, inspected(cfg), true) != nil {
		t.Fatal("baseline rejected")
	}
}
func TestInspectDetectsDrift(t *testing.T) {
	cases := map[string]func(*Inspected){"root": func(g *Inspected) { g.Config.User = "0:0" }, "privilege": func(g *Inspected) { g.HostConfig.Privileged = true }, "root-write": func(g *Inspected) { g.HostConfig.ReadonlyRootfs = false }, "capability": func(g *Inspected) { g.HostConfig.CapAdd = []string{"SYS_ADMIN"} }, "groups": func(g *Inspected) { g.HostConfig.GroupAdd = []string{"0"} }, "no-nnp": func(g *Inspected) { g.HostConfig.SecurityOpt = []string{"apparmor=tap-runtime"} }, "mac": func(g *Inspected) { g.AppArmorProfile = "unconfined" }, "host-network": func(g *Inspected) { g.HostConfig.NetworkMode = "host" }, "host-pid": func(g *Inspected) { g.HostConfig.PidMode = "host" }, "host-ipc": func(g *Inspected) { g.HostConfig.IpcMode = "host" }, "swap": func(g *Inspected) { g.HostConfig.MemorySwap = -1 }, "pids": func(g *Inspected) { g.HostConfig.PidsLimit = 0 }, "cpu": func(g *Inspected) { g.HostConfig.NanoCpus = 0 }, "logs": func(g *Inspected) { g.HostConfig.LogConfig.Type = "json-file" }, "restart": func(g *Inspected) { g.HostConfig.RestartPolicy.Name = "always" }, "ports": func(g *Inspected) {
		g.NetworkSettings.Ports = map[string][]json.RawMessage{"8080/tcp": {json.RawMessage(`{"HostPort":"8080"}`)}}
	}, "mount": func(g *Inspected) {
		g.Mounts = append(g.Mounts, struct {
			Type, Source, Destination string
			RW                        bool
		}{Type: "bind", Source: "/var/run/docker.sock", Destination: "/socket"})
	}, "labels": func(g *Inspected) { g.Config.Labels = map[string]string{"tap.owner": "foreign"} }, "stopped": func(g *Inspected) { g.State.Running = false }, "foreign-network": func(g *Inspected) {
		g.NetworkSettings.Networks["app"] = struct {
			NetworkID string
			Aliases   []string
			IPAddress string
		}{NetworkID: strings.Repeat("d", 64)}
	}}
	for n, change := range cases {
		t.Run(n, func(t *testing.T) {
			cfg := fixtureConfig(t)
			g := inspected(cfg)
			change(&g)
			if Verify(cfg, g, true) == nil {
				t.Fatal("engine drift accepted")
			}
		})
	}
}
func TestMissingEnforcementRefusesWithoutEngineCalls(t *testing.T) {
	e := &Engine{}
	if _, err := e.Probe(context.Background()); err != runtimeagent.ErrUnsupported {
		t.Fatal(err)
	}
}
func frame(stream byte, b []byte) []byte {
	out := make([]byte, 8)
	out[0] = stream
	binary.BigEndian.PutUint32(out[4:], uint32(len(b)))
	return append(out, b...)
}
func TestLogFrameBounds(t *testing.T) {
	good := append(frame(1, []byte("hello\n")), frame(2, []byte("stderr\n"))...)
	b, e := decodeLogs(bytes.NewReader(good), 100)
	if e != nil || string(b) != "hello\nstderr\n" {
		t.Fatal(e)
	}
	cases := map[string][]byte{"truncated-header": {1, 0}, "truncated-body": frame(1, []byte("hello"))[:10], "stream": frame(3, []byte("x")), "oversized": frame(1, bytes.Repeat([]byte("x"), 101)), "flood": bytes.Repeat(frame(1, nil), 1025)}
	for n, b := range cases {
		t.Run(n, func(t *testing.T) {
			if _, e := decodeLogs(bytes.NewReader(b), 100); e == nil {
				t.Fatal("malformed logs accepted")
			}
		})
	}
}
func TestUnixClientResponseBoundsAndSanitizedErrors(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "engine.sock")
	l, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	defer os.Remove(socket)
	var mode atomic.Value
	mode.Store("ok")
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1.47/info" {
			t.Error("unexpected API path", r.URL.Path)
		}
		switch mode.Load().(string) {
		case "error":
			http.Error(w, "SECRET-RAW-DAEMON", 403)
		case "oversize":
			w.Write(bytes.Repeat([]byte("x"), maxResponse+1))
		default:
			w.Write([]byte(`{"ID":"daemon"}`))
		}
	})}
	go server.Serve(l)
	defer server.Close()
	c, e := NewClient(socket)
	if e != nil {
		t.Fatal(e)
	}
	defer c.http.CloseIdleConnections()
	var info struct{ ID string }
	if c.call(context.Background(), "GET", "/info", nil, &info) != nil || info.ID != "daemon" {
		t.Fatal("typed request failed")
	}
	for _, m := range []string{"error", "oversize"} {
		mode.Store(m)
		if e := c.call(context.Background(), "GET", "/info", nil, &info); e != runtimeagent.ErrDenied {
			t.Fatal("unbounded/raw error", e)
		}
	}
	if _, e := NewClient("tcp://localhost:2375"); e == nil {
		t.Fatal("TCP engine accepted")
	}
}
