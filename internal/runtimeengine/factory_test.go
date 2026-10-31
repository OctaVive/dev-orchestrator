package runtimeengine

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/policy"
	"dev-orchestrator/internal/runtimeagent"
)

const factoryWorker = "11111111-1111-4111-8111-111111111111"
const factoryOther = "22222222-2222-4222-8222-222222222222"

type observerFixture struct{ denied atomic.Bool }

func (o *observerFixture) VerifyBackend(context.Context, runtimeagent.BackendBinding) error {
	if o.denied.Load() {
		return runtimeagent.ErrUnsupported
	}
	return nil
}

type enforcementFixture struct {
	b      runtimeagent.BackendBinding
	badApp bool
}

func (e enforcementFixture) Measure(_ context.Context, c runtimeagent.Command, check func() error) (runtimeagent.Inventory, error) {
	w, i, app, challenge := c.WorkerID, c.Incarnation, c.AppID, c.Nonce
	now := time.Now().UTC()
	if e.badApp {
		app = factoryOther
	}
	return runtimeagent.Inventory{Version: 2, WorkerID: w, Incarnation: i, AppID: app, BackendHash: e.b.Hash(), Challenge: challenge, MeasuredAt: now, ExpiresAt: now.Add(time.Minute), TemplateHash: contracts.Digest([]byte("template")), Kernel: "kernel", Engine: "engine", API: APIVersion, DaemonID: e.b.DaemonID, PolicyHash: policy.Hash(), Controls: policy.RequiredControls()}, nil
}
func (enforcementFixture) Reserve(context.Context, runtimeagent.Command) error         { return nil }
func (enforcementFixture) Network(context.Context, runtimeagent.Command, string) error { return nil }
func (enforcementFixture) Verify(context.Context, runtimeagent.Command) error          { return nil }
func (enforcementFixture) Release(context.Context, runtimeagent.Command) error         { return nil }

type deliveryFixture struct{}

func (deliveryFixture) Prepare(context.Context, runtimeagent.Command, contracts.RuntimeServiceV2, func() error) error {
	return nil
}
func TestFactoryRoutesAndFences(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	l, err := runtimeagent.OpenLedger(ctx, filepath.Join(dir, "ledger"), factoryWorker, factoryWorker)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if l.ConfigureBackends(ctx, runtimeagent.BackendCapacity{Apps: 2, Memory: 200, Disk: 200}) != nil {
		t.Fatal("capacity")
	}
	observer := &observerFixture{}
	var calls [2]atomic.Int32
	for n, app := range []string{factoryWorker, factoryOther} {
		socket := filepath.Join(dir, app+".sock")
		listener, err := net.Listen("unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		daemon := app
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls[n].Add(1)
			if r.URL.Path != "/v"+APIVersion+"/info" {
				t.Error("unexpected path", r.URL.Path)
			}
			json.NewEncoder(w).Encode(map[string]any{"DockerRootDir": filepath.Join(dir, app), "ID": daemon, "ServerVersion": "engine", "KernelVersion": "kernel", "CgroupDriver": "systemd", "CgroupVersion": "2", "SecurityOptions": []string{"name=rootless", "name=seccomp,profile=builtin"}})
		})}
		go server.Serve(listener)
		t.Cleanup(func() { server.Close() })
		b := runtimeagent.BackendBinding{DaemonPID: 100 + n, DaemonStartTicks: 123, BootID: factoryWorker, AppID: app, Socket: socket, DataRoot: filepath.Join(dir, app), DaemonID: daemon, UserNamespace: []string{"user:[2]", "user:[3]"}[n], InitialUserNamespace: "user:[1]", UIDMapHash: contracts.Digest([]byte("uid")), GIDMapHash: contracts.Digest([]byte("gid")), DaemonMemory: 10, WorkloadMemory: 90, ImageDisk: 50, WorkloadDisk: 50}
		if err := l.ReserveBackend(ctx, b.Reservation()); err != nil {
			t.Fatal(err)
		}
		if err := l.BindBackend(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	badApp := false
	f, err := NewFactory(l, observer, factoryWorker, factoryWorker, "tap-runtime", func(b runtimeagent.BackendBinding, c *Client) (Enforcement, ImageDelivery, error) {
		return enforcementFixture{b, badApp}, deliveryFixture{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	command := runtimeagent.Command{Nonce: strings.Repeat("a", 64), WorkerID: factoryWorker, Incarnation: factoryWorker, AppID: factoryWorker}
	inv, err := f.Probe(ctx, command, func() error { return nil })
	if err != nil || inv.AppID != factoryWorker || calls[0].Load() != 1 || calls[1].Load() != 0 {
		t.Fatal("wrong backend", err)
	}
	command.AppID = factoryOther
	if _, err = f.Probe(ctx, command, func() error { return nil }); err != nil || calls[0].Load() != 1 || calls[1].Load() != 1 {
		t.Fatal("app B", err)
	}
	command.AppID = factoryWorker
	badApp = true
	if _, err = f.Probe(ctx, command, func() error { return nil }); err == nil {
		t.Fatal("wrong-app measurement")
	}
	badApp = false
	e, err := f.backend(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Client.close()
	observer.denied.Store(true)
	before := calls[0].Load()
	if e.Client.call(ctx, "GET", "/info", nil, nil) == nil || calls[0].Load() != before {
		t.Fatal("binding drift reached engine")
	}
	if _, err = f.Probe(ctx, command, func() error { return nil }); err == nil || calls[0].Load() != before {
		t.Fatal("drift probe")
	}
	observer.denied.Store(false)
	command.WorkerID = factoryOther
	if _, err = f.Probe(ctx, command, func() error { return nil }); err == nil {
		t.Fatal("foreign worker")
	}
	command.WorkerID = factoryWorker
	command.AppID = "33333333-3333-4333-8333-333333333333"
	if _, err = f.Probe(ctx, command, func() error { return nil }); err == nil {
		t.Fatal("unregistered app")
	}
}
func TestMappingMeasurements(t *testing.T) {
	good := []byte("         0       1000          1\n         1     100000      65536\n")
	if !safeMapping(good) {
		t.Fatal("valid inherited rootless map")
	}
	for _, v := range []string{"", "0 0 65536", "0 1000 1", "0 1000 2\n1 100000 65536", "0 1000 65536\n65536 1001 2", "0 4294967295 2", "0 1000 -1", "0 1000 65536 extra", "0 1000 0"} {
		if safeMapping([]byte(v)) {
			t.Fatal("unsafe map", v)
		}
	}
}
func TestProcessStartParsing(t *testing.T) {
	raw := []byte("100 (dock er)d) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 123 0")
	n, err := startTicks(raw)
	if err != nil || n != 123 {
		t.Fatal(n, err)
	}
	for _, s := range []string{"", "100 (dockerd) S 1", "100 dockerd S 1"} {
		if _, err = startTicks([]byte(s)); err == nil {
			t.Fatal("malformed proc stat")
		}
	}
}
func TestLinuxObserverFailsClosed(t *testing.T) {
	if (LinuxObserver{}).VerifyBackend(context.Background(), runtimeagent.BackendBinding{}) == nil {
		t.Fatal("unbound observer")
	}
}

func TestBackendDaemonArguments(t *testing.T) {
	b := runtimeagent.BackendBinding{Socket: "/run/app/docker.sock", DataRoot: "/var/lib/app"}
	good := []byte("dockerd\x00--rootless\x00--data-root=/var/lib/app\x00--host=unix:///run/app/docker.sock\x00")
	if !backendArgs(good, b) {
		t.Fatal("fixed daemon arguments")
	}
	for _, s := range []string{
		"dockerd\x00--data-root=/var/lib/other\x00--host=unix:///run/app/docker.sock\x00",
		"dockerd\x00--data-root=/var/lib/app\x00--host=tcp://0.0.0.0:2375\x00",
		string(good) + "--host=tcp://127.0.0.1:2375\x00",
		"dockerd\x00--data-root=/var/lib/app\x00",
	} {
		if backendArgs([]byte(s), b) {
			t.Fatal("wrong daemon ownership arguments")
		}
	}
}

func (enforcementFixture) VerifyContainer(context.Context, runtimeagent.Command, string, int) error {
	return nil
}
