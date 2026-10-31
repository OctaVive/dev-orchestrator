package runtimeengine

import (
	"context"
	"encoding/json"
	"net/http"

	"dev-orchestrator/internal/runtimeagent"
)

// BackendObserver must independently compare the live daemon/socket/data root,
// process start identity, effective namespace and UID/GID maps with the durable
// assignment. It must verify private path ownership and fail on missing evidence.
// No implementation falls back to Docker's configured userns flags.
type BackendObserver interface {
	VerifyBackend(context.Context, runtimeagent.BackendBinding) error
}

// Factory dispatches by authenticated app identity only. A trusted provisioner
// must reserve before starting a daemon, then measure and bind its identity. Commands and
// labels cannot create/rebind assignments, select sockets or release reservations.
// Constructing a factory does not provision daemons or assert readiness.
type Factory struct {
	ledger                   *runtimeagent.Ledger
	observer                 BackendObserver
	worker, incarnation, mac string
	adapters                 func(runtimeagent.BackendBinding, *Client) (Enforcement, ImageDelivery, error)
}

func NewFactory(ledger *runtimeagent.Ledger, observer BackendObserver, worker, incarnation, mac string,
	adapters func(runtimeagent.BackendBinding, *Client) (Enforcement, ImageDelivery, error)) (*Factory, error) {
	if ledger == nil || observer == nil || mac == "" || adapters == nil || !ledger.Identity(worker, incarnation) {
		return nil, runtimeagent.ErrDenied
	}
	return &Factory{ledger, observer, worker, incarnation, mac, adapters}, nil
}

// guardedTransport rechecks the binding on every HTTP request, including cached
// connections and artifact imports. A changed daemon can never inherit readiness
// merely by taking over the same socket path. No daemon cleanup is attempted.
type guardedTransport struct {
	next  http.RoundTripper
	check func(context.Context) error
}

func (t guardedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.check(r.Context()) != nil {
		return nil, runtimeagent.ErrUnsupported
	}
	res, err := t.next.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	if t.check(r.Context()) != nil {
		res.Body.Close()
		return nil, runtimeagent.ErrUncertain
	}
	return res, nil
}
func (f *Factory) backend(ctx context.Context, c runtimeagent.Command) (*Engine, error) {
	if c.WorkerID != f.worker || c.Incarnation != f.incarnation {
		return nil, runtimeagent.ErrDenied
	}
	b, err := f.ledger.Backend(ctx, c.AppID)
	if err != nil || f.observer.VerifyBackend(ctx, b) != nil {
		return nil, runtimeagent.ErrUnsupported
	}
	client, err := NewClient(b.Socket)
	if err != nil {
		return nil, err
	}
	client.http.Transport = guardedTransport{client.http.Transport, func(ctx context.Context) error {
		current, err := f.ledger.Backend(ctx, c.AppID)
		if err != nil || current != b {
			return runtimeagent.ErrConflict
		}
		return f.observer.VerifyBackend(ctx, b)
	}}
	enforcement, delivery, err := f.adapters(b, client)
	if err != nil || enforcement == nil || delivery == nil {
		client.close()
		return nil, runtimeagent.ErrUnsupported
	}
	return &Engine{Backend: &b, Client: client, Ledger: f.ledger, Enforcement: enforcement, Delivery: delivery, WorkerID: f.worker, Incarnation: f.incarnation, MACProfile: f.mac}, nil
}
func (f *Factory) Probe(ctx context.Context, c runtimeagent.Command, check func() error) (runtimeagent.Inventory, error) {
	e, err := f.backend(ctx, c)
	if err != nil {
		return runtimeagent.Inventory{}, err
	}
	defer e.close()
	return e.Probe(ctx, c, check)
}
func (f *Factory) Prepare(ctx context.Context, c runtimeagent.Command, check func() error) error {
	e, err := f.backend(ctx, c)
	if err != nil {
		return err
	}
	defer e.close()
	return e.Prepare(ctx, c, check)
}
func (f *Factory) Create(ctx context.Context, c runtimeagent.Command, check func() error) error {
	e, err := f.backend(ctx, c)
	if err != nil {
		return err
	}
	defer e.close()
	return e.Create(ctx, c, check)
}
func (f *Factory) Inspect(ctx context.Context, c runtimeagent.Command) (string, error) {
	e, err := f.backend(ctx, c)
	if err != nil {
		return "", err
	}
	defer e.close()
	return e.Inspect(ctx, c)
}
func (f *Factory) Logs(ctx context.Context, c runtimeagent.Command) ([]byte, error) {
	e, err := f.backend(ctx, c)
	if err != nil {
		return nil, err
	}
	defer e.close()
	return e.Logs(ctx, c)
}
func (f *Factory) Stop(ctx context.Context, c runtimeagent.Command, check func() error) error {
	e, err := f.backend(ctx, c)
	if err != nil {
		return err
	}
	defer e.close()
	return e.Stop(ctx, c, check)
}
func (f *Factory) Remove(ctx context.Context, c runtimeagent.Command, check func() error) error {
	e, err := f.backend(ctx, c)
	if err != nil {
		return err
	}
	defer e.close()
	return e.Remove(ctx, c, check)
}

var _ runtimeagent.Engine = (*Factory)(nil)

func (e *Engine) close() {
	if e.Client != nil {
		e.Client.close()
	}
	if closer, ok := e.Enforcement.(interface{ Close() }); ok {
		closer.Close()
	}
}

func (f *Factory) Quarantine(ctx context.Context, c runtimeagent.Command) error {
	e, err := f.backend(ctx, c)
	if err != nil {
		return err
	}
	defer e.close()
	drainer, ok := e.Enforcement.(interface {
		DropIngress(context.Context, runtimeagent.Command) error
	})
	if !ok {
		return runtimeagent.ErrUnsupported
	}
	drainErr := drainer.DropIngress(ctx, c)
	// Still request an exact-owned stop when private fixture disconnection is
	// uncertain; retain the incident rather than asserting route drain success.
	stopErr := e.Stop(ctx, c, func() error { return ctx.Err() })
	if drainErr != nil || stopErr != nil {
		return runtimeagent.ErrUncertain
	}
	return nil
}

func (f *Factory) StoppedServices(ctx context.Context, c runtimeagent.Command) ([]string, error) {
	e, err := f.backend(ctx, c)
	if err != nil {
		return nil, err
	}
	defer e.close()
	target := c
	target.Target = c.ID
	target.Spec = nil
	resources, err := e.owned(ctx, target)
	if err != nil {
		return nil, err
	}
	var stopped []string
	for _, r := range resources {
		if r.Kind != "container" {
			continue
		}
		got, err := e.inspect(ctx, r.ID)
		if err != nil {
			return nil, err
		}
		var cfg ContainerConfig
		if json.Unmarshal(r.Expected, &cfg) != nil || verifyConfiguration(cfg, got, got.State.Running) != nil {
			return nil, runtimeagent.ErrDenied
		}
		if got.State.Running {
			if e.Enforcement.VerifyContainer(ctx, c, r.ID, got.State.Pid) != nil {
				return nil, runtimeagent.ErrDenied
			}
		} else {
			stopped = append(stopped, r.Service)
		}
	}
	return stopped, nil
}
func (f *Factory) RestartOwned(ctx context.Context, c runtimeagent.Command, service string, check func() error) error {
	e, err := f.backend(ctx, c)
	if err != nil {
		return err
	}
	defer e.close()
	target := c
	target.Target = c.ID
	resources, err := e.owned(ctx, target)
	if err != nil {
		return err
	}
	for _, r := range resources {
		if r.Kind != "container" || r.Service != service {
			continue
		}
		var cfg ContainerConfig
		if json.Unmarshal(r.Expected, &cfg) != nil {
			return runtimeagent.ErrLedger
		}
		got, err := e.inspect(ctx, r.ID)
		if err != nil || got.State.Running || verifyConfiguration(cfg, got, false) != nil {
			return runtimeagent.ErrDenied
		}
		if check() == nil && e.Enforcement.Verify(ctx, c) == nil && e.Client.call(ctx, "POST", "/containers/"+r.ID+"/start", nil, nil) == nil {
			return e.await(ctx, c, cfg, r.ID, check)
		}
		return runtimeagent.ErrUncertain
	}
	return runtimeagent.ErrDenied
}
