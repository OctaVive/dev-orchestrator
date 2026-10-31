package runtimeengine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/policy"
	"dev-orchestrator/internal/runtimeagent"
)

// Enforcement is a separately privileged, narrowly scoped trusted adapter. It
// must measure canary cgroups, network denial, enforced MAC, storage and relay
// connectivity, and reserve capacity before any network/container/image change.
// No default implementation substitutes configuration booleans for measurements.
type Enforcement interface {
	Measure(context.Context, runtimeagent.Command, func() error) (runtimeagent.Inventory, error)
	VerifyContainer(context.Context, runtimeagent.Command, string, int) error
	Reserve(context.Context, runtimeagent.Command) error
	Network(context.Context, runtimeagent.Command, string) error
	Verify(context.Context, runtimeagent.Command) error
	Release(context.Context, runtimeagent.Command) error
}

// ImageDelivery imports only the exact trusted admitted image with finite disk,
// byte, request and time budgets. It receives no raw command/registry API surface.
type ImageDelivery interface {
	Prepare(context.Context, runtimeagent.Command, contracts.RuntimeServiceV2, func() error) error
}
type Engine struct {
	Backend                           *runtimeagent.BackendBinding
	Client                            *Client
	Ledger                            *runtimeagent.Ledger
	Enforcement                       Enforcement
	Delivery                          ImageDelivery
	WorkerID, Incarnation, MACProfile string
}

var _ runtimeagent.Engine = (*Engine)(nil)

func (e *Engine) Probe(ctx context.Context, c runtimeagent.Command, check func() error) (runtimeagent.Inventory, error) {
	if check == nil || check() != nil || e.Backend == nil || !e.Backend.Valid() || e.Backend.AppID != c.AppID || e.Client == nil || e.Ledger == nil || e.Enforcement == nil || e.Delivery == nil || e.MACProfile == "" {
		return runtimeagent.Inventory{}, runtimeagent.ErrUnsupported
	}
	var info struct {
		ID, ServerVersion, KernelVersion, CgroupDriver, CgroupVersion, DockerRootDir string
		SecurityOptions                                                              []string
	}
	if e.Client.call(ctx, "GET", "/info", nil, &info) != nil || info.CgroupDriver != "systemd" || info.CgroupVersion != "2" || info.DockerRootDir != e.Backend.DataRoot {
		return runtimeagent.Inventory{}, runtimeagent.ErrUnsupported
	}
	rootless, seccomp := false, false
	for _, s := range info.SecurityOptions {
		if s == "name=rootless" {
			rootless = true
		}
		if strings.HasPrefix(s, "name=seccomp,") {
			seccomp = true
		}
	}
	if !rootless || !seccomp {
		return runtimeagent.Inventory{}, runtimeagent.ErrUnsupported
	}
	if !contracts.ValidDigest("sha256:" + c.Nonce) {
		return runtimeagent.Inventory{}, runtimeagent.ErrDenied
	}
	challenge := c.Nonce
	inv, err := e.Enforcement.Measure(ctx, c, check)
	if err != nil || inv.Challenge != challenge || inv.AppID != c.AppID || inv.BackendHash != e.Backend.Hash() || inv.DaemonID != e.Backend.DaemonID || inv.DaemonID != info.ID || inv.Engine != info.ServerVersion || inv.Kernel != info.KernelVersion || inv.API != APIVersion || inv.Ready(time.Now(), e.WorkerID, e.Incarnation) != nil {
		return runtimeagent.Inventory{}, runtimeagent.ErrUnsupported
	}
	return inv, nil
}
func (e *Engine) Prepare(ctx context.Context, c runtimeagent.Command, check func() error) error {
	if e.Enforcement == nil || e.Delivery == nil || e.Enforcement.Reserve(ctx, c) != nil {
		os.Stderr.WriteString("runtime_prepare_capacity_denied\n")
		return runtimeagent.ErrUnsupported
	}
	for _, s := range c.Spec.Services {
		if check() != nil || e.Delivery.Prepare(ctx, c, s, check) != nil {
			os.Stderr.WriteString("runtime_prepare_delivery_denied\n")
			return runtimeagent.ErrUncertain
		}
		if e.verifyImage(ctx, s) != nil {
			os.Stderr.WriteString("runtime_prepare_image_identity_denied\n")
			return runtimeagent.ErrDenied
		}
	}
	return check()
}

// The pinned containerd image store addresses loaded OCI manifests directly.
// A signed registry reference remains an admission identity; no registry fetch or
// mutable tag is needed to run the exact admitted content in the isolated VM.
func (e *Engine) verifyImage(ctx context.Context, s contracts.RuntimeServiceV2) error {
	if !policy.ValidImage(s.Image) {
		return runtimeagent.ErrDenied
	}
	_, digest, _ := strings.Cut(s.Image, "@")
	var image struct {
		ID               string `json:"Id"`
		Architecture, Os string
		Config           struct {
			User    string
			Volumes map[string]json.RawMessage
		}
	}
	if e.Client.call(ctx, "GET", "/images/"+escape(digest)+"/json", nil, &image) != nil || image.ID != digest || image.Architecture != "amd64" || image.Os != "linux" || len(image.Config.Volumes) != 0 {
		return runtimeagent.ErrDenied
	}
	u, g, err := policy.User(image.Config.User)
	if err != nil || u != s.UID || g != s.GID {
		return runtimeagent.ErrDenied
	}
	return nil
}
func (e *Engine) Create(ctx context.Context, c runtimeagent.Command, check func() error) error {
	if c.Spec == nil {
		return runtimeagent.ErrDenied
	}
	// Unsupported service settings must fail before image, network or container mutation.
	for _, s := range c.Spec.Services {
		if _, err := Config(c, s, strings.Repeat("0", 64), e.MACProfile); err != nil {
			return err
		}
	}
	if e.Ledger.RegisterRestarts(ctx, c) != nil {
		return runtimeagent.ErrDenied
	}
	if e.Prepare(ctx, c, check) != nil {
		os.Stderr.WriteString("runtime_create_prepare_denied\n")
		return runtimeagent.ErrUncertain
	}
	if check() != nil {
		return runtimeagent.ErrDenied
	}
	var network struct {
		ID string `json:"Id"`
	}
	name := "tap-" + c.ID
	request := struct {
		Name, Driver         string
		Internal, EnableIPv6 bool
		CheckDuplicate       bool
		Labels, Options      map[string]string
	}{Name: name, Driver: "bridge", Internal: true, CheckDuplicate: true, Labels: labels(c, ""), Options: map[string]string{"com.docker.network.bridge.enable_icc": "true"}}
	if e.Client.call(ctx, "POST", "/networks/create", request, &network) != nil || !objectID.MatchString(network.ID) {
		return runtimeagent.ErrUncertain
	}
	expected, _ := json.Marshal(request)
	if e.Ledger.SaveResource(ctx, c.ID, runtimeagent.Resource{ID: network.ID, Kind: "network", Expected: expected}) != nil {
		return runtimeagent.ErrUncertain
	}
	if check() != nil || e.Enforcement.Network(ctx, c, network.ID) != nil {
		return runtimeagent.ErrUncertain
	}
	// All candidate containers are inspected while stopped before the first start.
	ids := map[string]string{}
	configs := map[string]ContainerConfig{}
	for _, s := range c.Spec.Services {
		cfg, err := Config(c, s, network.ID, e.MACProfile)
		if err != nil {
			return err
		}
		if check() != nil {
			return runtimeagent.ErrDenied
		}
		var created struct {
			ID string `json:"Id"`
		}
		if e.Client.call(ctx, "POST", "/containers/create?name="+name+"-"+s.Name, cfg, &created) != nil || !objectID.MatchString(created.ID) {
			return runtimeagent.ErrUncertain
		}
		raw, _ := json.Marshal(cfg)
		if e.Ledger.SaveResource(ctx, c.ID, runtimeagent.Resource{ID: created.ID, Kind: "container", Service: s.Name, Expected: raw}) != nil {
			return runtimeagent.ErrUncertain
		}
		ids[s.Name] = created.ID
		configs[s.Name] = cfg
		got, err := e.inspect(ctx, created.ID)
		if err != nil || verifyConfiguration(cfg, got, false) != nil {
			configurationDrift(cfg, got)
			os.Stderr.WriteString("runtime_create_stopped_configuration_denied\n")
			return runtimeagent.ErrUncertain
		}
	}
	// The spec has already been independently validated as an acyclic graph.
	started := map[string]bool{}
	for len(started) < len(ids) {
		progressed := false
		for _, s := range c.Spec.Services {
			if started[s.Name] {
				continue
			}
			deps := true
			for _, d := range s.DependsOn {
				deps = deps && started[d]
			}
			if !deps {
				continue
			}
			if check() != nil || e.Enforcement.Verify(ctx, c) != nil {
				return runtimeagent.ErrUncertain
			}
			if e.Client.call(ctx, "POST", "/containers/"+ids[s.Name]+"/start", nil, nil) != nil {
				return runtimeagent.ErrUncertain
			}
			if e.await(ctx, c, configs[s.Name], ids[s.Name], check) != nil {
				os.Stderr.WriteString("runtime_create_readiness_denied\n")
				return runtimeagent.ErrUncertain
			}
			started[s.Name] = true
			progressed = true
		}
		if !progressed {
			return runtimeagent.ErrDenied
		}
	}
	if e.Enforcement.Verify(ctx, c) != nil {
		return runtimeagent.ErrUncertain
	}
	return check()
}
func (e *Engine) await(ctx context.Context, c runtimeagent.Command, cfg ContainerConfig, id string, check func() error) error {
	wait, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		if check() != nil {
			return runtimeagent.ErrDenied
		}
		got, err := e.inspect(wait, id)
		if err != nil || verifyConfiguration(cfg, got, true) != nil {
			return runtimeagent.ErrDenied
		}
		if e.Enforcement == nil || e.Enforcement.VerifyContainer(wait, c, id, got.State.Pid) != nil {
			select {
			case <-wait.Done():
				return runtimeagent.ErrDenied
			case <-time.After(100 * time.Millisecond):
				continue
			}
		}
		if cfg.Healthcheck == nil || equal(cfg.Healthcheck.Test, []string{"NONE"}) {
			return nil
		}
		if got.State.Health != nil && got.State.Health.Status == "healthy" {
			return nil
		}
		if got.State.Health != nil && got.State.Health.Status == "unhealthy" {
			return runtimeagent.ErrDenied
		}
		select {
		case <-wait.Done():
			return runtimeagent.ErrDenied
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func (e *Engine) inspect(ctx context.Context, id string) (Inspected, error) {
	var got Inspected
	if !objectID.MatchString(id) {
		return got, runtimeagent.ErrDenied
	}
	err := e.Client.call(ctx, "GET", "/containers/"+id+"/json", nil, &got)
	if err != nil {
		return Inspected{}, err
	}
	if got.ID != id {
		return Inspected{}, runtimeagent.ErrDenied
	}
	return got, nil
}
func (e *Engine) owned(ctx context.Context, c runtimeagent.Command) ([]runtimeagent.Resource, error) {
	return e.ownedResources(ctx, c, false)
}
func (e *Engine) ownedResources(ctx context.Context, c runtimeagent.Command, cleanup bool) ([]runtimeagent.Resource, error) {
	if e.Client == nil || e.Ledger == nil {
		return nil, runtimeagent.ErrDenied
	}
	resources, err := e.Ledger.Resources(ctx, c.Target)
	if err != nil || (!cleanup && len(resources) == 0) {
		return nil, runtimeagent.ErrUncertain
	}
	want := c
	want.ID = c.Target
	for _, resource := range resources {
		if !objectID.MatchString(resource.ID) {
			return nil, runtimeagent.ErrDenied
		}
		switch resource.Kind {
		case "container":
			var cfg ContainerConfig
			if json.Unmarshal(resource.Expected, &cfg) != nil || !equal(cfg.Labels, labels(want, resource.Service)) {
				return nil, runtimeagent.ErrDenied
			}
			got, err := e.inspect(ctx, resource.ID)
			if cleanup && err == errObjectAbsent {
				continue
			}
			if err != nil || !equal(got.Config.Labels, cfg.Labels) {
				return nil, runtimeagent.ErrDenied
			}
		case "network":
			var expected struct{ Labels map[string]string }
			if json.Unmarshal(resource.Expected, &expected) != nil || !equal(expected.Labels, labels(want, "")) {
				return nil, runtimeagent.ErrDenied
			}
			var got struct {
				ID         string `json:"Id"`
				Labels     map[string]string
				Containers map[string]json.RawMessage
				Internal   bool
				Driver     string
			}
			err := e.Client.call(ctx, "GET", "/networks/"+resource.ID, nil, &got)
			if cleanup && err == errObjectAbsent {
				continue
			}
			if err != nil || got.ID != resource.ID || !got.Internal || got.Driver != "bridge" || !equal(got.Labels, labels(want, "")) {
				return nil, runtimeagent.ErrDenied
			}
			if !cleanup {
				known := map[string]bool{}
				for _, r := range resources {
					if r.Kind == "container" {
						known[r.ID] = true
					}
				}
				for id := range got.Containers {
					if !known[id] {
						return nil, runtimeagent.ErrDenied
					}
				}
			}
		default:
			return nil, runtimeagent.ErrDenied
		}
	}
	return resources, nil
}
func (e *Engine) Inspect(ctx context.Context, c runtimeagent.Command) (string, error) {
	r, err := e.owned(ctx, c)
	if err != nil {
		return "", err
	}
	state := "stopped"
	for _, x := range r {
		if x.Kind != "container" {
			continue
		}
		got, err := e.inspect(ctx, x.ID)
		if err != nil {
			return "", err
		}
		var cfg ContainerConfig
		if json.Unmarshal(x.Expected, &cfg) != nil || verifyConfiguration(cfg, got, got.State.Running) != nil {
			return "", runtimeagent.ErrDenied
		}
		if got.State.Running {
			if e.Enforcement == nil || e.Enforcement.VerifyContainer(ctx, c, x.ID, got.State.Pid) != nil {
				return "", runtimeagent.ErrDenied
			}
			state = "running"
		}
	}
	if e.Enforcement == nil || e.Enforcement.Verify(ctx, c) != nil {
		return "", runtimeagent.ErrDenied
	}
	return state, nil
}
func (e *Engine) Logs(ctx context.Context, c runtimeagent.Command) ([]byte, error) {
	r, err := e.owned(ctx, c)
	if err != nil {
		return nil, err
	}
	var out []byte
	for _, x := range r {
		if x.Kind != "container" {
			continue
		}
		b, err := e.Client.logs(ctx, x.ID, c.LogLimit-len(out))
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	return out, nil
}
func (e *Engine) Stop(ctx context.Context, c runtimeagent.Command, check func() error) error {
	r, err := e.ownedResources(ctx, c, true)
	if err != nil {
		return err
	}
	var drainErr error
	if drainer, ok := e.Enforcement.(interface {
		DropIngress(context.Context, runtimeagent.Command) error
	}); ok {
		drainErr = drainer.DropIngress(ctx, c)
	} else {
		drainErr = runtimeagent.ErrUnsupported
	}
	for _, x := range r {
		if x.Kind != "container" {
			continue
		}
		if check() != nil {
			return runtimeagent.ErrDenied
		}
		got, err := e.inspect(ctx, x.ID)
		if err == errObjectAbsent {
			continue
		}
		if err != nil {
			return err
		}
		if !got.State.Running {
			continue
		}
		if e.Client.call(ctx, "POST", fmt.Sprintf("/containers/%s/stop?t=5", x.ID), nil, nil) != nil {
			if check() != nil || e.Client.call(ctx, "POST", "/containers/"+x.ID+"/kill?signal=SIGKILL", nil, nil) != nil {
				return runtimeagent.ErrUncertain
			}
		}
		got, err = e.inspect(ctx, x.ID)
		if err != nil || got.State.Running {
			return runtimeagent.ErrUncertain
		}
	}
	if drainErr != nil {
		return runtimeagent.ErrUncertain
	}
	return nil
}
func (e *Engine) Remove(ctx context.Context, c runtimeagent.Command, check func() error) error {
	if err := e.Stop(ctx, c, check); err != nil {
		return err
	}
	r, err := e.ownedResources(ctx, c, true)
	if err != nil {
		return err
	}
	// Resources are sorted container before network; never force-remove networks.
	for _, x := range r {
		if check() != nil {
			return runtimeagent.ErrDenied
		}
		path := "/containers/" + x.ID + "?v=false&force=false"
		if x.Kind == "network" {
			path = "/networks/" + x.ID
		}
		// A lost DELETE response can still have completed. Only an independent
		// same-backend GET 404 permits forgetting the exact recorded object.
		_ = e.Client.call(ctx, "DELETE", path, nil, nil)
		inspectPath := "/containers/" + x.ID + "/json"
		if x.Kind == "network" {
			inspectPath = "/networks/" + x.ID
		}
		if e.Client.call(ctx, "GET", inspectPath, nil, nil) != errObjectAbsent {
			return runtimeagent.ErrUncertain
		}
		if e.Ledger.ForgetResource(ctx, c.Target, x.ID) != nil {
			return runtimeagent.ErrUncertain
		}
	}
	if e.Enforcement == nil || e.Enforcement.Release(ctx, c) != nil {
		return runtimeagent.ErrUncertain
	}
	return nil
}
