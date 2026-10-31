package runtimeengine

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/runtimeagent"
	"dev-orchestrator/internal/runtimeobservation"
)

func (e *MeasuredEnforcement) runCanary(ctx context.Context, c runtimeagent.Command, check func() error) (outcome error) {
	if check() != nil {
		return runtimeagent.ErrDenied
	}
	request := struct {
		Name, Driver             string
		Internal, CheckDuplicate bool
		Labels                   map[string]string
	}{Name: "tap-probe-" + c.ID, Driver: "bridge", Internal: true, CheckDuplicate: true, Labels: labels(c, "")}
	var network struct {
		ID string `json:"Id"`
	}
	if e.client.call(ctx, "POST", "/networks/create", request, &network) != nil || !objectID.MatchString(network.ID) {
		return runtimeagent.ErrUncertain
	}
	raw, _ := json.Marshal(request)
	if e.ledger.SaveResource(ctx, c.ID, runtimeagent.Resource{ID: network.ID, Kind: "network", Expected: raw}) != nil {
		return runtimeagent.ErrUncertain
	}
	var createdID string
	cleanup := &Engine{Client: e.client, Ledger: e.ledger, Enforcement: e, WorkerID: e.config.WorkerID, Incarnation: e.config.Incarnation, MACProfile: "tap-runtime"}
	remove := c
	remove.Target = c.ID
	remove.Operation = "remove"
	remove.Spec = nil
	defer func() {
		if createdID != "" {
			stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			report, err := e.measurement.Report(stop, runtimeobservation.Request{Operation: "relay-stop", AppID: c.AppID, OwnerID: c.ID, ContainerID: createdID})
			cancel()
			if err != nil || report.Health == nil || report.Health.Status != 204 {
				outcome = runtimeagent.ErrUncertain
			}
		}
		bounded, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if cleanup.Remove(bounded, remove, func() error { return bounded.Err() }) != nil {
			outcome = runtimeagent.ErrUncertain
		}
	}()
	service := contracts.RuntimeServiceV2{Name: "tapcanary", Image: e.config.Canary.ManifestDigest, UID: 1000, GID: 1000, Entrypoint: []string{"/runtime-canary"}, Command: []string{"serve"}, Environment: map[string]string{"GOMAXPROCS": "1", "GOMEMLIMIT": "16777216", "TAP_CANARY_CONTAINER": "1"}, Expose: []int{8080}, Resources: contracts.Resources{CPUMillis: 100, MemoryBytes: 64 << 20, PIDs: 16, TmpBytes: 8 << 20, WritableBytes: 8 << 20, LogBytes: 2 << 20}}
	config, err := Config(c, service, network.ID, "tap-runtime")
	if err != nil {
		return err
	}
	var created struct {
		ID string `json:"Id"`
	}
	if check() != nil || e.client.call(ctx, "POST", "/containers/create?name=tap-probe-"+c.ID, config, &created) != nil || !objectID.MatchString(created.ID) {
		return runtimeagent.ErrUncertain
	}
	createdID = created.ID
	raw, _ = json.Marshal(config)
	if e.ledger.SaveResource(ctx, c.ID, runtimeagent.Resource{ID: created.ID, Kind: "container", Service: service.Name, Expected: raw}) != nil {
		return runtimeagent.ErrUncertain
	}
	got, err := e.client.InspectContainer(ctx, created.ID)
	if err != nil || verifyConfiguration(config, got, false) != nil {
		configurationDrift(config, got)
		return fmt.Errorf("runtime_canary_stopped_configuration_denied")
	}
	if check() != nil || e.client.call(ctx, "POST", "/containers/"+created.ID+"/start", nil, nil) != nil {
		return runtimeagent.ErrUncertain
	}
	wait, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var q runtimeobservation.Request
	for {
		if check() != nil {
			return runtimeagent.ErrDenied
		}
		got, err = e.client.InspectContainer(wait, created.ID)
		if err != nil || verifyConfiguration(config, got, true) != nil {
			configurationDrift(config, got)
			return fmt.Errorf("runtime_canary_live_configuration_denied")
		}
		q, err = e.request(wait, c, created.ID)
		if err != nil {
			return err
		}
		q.Operation = "relay-start"
		q.Port = 8080
		q.Path = "/probe"
		report, err := e.measurement.Report(wait, q)
		if err == nil && report.Process != nil && report.Health != nil && report.Health.Status == 200 {
			body, err := base64.StdEncoding.Strict().DecodeString(report.Health.BodyBase64)
			if err != nil || len(body) > 2048 {
				return runtimeagent.ErrUnsupported
			}
			probes, err := contracts.DecodeConfiguration[map[string]bool](bytes.NewReader(body))
			if err != nil || len(probes) != 14 {
				return runtimeagent.ErrUnsupported
			}
			for _, name := range []string{"tmp_writable", "run_writable", "host_ipv4_denied", "host_ipv6_denied", "metadata_denied", "management_denied", "external_denied", "readonly_hosts", "readonly_hostname", "readonly_resolv.conf", "engine_socket_absent", "agent_credentials_absent", "control_socket_absent", "systemd_socket_absent"} {
				if !probes[name] {
					return runtimeagent.ErrUnsupported
				}
			}
			break
		}
		select {
		case <-wait.Done():
			return fmt.Errorf("runtime_canary_private_probe_denied")
		case <-time.After(100 * time.Millisecond):
		}
	}
	stop := runtimeobservation.Request{Operation: "relay-stop", AppID: c.AppID, OwnerID: c.ID, ContainerID: created.ID}
	bounded, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	report, err := e.measurement.Report(bounded, stop)
	if err != nil || report.Health == nil || report.Health.Status != 204 {
		return runtimeagent.ErrUncertain
	}
	return check()
}
