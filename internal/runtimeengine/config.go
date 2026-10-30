package runtimeengine

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/runtimeagent"
)

type LogConfig struct {
	Type   string
	Config map[string]string
}
type RestartPolicy struct {
	Name              string
	MaximumRetryCount int
}
type HealthConfig struct {
	Test        []string
	Interval    int64
	Timeout     int64
	Retries     int
	StartPeriod int64
}
type HostConfig struct {
	Binds             []string
	Mounts            []json.RawMessage
	DeviceCgroupRules []string
	VolumesFrom       []string
	Links             []string
	ExtraHosts        []string
	DNS               []string
	DNSOptions        []string
	DNSSearch         []string
	Sysctls           map[string]string
	Runtime           string
	ShmSize           int64
	CpuPeriod         int64
	CpuQuota          int64
	CpusetCpus        string
	CpusetMems        string
	CapDrop           []string
	CapAdd            []string
	SecurityOpt       []string
	GroupAdd          []string
	Devices           []json.RawMessage
	DeviceRequests    []json.RawMessage
	ReadonlyRootfs    bool
	Privileged        bool
	PublishAllPorts   bool
	PortBindings      map[string][]json.RawMessage
	NetworkMode       string
	PidMode           string
	IpcMode           string
	UTSMode           string
	UsernsMode        string
	CgroupnsMode      string
	NanoCpus          int64
	Memory            int64
	MemorySwap        int64
	MemoryReservation int64
	PidsLimit         int64
	Tmpfs             map[string]string
	LogConfig         LogConfig
	RestartPolicy     RestartPolicy
	AutoRemove        bool
}
type Endpoint struct {
	NetworkID string
	Aliases   []string
}
type NetworkingConfig struct{ EndpointsConfig map[string]Endpoint }
type ContainerConfig struct {
	Image            string
	User             string
	Cmd              []string
	Entrypoint       []string
	Env              []string
	Labels           map[string]string
	ExposedPorts     map[string]struct{}
	Volumes          map[string]struct{}
	Healthcheck      *HealthConfig `json:",omitempty"`
	HostConfig       HostConfig
	NetworkingConfig NetworkingConfig
}

func labels(c runtimeagent.Command, service string) map[string]string {
	return map[string]string{"tap.worker": c.WorkerID, "tap.incarnation": c.Incarnation, "tap.app": c.AppID, "tap.deployment": c.DeploymentID, "tap.generation": strconv.FormatInt(c.Generation, 10), "tap.spec": c.SpecHash, "tap.owner": c.ID, "tap.service": service}
}

// Config always disables daemon-managed restart. The agent owns the finite
// lifetime budget, so daemon restarts cannot reset it or revive stopped apps.
// Workloads with restart attempts are rejected until durable restart dispatch exists.
func Config(c runtimeagent.Command, s contracts.RuntimeServiceV2, network, mac string) (ContainerConfig, error) {
	if !objectID.MatchString(network) || mac == "" || s.UID <= 0 || s.GID <= 0 || len(s.Volumes) > 0 || len(s.Secrets) > 0 || s.RestartAttempts != 0 {
		return ContainerConfig{}, runtimeagent.ErrUnsupported
	}
	h := HostConfig{Runtime: "runc", ShmSize: 1 << 20, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges=true", "apparmor=" + mac}, ReadonlyRootfs: true, NetworkMode: network, IpcMode: "private", CgroupnsMode: "private", NanoCpus: int64(s.Resources.CPUMillis) * 1000000, Memory: s.Resources.MemoryBytes, MemorySwap: s.Resources.MemoryBytes, PidsLimit: int64(s.Resources.PIDs), Tmpfs: map[string]string{"/tmp": fmt.Sprintf("rw,noexec,nosuid,nodev,size=%d,mode=1777", s.Resources.TmpBytes), "/run": fmt.Sprintf("rw,noexec,nosuid,nodev,size=%d,mode=755", s.Resources.WritableBytes)}, LogConfig: LogConfig{Type: "local", Config: map[string]string{"max-size": strconv.FormatInt(s.Resources.LogBytes/2, 10), "max-file": "2", "compress": "false"}}, RestartPolicy: RestartPolicy{Name: "no"}}
	out := ContainerConfig{Healthcheck: &HealthConfig{Test: []string{"NONE"}}, Image: s.Image, User: fmt.Sprintf("%d:%d", s.UID, s.GID), Cmd: s.Command, Entrypoint: s.Entrypoint, Labels: labels(c, s.Name), HostConfig: h, NetworkingConfig: NetworkingConfig{EndpointsConfig: map[string]Endpoint{network: {NetworkID: network, Aliases: []string{s.Name}}}}, ExposedPorts: map[string]struct{}{}}
	for k, v := range s.Environment {
		out.Env = append(out.Env, k+"="+v)
	}
	sort.Strings(out.Env)
	for _, p := range s.Expose {
		out.ExposedPorts[fmt.Sprintf("%d/tcp", p)] = struct{}{}
	}
	if s.Health != nil {
		out.Healthcheck = &HealthConfig{Test: append([]string{"CMD"}, s.Health.Argv...), Interval: int64(s.Health.IntervalSeconds) * 1e9, Timeout: int64(s.Health.TimeoutSeconds) * 1e9, Retries: s.Health.Retries}
	}
	return out, nil
}

// Inspected is internal and must never be returned as a status response.
type Inspected struct {
	ID              string `json:"Id"`
	Image           string
	Config          ContainerConfig
	HostConfig      HostConfig
	AppArmorProfile string
	Mounts          []struct {
		Type, Source, Destination string
		RW                        bool
	}
	State struct {
		Running bool
		Status  string
		Pid     int
		Health  *struct{ Status string }
	}
	NetworkSettings struct {
		Ports    map[string][]json.RawMessage
		Networks map[string]struct {
			NetworkID string
			Aliases   []string
			IPAddress string
		}
	}
}

func equal(a, b any) bool { return reflect.DeepEqual(a, b) }
func Verify(expected ContainerConfig, got Inspected, running bool) error {
	// Compare the complete typed HostConfig; no ignored dangerous modeled field.
	// Engine-added default namespace/security values require explicit normalization.
	if len(expected.HostConfig.SecurityOpt) != 2 {
		return runtimeagent.ErrDenied
	}
	h := got.HostConfig
	if h.PidMode == "" {
		h.PidMode = expected.HostConfig.PidMode
	}
	if !equal(h, expected.HostConfig) || got.Config.Image != expected.Image || got.Config.User != expected.User || !equal(got.Config.Cmd, expected.Cmd) || !equal(got.Config.Entrypoint, expected.Entrypoint) || !equal(got.Config.Env, expected.Env) || !equal(got.Config.Labels, expected.Labels) || !equal(got.Config.ExposedPorts, expected.ExposedPorts) || len(got.Config.Volumes) != 0 || !equal(got.Config.Healthcheck, expected.Healthcheck) || got.AppArmorProfile == "" || got.AppArmorProfile != expected.HostConfig.SecurityOpt[1][len("apparmor="):] || len(got.Mounts) != 0 || got.State.Running != running || len(got.NetworkSettings.Networks) != 1 {
		return runtimeagent.ErrDenied
	}
	for _, v := range got.NetworkSettings.Ports {
		if len(v) > 0 {
			return runtimeagent.ErrDenied
		}
	}
	for _, v := range got.NetworkSettings.Networks {
		if v.NetworkID != expected.HostConfig.NetworkMode {
			return runtimeagent.ErrDenied
		}
	}
	return nil
}
