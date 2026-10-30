package provisioner

import "context"

// LinuxConfig is host-local operator configuration, never accepted over RPC.
// Image is a credential-free raw boot disk (at most 1 GiB), expanded into a
// preallocated 10 GiB private raw disk. No backing chains or image parsers run.
type LinuxConfig struct {
	Root       string `json:"root"`
	Image      string `json:"image"`
	Digest     string `json:"digest"`
	TemplateID string `json:"template_id"`
	Executable string `json:"executable"`
	QEMU       string `json:"qemu"`
	UID        uint32 `json:"uid"`
	GID        uint32 `json:"gid"`
	KVMGID     uint32 `json:"kvm_gid"`
	// Empty/none preserves M04's no-NIC mode. broker-v1 is explicit opt-in.
	CloneEnabled     bool   `json:"clone_enabled,omitempty"`
	NetworkMode      string `json:"network_mode,omitempty"`
	EgressPolicy     string `json:"egress_policy,omitempty"`
	EgressPolicyHash string `json:"egress_policy_hash,omitempty"`
	EgressCA         string `json:"egress_ca,omitempty"`
	EgressKey        string `json:"egress_key,omitempty"`
	EgressCAHash     string `json:"egress_ca_hash,omitempty"`
	EgressResolver   string `json:"egress_resolver,omitempty"`
	BrokerExecutable string `json:"broker_executable,omitempty"`
	BrokerUID        uint32 `json:"broker_uid,omitempty"`
	BrokerGID        uint32 `json:"broker_gid,omitempty"`
}

// NewLinuxBackend fails closed on unsupported hosts. There is no emulation or
// container fallback. Controls report implementation assertions, NOT acceptance.
func NewLinuxBackend(c LinuxConfig) (Backend, error) { return newLinuxBackend(c) }

// NewLinuxGuardBackend does not require live egress policy/CA health to recover
// old leases. Create still performs the full admission preflight on every call.
func NewLinuxGuardBackend(c LinuxConfig) (Backend, error) { return newLinuxGuardBackend(c) }

// RunLinuxGuest is an internal systemd service entry point, not an RPC action.
func RunLinuxGuest(ctx context.Context, config, job string) error {
	return runLinuxGuest(ctx, config, job)
}

func ExpireLinuxGuest(ctx context.Context, config, job string) error {
	return expireLinuxGuest(ctx, config, job)
}

func LoadLinuxConfig(path string) (LinuxConfig, error) { return loadLinuxConfig(path) }

func RunLinuxBroker(ctx context.Context, config, job string) error {
	return runLinuxBroker(ctx, config, job)
}
