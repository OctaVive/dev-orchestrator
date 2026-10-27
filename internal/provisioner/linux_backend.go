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
}

// NewLinuxBackend fails closed on unsupported hosts. There is no emulation or
// container fallback. Controls report implementation assertions, NOT acceptance.
func NewLinuxBackend(c LinuxConfig) (Backend, error) { return newLinuxBackend(c) }

// RunLinuxGuest is an internal systemd service entry point, not an RPC action.
func RunLinuxGuest(ctx context.Context, config, job string) error {
	return runLinuxGuest(ctx, config, job)
}

func ExpireLinuxGuest(ctx context.Context, config, job string) error {
	return expireLinuxGuest(ctx, config, job)
}

func LoadLinuxConfig(path string) (LinuxConfig, error) { return loadLinuxConfig(path) }
