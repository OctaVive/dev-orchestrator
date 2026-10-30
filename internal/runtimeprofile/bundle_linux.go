// Package runtimeprofile is an experimental fixed OCI supplement inside the
// runtime VM. It is called only by the platform-owned runc wrapper, never RPC.
package runtimeprofile

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const MACProfile = "tap-runtime"
const Runtime = "tap-runc"
const MaxBundle = 1 << 20

var ErrDenied = errors.New("runtime_bundle_denied")

// Harden injects the preloaded MAC profile even when Docker's rootless support
// check suppresses its AppArmor option. It requires an existing private user
// namespace per container; the daemon's user namespace must never be reused.
// Bundle paths come from containerd, not from deployment commands.
func Harden(bundle string) error {
	if !filepath.IsAbs(bundle) || filepath.Clean(bundle) != bundle {
		return ErrDenied
	}
	root, e := os.OpenRoot(bundle)
	if e != nil {
		return ErrDenied
	}
	defer root.Close()
	file, e := root.OpenFile("config.json", os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if e != nil {
		return ErrDenied
	}
	st, e := file.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > MaxBundle {
		file.Close()
		return ErrDenied
	}
	b, e := io.ReadAll(io.LimitReader(file, MaxBundle+1))
	file.Close()
	if e != nil || len(b) > MaxBundle {
		return ErrDenied
	}
	var spec map[string]json.RawMessage
	if json.Unmarshal(b, &spec) != nil || len(spec["hooks"]) > 0 && string(spec["hooks"]) != "null" {
		return ErrDenied
	}
	var process map[string]json.RawMessage
	if json.Unmarshal(spec["process"], &process) != nil {
		return ErrDenied
	}
	var user struct {
		UID, GID       uint32
		AdditionalGids []uint32
	}
	if json.Unmarshal(process["user"], &user) != nil || user.UID == 0 || user.GID == 0 || user.UID > 65535 || user.GID > 65535 || len(user.AdditionalGids) > 1 || len(user.AdditionalGids) == 1 && user.AdditionalGids[0] != user.GID {
		return ErrDenied
	}
	var nnp bool
	if json.Unmarshal(process["noNewPrivileges"], &nnp) != nil || !nnp {
		return ErrDenied
	}
	var caps map[string][]string
	if json.Unmarshal(process["capabilities"], &caps) != nil {
		return ErrDenied
	}
	for _, v := range caps {
		if len(v) != 0 {
			return ErrDenied
		}
	}
	process["capabilities"] = json.RawMessage(`{"bounding":[],"effective":[],"inheritable":[],"permitted":[],"ambient":[]}`)
	var profile string
	if len(process["apparmorProfile"]) > 0 && json.Unmarshal(process["apparmorProfile"], &profile) != nil {
		return ErrDenied
	}
	if profile != "" && profile != MACProfile {
		return ErrDenied
	}
	process["apparmorProfile"], _ = json.Marshal(MACProfile)
	var rootfs struct{ Readonly bool }
	if json.Unmarshal(spec["root"], &rootfs) != nil || !rootfs.Readonly {
		return ErrDenied
	}
	var linux map[string]json.RawMessage
	if json.Unmarshal(spec["linux"], &linux) != nil || len(linux["seccomp"]) == 0 || string(linux["seccomp"]) == "null" {
		return ErrDenied
	}
	var seccomp struct{ DefaultAction string }
	if json.Unmarshal(linux["seccomp"], &seccomp) != nil || seccomp.DefaultAction != "SCMP_ACT_ERRNO" {
		return ErrDenied
	}
	var namespaces []struct {
		Type string `json:"type"`
		Path string `json:"path,omitempty"`
	}
	if json.Unmarshal(linux["namespaces"], &namespaces) != nil {
		return ErrDenied
	}
	seen := map[string]bool{}
	for _, ns := range namespaces {
		if seen[ns.Type] {
			return ErrDenied
		}
		seen[ns.Type] = true
		if ns.Type == "network" && ns.Path != "" {
			if !strings.HasPrefix(ns.Path, "/var/run/docker/netns/") && !strings.HasPrefix(ns.Path, "/run/docker/netns/") {
				return ErrDenied
			}
		}
		if ns.Type == "user" && ns.Path != "" {
			return ErrDenied
		}
		if ns.Type == "pid" || ns.Type == "ipc" || ns.Type == "mount" || ns.Type == "uts" || ns.Type == "cgroup" {
			if ns.Path != "" {
				return ErrDenied
			}
		}
	}
	for _, name := range []string{"pid", "ipc", "mount", "uts", "network", "cgroup"} {
		if !seen[name] {
			return ErrDenied
		}
	}
	if !seen["user"] {
		return ErrDenied
	}
	for _, key := range []string{"uidMappings", "gidMappings"} {
		var mappings []struct{ ContainerID, HostID, Size int64 }
		if json.Unmarshal(linux[key], &mappings) != nil || len(mappings) < 1 || len(mappings) > 8 {
			return ErrDenied
		}
		for _, m := range mappings {
			if m.HostID <= 0 || m.ContainerID < 0 || m.Size <= 0 || m.Size > 1<<32 || m.HostID > 1<<32-m.Size || m.ContainerID > 1<<32-m.Size {
				return ErrDenied
			}
		}
	}
	linux["namespaces"], _ = json.Marshal(namespaces)
	spec["linux"], _ = json.Marshal(linux)
	spec["process"], _ = json.Marshal(process)
	b, e = json.Marshal(spec)
	if e != nil || len(b) > MaxBundle {
		return ErrDenied
	}
	// The containerd bundle is private to the runtime account. Replace atomically,
	// never follow an attacker-created config symlink or truncate its target.
	output, e := root.OpenFile("config.tap-pending", os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return ErrDenied
	}
	defer root.Remove("config.tap-pending")
	if _, e = output.Write(b); e != nil || output.Sync() != nil {
		output.Close()
		return ErrDenied
	}
	if output.Close() != nil || root.Rename("config.tap-pending", "config.json") != nil {
		return ErrDenied
	}
	return nil
}
