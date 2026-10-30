package runtimeprofile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func bundle() map[string]any {
	return map[string]any{"process": map[string]any{"user": map[string]any{"uid": 1000, "gid": 1000}, "noNewPrivileges": true, "capabilities": map[string]any{"bounding": []string{}, "effective": []string{}}}, "root": map[string]any{"path": "rootfs", "readonly": true}, "linux": map[string]any{"seccomp": map[string]any{"defaultAction": "SCMP_ACT_ERRNO"}, "uidMappings": []any{map[string]any{"containerID": 0, "hostID": 100000, "size": 65536}}, "gidMappings": []any{map[string]any{"containerID": 0, "hostID": 100000, "size": 65536}}, "namespaces": []any{map[string]any{"type": "user"}, map[string]any{"type": "pid"}, map[string]any{"type": "ipc"}, map[string]any{"type": "mount"}, map[string]any{"type": "uts"}, map[string]any{"type": "cgroup"}, map[string]any{"type": "network", "path": "/var/run/docker/netns/owned"}}}}
}
func writeBundle(t *testing.T, m map[string]any) string {
	t.Helper()
	dir := t.TempDir()
	b, e := json.Marshal(m)
	if e != nil || os.WriteFile(filepath.Join(dir, "config.json"), b, 0600) != nil {
		t.Fatal("fixture")
	}
	return dir
}
func TestFixedBundleSupplement(t *testing.T) {
	dir := writeBundle(t, bundle())
	if Harden(dir) != nil {
		t.Fatal("supplement")
	}
	b, e := os.ReadFile(filepath.Join(dir, "config.json"))
	if e != nil {
		t.Fatal(e)
	}
	var got struct {
		Process struct {
			ApparmorProfile string
			NoNewPrivileges bool
		}
		Linux struct {
			Namespaces  []struct{ Type, Path string }
			UIDMappings []struct{ ContainerID, HostID, Size int }
		}
	}
	if json.Unmarshal(b, &got) != nil || got.Process.ApparmorProfile != MACProfile || !got.Process.NoNewPrivileges {
		t.Fatal("missing MAC/nnp")
	}
	user := false
	for _, ns := range got.Linux.Namespaces {
		if ns.Type == "user" {
			user = ns.Path == ""
		}
		if ns.Type == "network" && ns.Path != "/var/run/docker/netns/owned" {
			t.Fatal("network changed")
		}
	}
	if !user || len(got.Linux.UIDMappings) != 1 || got.Linux.UIDMappings[0].Size != 65536 {
		t.Fatal("private user namespace missing")
	}
}
func TestUnsafeBundlesDeniedBeforeNamespaceJoin(t *testing.T) {
	cases := map[string]func(map[string]any){"root": func(m map[string]any) { m["process"].(map[string]any)["user"].(map[string]any)["uid"] = 0 }, "group": func(m map[string]any) {
		m["process"].(map[string]any)["user"].(map[string]any)["additionalGids"] = []int{0}
	}, "nnp": func(m map[string]any) { m["process"].(map[string]any)["noNewPrivileges"] = false }, "capabilities": func(m map[string]any) {
		m["process"].(map[string]any)["capabilities"] = map[string]any{"effective": []string{"CAP_SYS_ADMIN"}}
	}, "mac": func(m map[string]any) { m["process"].(map[string]any)["apparmorProfile"] = "unconfined" }, "root-write": func(m map[string]any) { m["root"].(map[string]any)["readonly"] = false }, "hooks": func(m map[string]any) { m["hooks"] = map[string]any{"prestart": []any{}} }, "seccomp": func(m map[string]any) { m["linux"].(map[string]any)["seccomp"] = nil }, "allow-all-syscalls": func(m map[string]any) {
		m["linux"].(map[string]any)["seccomp"] = map[string]any{"defaultAction": "SCMP_ACT_ALLOW"}
	}, "host-network": func(m map[string]any) {
		ns := m["linux"].(map[string]any)["namespaces"].([]any)
		ns[len(ns)-1].(map[string]any)["path"] = "/proc/1/ns/net"
	}, "shared-pid": func(m map[string]any) {
		ns := m["linux"].(map[string]any)["namespaces"].([]any)
		ns[0].(map[string]any)["path"] = "/proc/1/ns/pid"
	}}
	for n, change := range cases {
		t.Run(n, func(t *testing.T) {
			m := bundle()
			change(m)
			dir := writeBundle(t, m)
			if Harden(dir) != ErrDenied {
				t.Fatal("unsafe bundle accepted or joined")
			}
		})
	}
}
func TestBundlePathAndSymlinkDenials(t *testing.T) {
	if Harden("relative") != ErrDenied {
		t.Fatal("relative path")
	}
	dir := writeBundle(t, bundle())
	p := filepath.Join(dir, "config.json")
	os.Remove(p)
	os.Symlink("/etc/passwd", p)
	if Harden(dir) != ErrDenied {
		t.Fatal("symlink")
	}
	os.Remove(p)
	os.WriteFile(p, []byte(strings.Repeat(" ", MaxBundle+1)), 0600)
	if Harden(dir) != ErrDenied {
		t.Fatal("oversized bundle")
	}
}
