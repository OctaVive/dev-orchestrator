package runtimehost

import (
	"dev-orchestrator/internal/contracts"
	"testing"
)

func profile() Profile {
	tools := map[string]string{}
	for _, path := range ToolPaths {
		tools[path] = contracts.Digest([]byte(path))
	}
	return Profile{Version: 1, WorkerID: "11111111-1111-4111-8111-111111111111", Incarnation: "22222222-2222-4222-8222-222222222222", TemplateHash: contracts.Digest([]byte("template")), MACDigest: contracts.Digest([]byte("mac")), MemoryBytes: 1 << 30, DiskBytes: 1 << 30, CPUMillis: 2000, Tools: tools, Apps: []App{{ID: "33333333-3333-4333-8333-333333333333", MemoryBytes: 512 << 20, CPUMillis: 1000, PIDs: 128, ImageDiskBytes: 128 << 20, WorkloadDiskBytes: 128 << 20}}}
}
func TestBoundedOperatorSlots(t *testing.T) {
	p := profile()
	if !p.Valid() {
		t.Fatal("valid operator profile")
	}
	for _, field := range []string{"memory", "disk", "cpu", "duplicate", "path", "tool", "extra-tool", "unbounded"} {
		t.Run(field, func(t *testing.T) {
			p := profile()
			switch field {
			case "memory":
				p.MemoryBytes = 512 << 20
			case "disk":
				p.DiskBytes = (256 << 20) - 1
			case "cpu":
				p.CPUMillis = 1000
			case "duplicate":
				p.Apps = append(p.Apps, p.Apps[0])
			case "path":
				p.Apps[0].ID = "../foreign"
			case "tool":
				p.Tools[ToolPaths[0]] = "unversioned"
			case "extra-tool":
				p.Tools["/bin/sh"] = contracts.Digest([]byte("shell"))
			case "unbounded":
				p.Apps[0].PIDs = 0
			}
			if p.Valid() {
				t.Fatal("unsafe slot admitted")
			}
		})
	}
	r := p.Apps[0].Reservation()
	if !r.Valid() || r.DaemonMemory != DaemonMemory || r.ImageDisk != p.Apps[0].ImageDiskBytes || r.Socket != RunRoot+"/apps/"+p.Apps[0].ID+"/docker.sock" {
		t.Fatal("reservation omitted daemon/image charge")
	}
}
func TestProfilePinCoversBudgetsAndTools(t *testing.T) {
	p := profile()
	before := p.Hash()
	p.Apps[0].MemoryBytes += 16 << 20
	if p.Hash() == before {
		t.Fatal("memory not bound")
	}
	p = profile()
	p.Tools[ToolPaths[0]] = contracts.Digest([]byte("replacement"))
	if p.Hash() == before {
		t.Fatal("tool not bound")
	}
}
