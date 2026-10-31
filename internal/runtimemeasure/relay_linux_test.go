package runtimemeasure

import (
	"dev-orchestrator/internal/runtimenet"
	"testing"
)

func TestStoppingServiceWithoutRelayPreservesSiblingIngress(t *testing.T) {
	const app = "11111111-1111-4111-8111-111111111111"
	const owner = "22222222-2222-4222-8222-222222222222"
	canceled := false
	entry := &relayEntry{container: "web", configuration: runtimenet.Configuration{AppID: app, OwnerID: owner}, cancel: func() { canceled = true }}
	manager := relayManager{entries: map[string]*relayEntry{relayKey(app, owner, "web"): entry}}
	if err := manager.stop(app, owner, "db"); err != nil {
		t.Fatal("service with no ingress blocked deployment drain", err)
	}
	if canceled || len(manager.entries) != 1 || manager.entries[relayKey(app, owner, "web")] != entry {
		t.Fatal("stopping db altered web ingress")
	}
}
