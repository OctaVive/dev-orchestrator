// runtime-agent is an outbound-only typed runtime process inside a dedicated VM.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"flag"
	"os"
	"os/signal"
	"reflect"
	"syscall"

	"dev-orchestrator/internal/runtimeagent"
	"dev-orchestrator/internal/runtimeengine"
	"dev-orchestrator/internal/runtimehost"
	"dev-orchestrator/internal/runtimeisolation"
	"dev-orchestrator/internal/runtimeprocess"
	"dev-orchestrator/internal/runtimerpc"
)

func fatal(code string) { os.Stderr.WriteString(code + "\n"); os.Exit(1) }
func main() {
	syscall.Umask(0077)
	path := flag.String("config", runtimehost.Root+"/agent/config.json", "private operator configuration")
	flag.Parse()
	if os.Geteuid() != 1000 || flag.NArg() != 0 {
		fatal("runtime_agent_identity_denied")
	}
	configuration, err := runtimeprocess.LoadAgent(*path)
	if err != nil {
		fatal("runtime_agent_configuration_denied")
	}
	profile, err := runtimehost.Load()
	if err != nil || profile.Canary == nil || !profile.Canary.Valid() {
		fatal("runtime_agent_profile_denied")
	}
	keys, err := runtimeprocess.PublicKeys(configuration.CommandKeys)
	if err != nil {
		fatal("runtime_agent_keys_denied")
	}
	inventoryKey, err := runtimeprocess.PrivateKey(configuration.InventoryKey)
	if err != nil {
		fatal("runtime_agent_inventory_key_denied")
	}
	identity, err := runtimeprocess.Certificate(configuration.Certificate, configuration.Key)
	if err != nil || len(identity.Leaf.URIs) != 1 || identity.Leaf.URIs[0].String() != "spiffe://tap/runtime-agent/"+profile.WorkerID {
		fatal("runtime_agent_certificate_denied")
	}
	if public, ok := identity.Leaf.PublicKey.(ed25519.PublicKey); ok && bytes.Equal(public, inventoryKey.Public().(ed25519.PublicKey)) {
		fatal("runtime_agent_key_roles_denied")
	}
	transport, err := runtimeprocess.AgentTransport(*path, configuration)
	if err != nil {
		fatal("runtime_agent_transport_denied")
	}
	live, err := runtimerpc.NewLive(transport)
	if err != nil {
		fatal("runtime_agent_transport_denied")
	}
	defer live.Close()
	authority := &runtimerpc.Authority{Client: live}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	ledger, err := runtimeagent.OpenLedger(ctx, runtimehost.Root+"/agent/ledger.sqlite", profile.WorkerID, profile.Incarnation)
	if err != nil {
		fatal("runtime_agent_ledger_denied")
	}
	defer ledger.Close()
	anchor, err := runtimeisolation.ReadAgentEnrollment()
	if err != nil || !anchor.Matches(ledger) {
		fatal("runtime_agent_reenrollment_required")
	}
	if ledger.PinRuntimeProfile(ctx, profile.Hash()) != nil || ledger.ConfigureBackends(ctx, runtimeagent.BackendCapacity{Apps: len(profile.Apps), Memory: profile.MemoryBytes, Disk: profile.DiskBytes}) != nil {
		fatal("runtime_agent_capacity_denied")
	}
	for _, app := range profile.Apps {
		enrollment, err := runtimeisolation.ReadEnrollment(app.ID)
		if err != nil || enrollment.WorkerID != profile.WorkerID || enrollment.Incarnation != profile.Incarnation || enrollment.Backend.Reservation() != app.Reservation() || (runtimeengine.LinuxObserver{}).VerifyBackend(ctx, enrollment.Backend) != nil || ledger.ReserveBackend(ctx, app.Reservation()) != nil || ledger.BindBackend(ctx, enrollment.Backend) != nil {
			fatal("runtime_agent_backend_denied")
		}
	}
	if ledger.RecoverPendingResults(ctx) != nil {
		fatal("runtime_agent_recovery_uncertain")
	}
	factory, err := runtimeengine.NewFactory(ledger, runtimeengine.LinuxObserver{}, profile.WorkerID, profile.Incarnation, "tap-runtime", func(binding runtimeagent.BackendBinding, client *runtimeengine.Client) (runtimeengine.Enforcement, runtimeengine.ImageDelivery, error) {
		for _, app := range profile.Apps {
			if app.ID != binding.AppID {
				continue
			}
			enforcement, err := runtimeengine.NewMeasuredEnforcement(client, ledger, binding, runtimeengine.EnforcementConfig{WorkerID: profile.WorkerID, Incarnation: profile.Incarnation, TemplateHash: profile.TemplateHash, ProfileHash: profile.Hash(), CPUMillis: app.CPUMillis, PIDs: app.PIDs, Canary: *profile.Canary})
			if err != nil {
				return nil, nil, err
			}
			return enforcement, &runtimeengine.Delivery{Client: client, Transport: live, Metadata: authority, Scratch: app.MountDirectory() + "/spool"}, nil
		}
		return nil, nil, runtimeagent.ErrUnsupported
	})
	if err != nil {
		fatal("runtime_agent_engine_denied")
	}
	agent, err := runtimeagent.New(runtimeagent.Config{WorkerID: profile.WorkerID, Incarnation: profile.Incarnation, Keys: keys, InventoryKey: inventoryKey, Resolver: authority, Approval: authority, Lease: authority, Engine: factory, Ledger: ledger})
	if err != nil {
		fatal("runtime_agent_configuration_denied")
	}
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	defer signal.Stop(reload)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-reload:
				next, err := runtimeprocess.LoadAgent(*path)
				if err != nil || !reflect.DeepEqual(next.CommandKeys, configuration.CommandKeys) || next.InventoryKey != configuration.InventoryKey {
					continue
				}
				client, err := runtimeprocess.AgentTransport(*path, next)
				if err != nil {
					continue
				}
				live.Replace(client)
			}
		}
	}()
	supervisor := &runtimeengine.Supervisor{Ledger: ledger, Factory: factory, Authority: authority, WorkerID: profile.WorkerID, Incarnation: profile.Incarnation}
	if err = agent.Serve(ctx, live, supervisor); err != nil && ctx.Err() == nil {
		fatal("runtime_agent_service_uncertain")
	}
}
