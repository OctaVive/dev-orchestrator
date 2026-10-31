// hostprobe validates the actual provisioner/measurement services only inside a
// fresh disposable runtime guest. It is not the M09 acceptance driver.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/runtimeagent"
	"dev-orchestrator/internal/runtimeengine"
	"dev-orchestrator/internal/runtimehost"
	"dev-orchestrator/internal/runtimeisolation"
	"dev-orchestrator/internal/runtimeobservation"
)

func must(err error) {
	if err != nil {
		fmt.Println("M09-HOST-ERROR", err)
		os.Exit(1)
	}
}
func main() {
	if os.Geteuid() != 1000 {
		must(runtimeagent.ErrDenied)
	}
	if _, err := os.Stat("/etc/m09-disposable-guest"); err != nil {
		must(runtimeagent.ErrDenied)
	}
	profile, err := runtimehost.Load()
	must(err)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	ledger, err := runtimeagent.OpenLedger(ctx, runtimehost.Root+"/agent/ledger.sqlite", profile.WorkerID, profile.Incarnation)
	must(err)
	defer ledger.Close()
	anchor, err := runtimeisolation.ReadAgentEnrollment()
	must(err)
	if !anchor.Matches(ledger) {
		must(runtimeagent.ErrDenied)
	}
	must(ledger.PinRuntimeProfile(ctx, profile.Hash()))
	must(ledger.ConfigureBackends(ctx, runtimeagent.BackendCapacity{Apps: len(profile.Apps), Memory: profile.MemoryBytes, Disk: profile.DiskBytes}))
	for _, app := range profile.Apps {
		enrollment, err := runtimeisolation.ReadEnrollment(app.ID)
		must(err)
		fmt.Println("M09-HOST-CHECK observer", app.ID)
		must((runtimeengine.LinuxObserver{}).VerifyBackend(ctx, enrollment.Backend))
		must(ledger.ReserveBackend(ctx, app.Reservation()))
		must(ledger.BindBackend(ctx, enrollment.Backend))
		client, err := runtimeengine.NewMeasurementClient(enrollment.Backend, profile.Hash())
		must(err)
		fmt.Println("M09-HOST-CHECK backend", app.ID)
		report, err := client.Report(ctx, runtimeobservation.Request{Operation: "backend", AppID: app.ID})
		must(err)
		raw, err := json.Marshal(report)
		must(err)
		fmt.Println("M09-HOST-BACKEND", string(raw))
		ids, err := os.ReadFile("/run/m09-host-" + app.ID + ".id")
		must(err)
		request := runtimeobservation.Request{Operation: "container", AppID: app.ID, ContainerID: strings.TrimSpace(string(ids)), OwnerID: profile.WorkerID, DeploymentID: profile.WorkerID, Generation: 1, SpecHash: contracts.Digest([]byte("host-fixture")), Service: "web", UID: 1000, GID: 1000, Resources: contracts.Resources{CPUMillis: 100, MemoryBytes: 64 << 20, PIDs: 16, TmpBytes: 8 << 20, WritableBytes: 8 << 20, LogBytes: 2 << 20}}
		report, err = client.Report(ctx, request)
		must(err)
		if report.Process == nil {
			must(runtimeagent.ErrDenied)
		}
		raw, err = json.Marshal(report)
		must(err)
		fmt.Println("M09-HOST-CONTAINER", string(raw))
		request.Operation = "health"
		request.Port = 8080
		request.Path = "/"
		report, err = client.Report(ctx, request)
		must(err)
		if report.Health == nil || report.Health.Status != 200 {
			must(runtimeagent.ErrDenied)
		}
		fmt.Println("M09-HOST-PRIVATE-HEALTH", app.ID, report.Health.Status)
		request.Operation = "relay-start"
		report, err = client.Report(ctx, request)
		must(err)
		if report.Health == nil || report.Health.Status != 200 {
			must(runtimeagent.ErrDenied)
		}
		request.Operation = "relay-fetch"
		report, err = client.Report(ctx, request)
		must(err)
		if report.Health == nil || report.Health.Status != 200 {
			must(runtimeagent.ErrDenied)
		}
		request.Operation = "relay-stop"
		request.Port = 0
		request.Path = ""
		request.DeploymentID = ""
		request.Generation = 0
		request.SpecHash = ""
		request.Service = ""
		request.UID = 0
		request.GID = 0
		request.Resources = contracts.Resources{}
		report, err = client.Report(ctx, request)
		must(err)
		if report.Health == nil || report.Health.Status != 204 {
			must(runtimeagent.ErrDenied)
		}
		fmt.Println("M09-HOST-PRIVATE-RELAY-REMOVED", app.ID)

		client.Close()
	}
	fmt.Println("M09-HOST-COMPLETE scope=provisioning-and-kernel-only-not-R01")
}
