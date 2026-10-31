// profileprobe is a fixed disposable-VM diagnostic, not runtime acceptance.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"strconv"
	"strings"
	"time"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/runtimeagent"
	"dev-orchestrator/internal/runtimeengine"
	"dev-orchestrator/internal/runtimeisolation"
)

const worker = "11111111-1111-4111-8111-111111111111"
const other = "22222222-2222-4222-8222-222222222222"

func must(err error) {
	if err != nil {
		fmt.Println("M09-PROFILE-ERROR", err)
		os.Exit(1)
	}
}
func main() {
	if os.Geteuid() != 0 || len(os.Args) != 2 {
		must(runtimeagent.ErrDenied)
	}
	if _, err := os.Stat("/etc/m09-disposable-guest"); err != nil {
		must(runtimeagent.ErrDenied)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for n, app := range []string{"a", "b"} {
		appID := []string{worker, other}[n]
		if os.Args[1] == "enroll" {
			r := runtimeagent.BackendReservation{AppID: appID, Socket: "/run/user/1000/app-" + app + ".sock", DataRoot: "/home/runtime/app-" + app + "-data", DaemonMemory: 64 << 20, WorkloadMemory: 128 << 20, ImageDisk: 128 << 20, WorkloadDisk: 128 << 20}
			e, err := runtimeisolation.CollectBackend(ctx, worker, worker, r)
			must(err)
			must(os.MkdirAll(runtimeisolation.EnrollmentRoot, 0755))
			bytes, err := runtimeisolation.EncodeEnrollment(e)
			must(err)
			must(os.WriteFile(runtimeisolation.EnrollmentRoot+"/"+appID+".json", bytes, 0644))
			fmt.Println("M09-PROFILE-ENROLLED", appID, e.Backend.UserNamespace)
		} else if os.Args[1] == "verify" {
			e, err := runtimeisolation.ReadEnrollment(appID)
			must(err)
			bytes, err := os.ReadFile("/run/m09-profile-" + app + ".id")
			must(err)
			id := strings.TrimSpace(string(bytes))
			client, err := runtimeengine.NewClient(e.Backend.Socket)
			must(err)
			got, err := client.InspectContainer(ctx, id)
			must(err)
			if got.Config.Labels["tap.app"] != appID || got.Config.Labels["tap.owner"] != worker || !got.State.Running {
				must(runtimeagent.ErrDenied)
			}
			proc := "/proc/" + strconv.Itoa(got.State.Pid)
			mountBytes, readErr := os.ReadFile(proc + "/mountinfo")
			must(readErr)
			for _, line := range strings.Split(string(mountBytes), "\n") {
				f := strings.Fields(line)
				if len(f) < 7 || (f[4] != "/" && f[4] != "/tmp" && f[4] != "/run") {
					continue
				}
				tail := strings.SplitN(line, " - ", 2)
				kind := "unknown"
				if len(tail) == 2 {
					kind = strings.Fields(tail[1])[0]
				}
				var st unix.Statfs_t
				statErr := unix.Statfs(proc+"/root"+f[4], &st)
				fmt.Printf("M09-PROFILE-FILESYSTEM mount=%s flags=%s type=%s blocks=%d bsize=%d stat_ok=%t\n", f[4], f[5], kind, st.Blocks, st.Bsize, statErr == nil)
			}
			observation, err := runtimeisolation.VerifyProcess(e, got.State.Pid, runtimeisolation.ProcessLimits{UID: 1000, GID: 1000, Resources: contracts.Resources{CPUMillis: 100, MemoryBytes: 64 << 20, PIDs: 16, TmpBytes: 8 << 20, WritableBytes: 8 << 20, LogBytes: 2 << 20}})
			must(err)
			bytes, err = json.Marshal(observation)
			must(err)
			fmt.Println("M09-PROFILE-MEASURED", appID, string(bytes))
		} else {
			must(runtimeagent.ErrDenied)
		}
	}
	fmt.Println("M09-PROFILE-COMPLETE", os.Args[1])
}
