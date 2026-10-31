// backendprobe is a disposable-VM development diagnostic, not an agent service
// or acceptance driver. Its paths, identities and budgets are fixed fixtures.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/runtimeagent"
	"dev-orchestrator/internal/runtimeengine"
	"golang.org/x/sys/unix"
)

const worker = "11111111-1111-4111-8111-111111111111"
const other = "22222222-2222-4222-8222-222222222222"

func must(err error) {
	if err != nil {
		fmt.Println("M09-BACKEND-ERROR", err)
		os.Exit(1)
	}
}
func read(path string) []byte { b, err := os.ReadFile(path); must(err); return b }
func link(path string) string { b, err := os.Readlink(path); must(err); return b }
func main() {
	if os.Geteuid() != 0 {
		must(runtimeagent.ErrDenied)
	}
	if _, err := os.Stat("/etc/m09-disposable-guest"); err != nil {
		must(runtimeagent.ErrDenied)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	boot := strings.TrimSpace(string(read("/proc/sys/kernel/random/boot_id")))
	initial := link("/proc/1/ns/user")
	var bindings []runtimeagent.BackendBinding
	for n, app := range []string{"a", "b"} {
		socket := "/run/user/1000/app-" + app + ".sock"
		data := "/home/runtime/app-" + app + "-data"
		must(os.Chmod(socket, 0600))
		must(os.Chmod(data, 0700))
		conn, err := net.Dial("unix", socket)
		must(err)
		raw, err := conn.(*net.UnixConn).SyscallConn()
		must(err)
		var cred *unix.Ucred
		var peerErr error
		must(raw.Control(func(fd uintptr) { cred, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }))
		must(peerErr)
		must(conn.Close())
		if cred == nil || cred.Uid != 1000 {
			must(runtimeagent.ErrDenied)
		}
		proc := fmt.Sprintf("/proc/%d", cred.Pid)
		stat := string(read(proc + "/stat"))
		tail := strings.Fields(stat[strings.LastIndexByte(stat, ')')+1:])
		if len(tail) < 20 {
			must(runtimeagent.ErrDenied)
		}
		ticks, err := strconv.ParseUint(tail[19], 10, 64)
		must(err)
		transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socket)
		}}
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		res, err := client.Get("http://engine/v1.47/info")
		must(err)
		var info struct{ ID string }
		must(json.NewDecoder(res.Body).Decode(&info))
		must(res.Body.Close())
		transport.CloseIdleConnections()
		b := runtimeagent.BackendBinding{AppID: []string{worker, other}[n], Socket: socket, DataRoot: data, DaemonID: info.ID, DaemonPID: int(cred.Pid), DaemonStartTicks: ticks, BootID: boot, UserNamespace: link(proc + "/ns/user"), InitialUserNamespace: initial, UIDMapHash: contracts.Digest(read(proc + "/uid_map")), GIDMapHash: contracts.Digest(read(proc + "/gid_map")), DaemonMemory: 64 << 20, WorkloadMemory: 64 << 20, ImageDisk: 128 << 20, WorkloadDisk: 64 << 20}
		if !b.Valid() {
			must(runtimeagent.ErrDenied)
		}
		bindings = append(bindings, b)
	}
	if bindings[0].UserNamespace == bindings[1].UserNamespace {
		must(runtimeagent.ErrDenied)
	}
	state := "/home/runtime/m09-backend-ledger"
	must(os.Mkdir(state, 0700))
	must(os.Chown(state, 1000, 1000))
	must(unix.Setgroups(nil))
	must(unix.Setgid(1000))
	must(unix.Setuid(1000))
	observer := runtimeengine.LinuxObserver{}
	ledger, err := runtimeagent.OpenLedger(ctx, state+"/ledger.sqlite", worker, worker)
	must(err)
	must(ledger.ConfigureBackends(ctx, runtimeagent.BackendCapacity{Apps: 2, Memory: 256 << 20, Disk: 384 << 20}))
	for _, b := range bindings {
		must(observer.VerifyBackend(ctx, b))
		must(ledger.ReserveBackend(ctx, b.Reservation()))
		must(ledger.BindBackend(ctx, b))
		fmt.Printf("M09-BACKEND-VERIFIED app=%s namespace=%s binding=%s\n", b.AppID, b.UserNamespace, b.Hash())
	}
	must(ledger.Close())
	ledger, err = runtimeagent.OpenLedger(ctx, state+"/ledger.sqlite", worker, worker)
	must(err)
	for _, b := range bindings {
		got, err := ledger.Backend(ctx, b.AppID)
		must(err)
		if got != b {
			must(runtimeagent.ErrDenied)
		}
		for _, field := range []string{"start", "mapping", "namespace", "boot"} {
			bad := b
			switch field {
			case "start":
				bad.DaemonStartTicks++
			case "mapping":
				bad.UIDMapHash = contracts.Digest([]byte("bad"))
			case "namespace":
				bad.UserNamespace = bad.InitialUserNamespace
			case "boot":
				bad.BootID = other
			}
			if observer.VerifyBackend(ctx, bad) == nil {
				must(runtimeagent.ErrDenied)
			}
			fmt.Printf("M09-BACKEND-DENIED app=%s field=%s\n", b.AppID, field)
		}
	}
	must(ledger.Close())
	fmt.Println("M09-BACKEND-OBSERVATION-COMPLETE scope=identity-only-not-R01")
}
