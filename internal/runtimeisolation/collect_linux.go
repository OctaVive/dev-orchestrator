package runtimeisolation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/runtimeagent"
	"golang.org/x/sys/unix"
)

// CollectBackend is a root provisioner measurement, not admission or capacity
// allocation. The supplied reservation must already be durably committed before
// provisioning. No workload/container may run until its enrollment is installed.
func CollectBackend(ctx context.Context, worker, incarnation string, r runtimeagent.BackendReservation) (Enrollment, error) {
	fail := func() (Enrollment, error) { return Enrollment{}, runtimeagent.ErrUnsupported }
	if os.Geteuid() != 0 || !r.Valid() || !contracts.ValidJobID(worker) || !contracts.ValidJobID(incarnation) {
		return fail()
	}
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", r.Socket)
	if err != nil {
		return fail()
	}
	u, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return fail()
	}
	raw, err := u.SyscallConn()
	if err != nil {
		conn.Close()
		return fail()
	}
	var cred *unix.Ucred
	var peerErr error
	err = raw.Control(func(fd uintptr) { cred, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	conn.Close()
	if err != nil || peerErr != nil || cred == nil || cred.Uid != 1000 || cred.Pid <= 1 {
		return fail()
	}
	proc := fmt.Sprintf("/proc/%d", cred.Pid)
	before, err := ReadSmall(proc+"/stat", 4096)
	if err != nil {
		return fail()
	}
	ticks, err := StartTicks(before)
	if err != nil {
		return fail()
	}
	tr := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", r.Socket)
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return runtimeagent.ErrDenied }}
	request, err := http.NewRequestWithContext(ctx, "GET", "http://engine/v1.47/info", nil)
	if err != nil {
		return fail()
	}
	response, err := client.Do(request)
	if err != nil {
		return fail()
	}
	defer response.Body.Close()
	var info struct{ ID, DockerRootDir string }
	bytes, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(bytes) > 1<<20 || response.StatusCode != 200 || json.Unmarshal(bytes, &info) != nil || info.DockerRootDir != r.DataRoot {
		return fail()
	}
	boot, err := scalar("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return fail()
	}
	initial, err := os.Readlink("/proc/1/ns/user")
	if err != nil {
		return fail()
	}
	ns, err := os.Readlink(proc + "/ns/user")
	if err != nil || ns == initial {
		return fail()
	}
	uid, err := ReadSmall(proc+"/uid_map", 4096)
	if err != nil {
		return fail()
	}
	if _, err = ParseMappings(uid); err != nil {
		return fail()
	}
	gid, err := ReadSmall(proc+"/gid_map", 4096)
	if err != nil {
		return fail()
	}
	if _, err = ParseMappings(gid); err != nil {
		return fail()
	}
	after, err := ReadSmall(proc+"/stat", 4096)
	if err != nil {
		return fail()
	}
	again, err := StartTicks(after)
	if err != nil || ticks != again {
		return fail()
	}
	e := Enrollment{Version: 1, WorkerID: worker, Incarnation: incarnation, Backend: runtimeagent.BackendBinding{AppID: r.AppID, Socket: r.Socket, DataRoot: r.DataRoot, DaemonID: info.ID, DaemonPID: int(cred.Pid), DaemonStartTicks: ticks, BootID: strings.TrimSpace(boot), UserNamespace: ns, InitialUserNamespace: initial, UIDMapHash: contracts.Digest(uid), GIDMapHash: contracts.Digest(gid), DaemonMemory: r.DaemonMemory, WorkloadMemory: r.WorkloadMemory, ImageDisk: r.ImageDisk, WorkloadDisk: r.WorkloadDisk}}
	if !e.Valid() {
		return fail()
	}
	return e, nil
}
