package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"dev-orchestrator/internal/runtimeagent"
	"dev-orchestrator/internal/runtimeengine"
	"dev-orchestrator/internal/runtimehost"
	"dev-orchestrator/internal/runtimeisolation"
	"golang.org/x/sys/unix"
)

type operatorAgent struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func startOperatorAgent() *operatorAgent {
	cmd := exec.Command("/usr/local/bin/tap-runtime-agent")
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C"}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000, Groups: []uint32{}}, Pdeathsig: syscall.SIGKILL}
	must(cmd.Start())
	child := &operatorAgent{cmd: cmd, done: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(child.done) }()
	return child
}
func (a *operatorAgent) stop() {
	_ = a.cmd.Process.Kill()
	select {
	case <-a.done:
	case <-time.After(3 * time.Second):
		must(runtimeagent.ErrUncertain)
	}
}
func operatorSnapshot(profile runtimehost.Profile, phase string) {
	for _, app := range profile.Apps {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		enrollment, err := runtimeisolation.ReadEnrollment(app.ID)
		must(err)
		live, err := runtimeisolation.CollectBackend(ctx, profile.WorkerID, profile.Incarnation, app.Reservation())
		must(err)
		if live != enrollment {
			must(runtimeagent.ErrDenied)
		}
		client, err := runtimeengine.NewClient(enrollment.Backend.Socket)
		must(err)
		containers, networks, err := client.ObjectCounts(ctx)
		client.Close()
		cancel()
		must(err)
		raw, err := json.Marshal(struct {
			Phase      string `json:"phase"`
			AppID      string `json:"app_id"`
			Containers int    `json:"containers"`
			Networks   int    `json:"networks"`
		}{phase, app.ID, containers, networks})
		must(err)
		fmt.Println("M09-OPERATOR-STATE", string(raw))
	}
}

// This fixed enum fixture exists only in disposable lab roots. No payload can
// select a PID, executable, shell, filesystem path, socket or Docker API.
func operator() {
	if os.Geteuid() != 0 {
		must(runtimeagent.ErrDenied)
	}
	_, err := os.Stat("/etc/m09-disposable-guest")
	must(err)
	profile, err := runtimehost.Load()
	must(err)
	fd, err := unix.Open("/dev/ttyS2", unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
	must(err)
	terminal, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	must(err)
	terminal.Iflag = unix.IGNPAR
	terminal.Oflag = 0
	terminal.Lflag = 0
	terminal.Cflag = unix.CS8 | unix.CLOCAL | unix.CREAD | unix.B115200
	terminal.Cc[unix.VMIN] = 1
	terminal.Cc[unix.VTIME] = 0
	must(unix.IoctlSetTermios(fd, unix.TCSETS, terminal))
	must(unix.SetNonblock(fd, false))
	control := os.NewFile(uintptr(fd), "private-lab-control")
	defer control.Close()
	agent := startOperatorAgent()
	defer func() { agent.stop() }()
	fmt.Println("M09-OPERATOR-READY")
	scanner := bufio.NewScanner(control)
	scanner.Buffer(make([]byte, 128), 128)
	for scanner.Scan() {
		switch scanner.Text() {
		case "restart-agent":
			operatorSnapshot(profile, "before-restart")
			before := agent.cmd.Process.Pid
			agent.stop()
			agent = startOperatorAgent()
			operatorSnapshot(profile, "after-restart")
			fmt.Printf("M09-OPERATOR-ACK restart-agent old=%d new=%d\n", before, agent.cmd.Process.Pid)
		case "snapshot":
			operatorSnapshot(profile, "final")
			fmt.Println("M09-OPERATOR-ACK snapshot")
		default:
			must(runtimeagent.ErrDenied)
		}
	}
	if scanner.Err() != nil {
		must(runtimeagent.ErrDenied)
	}
}
