//go:build linux

// clone-runner is a fixed guest entry point, not a host command execution API.
package main

import (
	"bufio"
	"bytes"
	"context"
	"dev-orchestrator/internal/builder"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"dev-orchestrator/internal/cloner"
	"dev-orchestrator/internal/contracts"
)

func main() {
	// Read exactly one bounded, length-prefixed JSON job from a read-only raw
	// virtio device; sector padding is never interpreted as a second document.
	f, e := os.Open("/dev/vdb")
	if e != nil {
		os.Exit(21)
	}
	defer f.Close()
	job, e := contracts.ReadCloneInput(f, time.Now())
	if e != nil {
		os.Exit(22)
	}
	out, e := os.OpenFile("/dev/ttyS1", os.O_RDWR, 0)
	if e != nil {
		os.Exit(23)
	}
	defer out.Close()
	if job.Build != nil {
		term, e := unix.IoctlGetTermios(int(out.Fd()), unix.TCGETS)
		if e != nil {
			os.Exit(24)
		}
		term.Iflag = 0
		term.Oflag = 0
		term.Lflag = 0
		term.Cc[unix.VMIN] = 1
		term.Cc[unix.VTIME] = 0
		if unix.IoctlSetTermios(int(out.Fd()), unix.TCSETS, term) != nil {
			os.Exit(24)
		}
	}

	emit := func(r contracts.CloneResult) error {
		b, e := json.Marshal(r)
		if e != nil || len(b) > contracts.MaxCloneResultBytes {
			return io.ErrShortBuffer
		}
		_, e = io.WriteString(out, "M06 "+string(b)+"\n")
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	r := cloner.Run(ctx, job, emit)
	if emit(r) != nil {
		os.Exit(2)
	}
	if strings.TrimSpace(r.Outcome) != "success" {
		os.Exit(1)
	}
	if job.Build != nil {
		build(ctx, out, job)
	}
}

func build(ctx context.Context, out *os.File, j contracts.CloneJob) {
	reader := bufio.NewReaderSize(io.LimitReader(out, contracts.MaxBuildJobBytes+514), contracts.MaxBuildJobBytes+514)
	line, e := reader.ReadBytes('\n')
	if e != nil || len(line) > contracts.MaxBuildJobBytes+513 {
		os.Exit(27)
	}
	a, e := contracts.DecodeBuildAuthorization(bytes.NewReader(bytes.TrimSuffix(line, []byte{'\n'})), j, time.Now())
	if e != nil {
		os.Exit(28)
	}
	result := contracts.BuildResult{JobID: j.JobID, PolicyHash: a.Job.PolicyHash, Outcome: "denied"}
	path, e := builder.Run(ctx, a.Job)
	result.Reason = "context"
	if errors.Is(e, builder.ErrPolicy) {
		result.Reason = "policy"
	}
	if errors.Is(e, builder.ErrDaemon) {
		result.Reason = "daemon"
	}
	if errors.Is(e, builder.ErrExecution) {
		result.Reason = "build"
	}
	if errors.Is(e, builder.ErrLimit) {
		result.Reason = "export"
	}

	if e == nil {
		e = builder.Upload(ctx, path, a)
		if e != nil {
			result.Reason = "upload"
		}
	}
	if e == nil {
		result.Outcome = "exported"
		result.Reason = ""
	}
	b, e := json.Marshal(result)
	if e != nil {
		os.Exit(29)
	}
	if _, e = io.WriteString(out, "M07 "+string(b)+"\n"); e != nil {
		os.Exit(30)
	}
}
