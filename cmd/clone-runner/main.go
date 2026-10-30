//go:build linux

// clone-runner is a fixed guest entry point, not a host command execution API.
package main

import (
	"context"
	"encoding/json"
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
	out, e := os.OpenFile("/dev/ttyS1", os.O_WRONLY, 0)
	if e != nil {
		os.Exit(23)
	}
	defer out.Close()
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
}
