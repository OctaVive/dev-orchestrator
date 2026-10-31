package main

import (
	"context"
	"dev-orchestrator/internal/runtimehost"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	syscall.Umask(0022)
	p, err := runtimehost.Load()
	if err != nil {
		os.Stderr.WriteString("runtime_host_configuration_denied\n")
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	deadline, stop := context.WithTimeout(ctx, 5*time.Minute)
	defer stop()
	if err := p.Provision(deadline); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}
