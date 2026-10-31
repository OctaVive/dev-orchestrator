package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dev-orchestrator/internal/runtimehost"
	"dev-orchestrator/internal/runtimemeasure"
	"dev-orchestrator/internal/runtimeobservation"
)

func main() {
	p, err := runtimehost.Load()
	if err != nil {
		os.Stderr.WriteString("runtime_measure_configuration_denied\n")
		os.Exit(1)
	}
	handler, err := runtimemeasure.New(p)
	if err != nil {
		os.Stderr.WriteString("runtime_measure_profile_denied\n")
		os.Exit(1)
	}
	defer handler.Close()
	listener, err := net.Listen("unix", runtimeobservation.Socket)
	if err != nil {
		os.Stderr.WriteString("runtime_measure_socket_denied\n")
		os.Exit(1)
	}
	defer listener.Close()
	if os.Chown(runtimeobservation.Socket, 0, 1000) != nil || os.Chmod(runtimeobservation.Socket, 0660) != nil {
		os.Exit(1)
	}
	server := &http.Server{Handler: handler, ConnContext: runtimemeasure.ConnContext, ReadHeaderTimeout: time.Second, ReadTimeout: 4 * time.Second, WriteTimeout: 4 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	failures := make(chan error, 1)
	go func() { failures <- server.Serve(listener) }()
	select {
	case <-ctx.Done():
	case <-failures:
	}
	stop, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	server.Shutdown(stop)
}
