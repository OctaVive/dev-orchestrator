// runtime-controller is the dedicated runtime mTLS listener using management's
// durable state adapters. It never approves deployments or parses OCI archives.
// Run as the sole metadata controller, or embed the handler in that controller;
// this command does not authorize a shared multi-controller database deployment.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dev-orchestrator/internal/artifacts"
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/runtimeauthority"
	"dev-orchestrator/internal/runtimeprocess"
	"dev-orchestrator/internal/storage"
)

type configuration struct {
	Database    string            `json:"database"`
	Artifacts   string            `json:"artifacts"`
	Listen      string            `json:"listen"`
	CA          string            `json:"ca"`
	Certificate string            `json:"certificate"`
	Key         string            `json:"key"`
	CommandKeys map[string]string `json:"command_keys"`
}

func fatal(code string) { os.Stderr.WriteString(code + "\n"); os.Exit(1) }
func main() {
	syscall.Umask(0077)
	path := flag.String("config", "", "private operator configuration")
	flag.Parse()
	if flag.NArg() != 0 {
		fatal("runtime_controller_configuration_denied")
	}
	raw, err := runtimeprocess.Read(*path, true, 64<<10)
	if err != nil {
		fatal("runtime_controller_configuration_denied")
	}
	c, err := contracts.DecodeConfiguration[configuration](bytes.NewReader(raw))
	if err != nil || c.Listen == "" {
		fatal("runtime_controller_configuration_denied")
	}
	identity, err := runtimeprocess.Certificate(c.Certificate, c.Key)
	if err != nil || len(identity.Leaf.URIs) != 1 || identity.Leaf.URIs[0].String() != "spiffe://tap/runtime-controller" {
		fatal("runtime_controller_certificate_denied")
	}
	roots, err := runtimeprocess.Roots(c.CA)
	if err != nil {
		fatal("runtime_controller_trust_denied")
	}
	keys, err := runtimeprocess.PublicKeys(c.CommandKeys)
	if err != nil {
		fatal("runtime_controller_keys_denied")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	state, err := storage.Open(ctx, c.Database)
	if err != nil {
		fatal("runtime_controller_metadata_denied")
	}
	defer state.Close()
	downloads, err := artifacts.NewRuntimeDownloads(c.Artifacts, state)
	if err != nil {
		fatal("runtime_controller_artifacts_denied")
	}
	defer downloads.Close()
	handler, err := runtimeauthority.NewServer(state, keys, downloads)
	if err != nil {
		fatal("runtime_controller_configuration_denied")
	}
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		fatal("runtime_controller_listener_denied")
	}
	defer listener.Close()
	server := &http.Server{Handler: handler, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{identity}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
	failures := make(chan error, 1)
	go func() { failures <- server.ServeTLS(listener, "", "") }()
	select {
	case <-ctx.Done():
	case <-failures:
	}
	stop, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	server.Shutdown(stop)
}
