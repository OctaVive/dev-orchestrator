// The provisioner executable exposes an mTLS contract, NOT VM execution yet.
// UnconfiguredBackend is deliberately hard-coded until Linux host enforcement
// and KVM create/destroy/expiry integration gates have been demonstrated.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"dev-orchestrator/internal/provisioner"
	"dev-orchestrator/internal/provisionerrpc"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("orchestrator-provisioner", flag.ContinueOnError)
	mode := f.String("mode", "serve", "serve contract diagnostics or run independent guard (requires a real backend)")
	ledgerPath := f.String("ledger", "", "dedicated host-private lease DB, NEVER the management DB")
	listen := f.String("listen", "127.0.0.1:9444", "prototype loopback mTLS bind; remote host rollout is not enabled")
	authority := f.String("authority", "localhost:9444", "exact TLS service Host authority")
	controller := f.String("controller-id", "", "approved controller UUID from its URI SAN")
	pin := f.String("controller-cert-sha256", "", "approved controller leaf certificate SHA-256 hex fingerprint")
	caFile := f.String("client-ca", "", "dedicated controller client CA PEM file")
	certFile := f.String("tls-cert", "", "provisioner server certificate PEM")
	keyFile := f.String("tls-key", "", "private provisioner server key PEM")
	templateID := f.String("template-id", "build-linux-v1", "fixed operator-approved template ID")
	templateDigest := f.String("template-digest", "", "pinned sha256 digest; not an image URL/path")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *ledgerPath == "" || (*mode != "serve" && *mode != "guard") {
		return errors.New("invalid provisioner mode or missing private ledger")
	}
	l, err := provisioner.OpenLedger(ctx, *ledgerPath)
	if err != nil {
		return err
	}
	defer l.Close()
	m, err := provisioner.NewManager(l, provisioner.UnconfiguredBackend{}, provisioner.Config{Templates: []provisioner.Template{{ID: *templateID, Digest: *templateDigest}}})
	if err != nil {
		return err
	}
	if *mode == "guard" {
		return m.RunGuard(ctx)
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		return errors.New("prototype provisioner requires a loopback bind")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return errors.New("prototype provisioner requires a literal loopback bind")
	}
	clientCA, err := readFile(*caFile, false)
	if err != nil {
		return err
	}
	tlsConfig, err := provisionerrpc.ServerTLSConfig(clientCA)
	if err != nil {
		return err
	}
	key, err := readFile(*keyFile, true)
	if err != nil {
		return err
	}
	cert, err := readFile(*certFile, false)
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return errors.New("invalid provisioner TLS certificate/key")
	}
	tlsConfig.Certificates = []tls.Certificate{pair}
	h, err := provisionerrpc.NewHandler(m, *authority, *controller, []string{*pin})
	if err != nil {
		return err
	}
	server := &http.Server{Addr: *listen, Handler: h, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 50 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServeTLS("", "") }()
	var result error
	select {
	case <-ctx.Done():
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			result = errors.New("provisioner mTLS listener failed")
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		_ = server.Close()
	}
	return result
}

func readFile(path string, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 || private && runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("invalid service credential file or permissions")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot read service credential file")
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(info, actual) {
		return nil, errors.New("service credential file changed")
	}
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(b) > 1<<20 || len(strings.TrimSpace(string(b))) == 0 {
		return nil, errors.New("invalid service credential file size")
	}
	return b, nil
}
