// egress-broker runs one immutable host-assigned lease. Removing its service
// revokes every session. It has no provisioner or management API.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dev-orchestrator/internal/egress"
)

func run(args []string) error {
	flags := flag.NewFlagSet("egress-broker", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	policyFile := flags.String("policy", "", "operator policy")
	certFile := flags.String("ca-cert", "", "build-only CA certificate")
	keyFile := flags.String("ca-key", "", "build-only CA private key")
	listen := flags.String("listen", "", "dedicated broker IP:port")
	guest := flags.String("guest", "", "host-assigned guest IPv4")
	expires := flags.String("expires", "", "absolute RFC3339 lease deadline")
	resolver := flags.String("resolver", "", "dedicated resolver IP:port")
	listenerFD := flags.Int("listener-fd", 0, "host-opened namespace listener (internal)")
	readyFD := flags.Int("ready-fd", 0, "host readiness pipe (internal)")
	policyHash := flags.String("policy-hash", "", "expected immutable policy identity")
	caHash := flags.String("ca-hash", "", "expected build CA certificate SHA-256")
	inspect := flags.Bool("inspect", false, "print canonical policy and public CA hashes without starting a broker")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return egress.ErrDenied
	}
	if *inspect {
		return inspectFiles(*policyFile, *certFile)
	}
	ip, err := netip.ParseAddr(*guest)
	if err != nil || !ip.Is4() {
		return egress.ErrDenied
	}
	var addr netip.AddrPort
	if *listenerFD == 0 {
		addr, err = netip.ParseAddrPort(*listen)
		if err != nil || !addr.Addr().Is4() || addr.Addr().IsUnspecified() {
			return egress.ErrDenied
		}
	} else if *listenerFD != 3 || *listen != "" || *readyFD != 7 || *policyHash == "" || *caHash == "" {
		return egress.ErrDenied
	}
	dns, err := netip.ParseAddrPort(*resolver)
	if err != nil || dns.Port() != 53 {
		return egress.ErrDenied
	}
	end, err := time.Parse(time.RFC3339, *expires)
	if err != nil || !time.Now().Before(end) || time.Until(end) > time.Hour {
		return egress.ErrDenied
	}
	f, err := inputFile(*policyFile, *listenerFD != 0, 4)
	if err != nil {
		return egress.ErrDenied
	}
	defer f.Close()
	p, err := egress.DecodePolicy(f)
	if err != nil {
		return err
	}
	if *policyHash != "" && p.Hash() != *policyHash {
		return egress.ErrDenied
	}
	cf, err := inputFile(*certFile, *listenerFD != 0, 5)
	if err != nil {
		return egress.ErrDenied
	}
	defer cf.Close()
	kf, err := inputFile(*keyFile, *listenerFD != 0, 6)
	if err != nil {
		return egress.ErrDenied
	}
	defer kf.Close()
	certData, err := io.ReadAll(io.LimitReader(cf, 65537))
	if err != nil || len(certData) > 65536 {
		return egress.ErrDenied
	}
	keyData, err := io.ReadAll(io.LimitReader(kf, 65537))
	if err != nil || len(keyData) > 65536 {
		return egress.ErrDenied
	}
	defer clear(keyData)
	ca, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return egress.ErrDenied
	}
	hash := sha256.Sum256(ca.Certificate[0])
	if *caHash != "" && hex.EncodeToString(hash[:]) != *caHash {
		return egress.ErrDenied
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	ctx, cancel := context.WithDeadline(ctx, end)
	defer cancel()
	r := &net.Resolver{PreferGo: true, StrictErrors: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", dns.String())
	}}
	b, err := egress.NewObserved(p, ca, r, func(peer netip.Addr) (egress.Lease, bool) {
		return egress.Lease{Context: ctx, Expires: end, PolicyHash: p.Hash()}, peer == ip
	}, func(reason, hash string) { fmt.Fprintf(os.Stderr, "egress decision=%s policy=%s\n", reason, hash) })
	if err != nil {
		return err
	}
	var listener net.Listener
	if *listenerFD != 0 {
		file := os.NewFile(uintptr(*listenerFD), "namespace-listener")
		listener, err = net.FileListener(file)
		file.Close()
		if err != nil {
			return egress.ErrDenied
		}
		if listener.Addr().String() != "192.0.2.1:8443" {
			listener.Close()
			return egress.ErrDenied
		}
	} else {
		listener, err = net.Listen("tcp4", addr.String())
		if err != nil {
			return egress.ErrDenied
		}
	}
	defer listener.Close()
	listener = egress.LimitListener(listener, p.MaxConnections*2)
	server := &http.Server{Handler: b, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 32768}
	go func() { <-ctx.Done(); server.Close() }()
	if *readyFD != 0 {
		ready := os.NewFile(uintptr(*readyFD), "ready")
		_, err = ready.Write([]byte{1})
		ready.Close()
		if err != nil {
			return egress.ErrDenied
		}
	}
	err = server.Serve(listener)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func inputFile(path string, inherited bool, fd uintptr) (*os.File, error) {
	if !inherited {
		return os.Open(path)
	}
	if path != fmt.Sprintf("/proc/self/fd/%d", fd) {
		return nil, egress.ErrDenied
	}
	// Read the already-open capability directly. Reopening /proc/self/fd may
	// require the root-only source inode's permissions after dropping UID.
	return os.NewFile(fd, "host-input"), nil
}

func inspectFiles(policyPath, certPath string) error {
	f, e := os.Open(policyPath)
	if e != nil {
		return egress.ErrDenied
	}
	defer f.Close()
	p, e := egress.DecodePolicy(f)
	if e != nil {
		return egress.ErrDenied
	}
	fca, e := os.Open(certPath)
	if e != nil {
		return egress.ErrDenied
	}
	defer fca.Close()
	data, e := io.ReadAll(io.LimitReader(fca, 65537))
	if e != nil || len(data) > 65536 {
		return egress.ErrDenied
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return egress.ErrDenied
	}
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil || !cert.IsCA {
		return egress.ErrDenied
	}
	h := sha256.Sum256(block.Bytes)
	fmt.Printf("policy_hash=%s\nca_sha256=%s\n", p.Hash(), hex.EncodeToString(h[:]))
	return nil
}
func main() {
	if run(os.Args[1:]) != nil {
		fmt.Fprintln(os.Stderr, "egress broker unavailable")
		os.Exit(1)
	}
}
