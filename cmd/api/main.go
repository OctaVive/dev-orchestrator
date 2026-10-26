package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
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
	"strconv"
	"strings"
	"syscall"
	"time"

	"dev-orchestrator/internal/auth"
	"dev-orchestrator/internal/httpapi"
	"dev-orchestrator/internal/storage"
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
	f := flag.NewFlagSet("orchestrator-api", flag.ContinueOnError)
	dbPath := f.String("db", "data/metadata.db", "operator-controlled metadata path in an existing private directory")
	listen := f.String("listen", "127.0.0.1:8443", "TLS portal API bind address")
	origin := f.String("public-origin", "", "exact browser HTTPS origin, without trailing slash")
	certPath := f.String("tls-cert", "", "TLS certificate file")
	keyPath := f.String("tls-key", "", "TLS private key file")
	setupFile := f.String("setup-token-file", "", "private operator file containing a 64-character lowercase hex token; never a CLI token value")
	setupExpiry := f.String("setup-expires-at", "", "explicit RFC3339 setup expiry, at most 15 minutes from startup")
	setupListen := f.String("setup-listen", "127.0.0.1:9443", "separate operator-only loopback TLS listener; never expose through public proxy")
	setupOrigin := f.String("setup-origin", "https://localhost:9443", "exact localhost/loopback HTTPS origin for operator setup")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *certPath == "" || *keyPath == "" || *origin == "" {
		return errors.New("TLS certificate/key and exact public origin are required; no positional arguments")
	}
	key, err := readPrivateFile(*keyPath, 1<<20)
	if err != nil {
		return errors.New("could not read private operator TLS key")
	}
	cert, err := os.ReadFile(*certPath)
	if err != nil {
		return errors.New("could not read operator TLS certificate")
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return errors.New("could not load operator TLS certificate/key")
	}
	store, err := storage.Open(ctx, *dbPath)
	if err != nil {
		return fmt.Errorf("metadata startup refused: %w", err)
	}
	defer store.Close()
	needsSetup, err := store.SetupAllowed(ctx)
	if err != nil {
		return errors.New("could not check bootstrap state")
	}
	var setup auth.SetupConfig
	if needsSetup {
		if !loopbackAddress(*setupListen) || *setupListen == *listen {
			return errors.New("setup must use a distinct literal-loopback listener")
		}
		setup.ExpiresAt, err = time.Parse(time.RFC3339, *setupExpiry)
		if err != nil {
			return errors.New("fresh installation requires an explicit setup expiry and private token file")
		}
		token, err := readSetupToken(*setupFile)
		if err != nil {
			return err
		}
		setup.TokenHash = sha256.Sum256([]byte(token))
	}
	service, err := auth.NewService(store, setup)
	if err != nil {
		return errors.New("authentication configuration invalid (check setup expiry)")
	}
	portal, err := httpapi.NewPortalHandler(service, *origin)
	if err != nil {
		return err
	}
	servers := []*http.Server{server(*listen, portal, pair)}
	if needsSetup {
		bootstrap, err := httpapi.NewSetupHandler(service, *setupOrigin)
		if err != nil {
			return err
		}
		servers = append(servers, server(*setupListen, bootstrap, pair))
	}
	done := make(chan error, len(servers))
	for _, s := range servers {
		go func() { done <- s.ListenAndServeTLS("", "") }()
	}
	var result error
	select {
	case <-ctx.Done():
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			result = errors.New("TLS API listener failed")
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		if err := s.Shutdown(shutdown); err != nil {
			_ = s.Close()
		}
	}
	return result
}

func server(address string, handler http.Handler, pair tls.Certificate) *http.Server {
	config := httpapi.TLSConfig()
	config.Certificates = []tls.Certificate{pair}
	return &http.Server{Addr: address, Handler: handler, TLSConfig: config, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 16 << 10}
}

func loopbackAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return false
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return false
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func readSetupToken(path string) (string, error) {
	b, err := readPrivateFile(path, 128)
	if err != nil {
		return "", errors.New("setup token must be a small private regular file, not a symlink")
	}
	token := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	decoded, err := hex.DecodeString(token)
	if err != nil || len(decoded) != 32 || token != strings.ToLower(token) {
		return "", errors.New("setup token file must contain exactly 64 lowercase hex characters")
	}
	return token, nil
}

func readPrivateFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maximum || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("private file must be a bounded regular file with restricted access")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("could not read private file")
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(info, actual) {
		return nil, errors.New("private file changed while opening")
	}
	b, err := io.ReadAll(io.LimitReader(f, maximum+1))
	if err != nil || int64(len(b)) > maximum {
		return nil, errors.New("invalid private file size")
	}
	return b, nil
}
