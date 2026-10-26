package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dev-orchestrator/internal/storage"
)

func TestOperatorTokenFileAndLoopbackConfig(t *testing.T) {
	for _, address := range []string{"127.0.0.1:9443", "[::1]:9443"} {
		if !loopbackAddress(address) {
			t.Fatal("loopback address rejected")
		}
	}
	for _, address := range []string{":9443", "0.0.0.0:9443", "203.0.113.1:9443", "localhost:9443", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:99999", "127.0.0.1:http"} {
		if loopbackAddress(address) {
			t.Fatal("nonliteral/nonloopback setup bind accepted")
		}
	}
	path := filepath.Join(t.TempDir(), "setup-token")
	token := strings.Repeat("a", 64)
	if err := os.WriteFile(path, []byte(token+"\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := readSetupToken(path); err != nil || got != token {
		t.Fatal("valid private token file rejected", err)
	}
	for _, content := range []string{"short", strings.Repeat("A", 64), strings.Repeat("a", 129), " " + token} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readSetupToken(path); err == nil || strings.Contains(err.Error(), token) {
			t.Fatal("bad token file accepted or error leaked token")
		}
	}
	if err := run(context.Background(), nil); err == nil {
		t.Fatal("server started without TLS/config")
	}
	if err := run(context.Background(), []string{"-tls-cert", "missing", "-tls-key", "missing", "-public-origin", "https://portal.example.test"}); err == nil {
		t.Fatal("server started without usable TLS files")
	}
}

func TestRunTLSStartupAndGracefulShutdown(t *testing.T) {
	dir := t.TempDir()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-only"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	for path, data := range map[string][]byte{certPath: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPath: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	dbPath := filepath.Join(dir, "metadata.db")
	store, err := storage.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	// Test-only preexisting identity: this test does not log in with this hash.
	_, err = store.BootstrapAdmin(context.Background(), "admin", "$argon2id$test-only-fixture", "11111111-1111-4111-8111-111111111111", time.Now())
	store.Close()
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	reservation.Close()
	origin := "https://" + address
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"-db", dbPath, "-tls-cert", certPath, "-tls-key", keyPath, "-public-origin", origin, "-listen", address})
	}()
	certificate, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	ready := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			t.Fatal("API stopped before ready", err)
		default:
		}
		response, err := client.Get(origin + "/api/v1/auth/session")
		if err == nil {
			response.Body.Close()
			if response.StatusCode != 401 || response.TLS.Version != tls.VersionTLS13 {
				t.Fatal("CLI failed closed-auth/TLS checks", response.StatusCode)
			}
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("TLS API did not become ready")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(fmt.Errorf("graceful shutdown: %w", err))
		}
	case <-time.After(6 * time.Second):
		t.Fatal("API did not shut down")
	}
}
