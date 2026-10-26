package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dev-orchestrator/internal/provisioner"
)

func TestPrototypeCannotEnableExecutionOrExposePublicBind(t *testing.T) {
	if err := run(context.Background(), nil); err == nil {
		t.Fatal("missing host configuration accepted")
	}
	base := func() []string {
		return []string{"-ledger", filepath.Join(t.TempDir(), "host.db"), "-template-digest", "sha256:" + strings.Repeat("a", 64)}
	}
	if err := run(context.Background(), append(base(), "-mode", "guard")); !errors.Is(err, provisioner.ErrUnavailable) {
		t.Fatal("unconfigured watchdog advertised hard kill capability", err)
	}
	if err := run(context.Background(), append(base(), "-listen", "0.0.0.0:9444")); err == nil {
		t.Fatal("prototype exposed to public networks")
	}
	if err := run(context.Background(), append(base(), "-backend", "simulator")); err == nil {
		t.Fatal("simulator enabled in production binary")
	}
}

func TestPrivateServiceFileIsBoundedAndSanitized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, []byte("test-only-not-a-private-key"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readFile(path, true); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("s", (1<<20)+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readFile(path, true); err == nil || strings.Contains(err.Error(), "ssss") {
		t.Fatal("oversized private file accepted/leaked")
	}
}

func TestLinuxBackendRequiresExplicitValidHostConfiguration(t *testing.T) {
	for _, args := range [][]string{
		{"-backend", "linux-kvm", "-mode", "guard", "-ledger", filepath.Join(t.TempDir(), "leases.db")},
		{"-linux-config", filepath.Join(t.TempDir(), "missing.json")},
		{"-mode", "host-run", "-host-job", "../../foreign"},
		{"-mode", "host-expire", "-host-job", "../../foreign"},
		{"-backend", "tcg"},
		{"-backend", "docker"},
	} {
		if err := run(context.Background(), args); err == nil {
			t.Fatalf("unsafe host configuration accepted: %v", args)
		}
	}
}
