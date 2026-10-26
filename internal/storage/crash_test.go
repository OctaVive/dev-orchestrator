package storage

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"dev-orchestrator/internal/domain"
)

// Fixed test-binary subprocess only: no user/repository shell command execution.
// os.Exit bypasses Close/deferred rollback to exercise real WAL crash recovery.
func TestCrashRecoveryAllOrNothing(t *testing.T) {
	for _, stage := range []string{"before-commit", "after-commit"} {
		t.Run(stage, func(t *testing.T) {
			s, path := testStore(t)
			seed(t, s)
			submit(t, s)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCrashHelper$")
			cmd.Env = append(os.Environ(), "ORCH_STORAGE_CRASH_TEST="+stage, "ORCH_STORAGE_CRASH_PATH="+path)
			output, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 23 {
				t.Fatalf("crash helper failed: %v %s", err, output)
			}
			s, err = Open(context.Background(), path)
			if err != nil {
				t.Fatal("recovery failed", err)
			}
			defer s.Close()
			d, err := s.Deployment(context.Background(), deploymentID)
			if err != nil {
				t.Fatal(err)
			}
			wantState, wantVersion := domain.Submitted, int64(1)
			if stage == "after-commit" {
				wantState, wantVersion = domain.Validating, 2
			}
			if d.State != wantState || d.Version != wantVersion {
				t.Fatalf("partial state after crash: %+v", d)
			}
			assertCounts(t, s, 1, wantVersion)
			if err := s.CheckIntegrity(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCrashHelper(t *testing.T) {
	stage := os.Getenv("ORCH_STORAGE_CRASH_TEST")
	if stage == "" {
		return
	}
	s, err := Open(context.Background(), os.Getenv("ORCH_STORAGE_CRASH_PATH"))
	if err != nil {
		t.Fatal(err)
	}
	switch stage {
	case "before-commit":
		err = s.write(context.Background(), func(conn *sql.Conn) error {
			if _, err := s.advanceTx(context.Background(), conn, change()); err != nil {
				return err
			}
			os.Exit(23)
			return nil
		})
	case "after-commit":
		_, err = s.Advance(context.Background(), change())
		if err == nil {
			os.Exit(23)
		}
	default:
		t.Fatal("unexpected crash test stage")
	}
	t.Fatal("crash helper did not reach exit", err)
}
