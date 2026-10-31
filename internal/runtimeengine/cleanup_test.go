package runtimeengine

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"dev-orchestrator/internal/runtimeagent"
)

type cleanupEnforcement struct {
	enforcementFixture
	releases atomic.Int32
}

func (e *cleanupEnforcement) DropIngress(context.Context, runtimeagent.Command) error { return nil }
func (e *cleanupEnforcement) Release(context.Context, runtimeagent.Command) error {
	e.releases.Add(1)
	return nil
}

func TestCleanupRequiresIndependentAbsenceAndPreservesOwnership(t *testing.T) {
	for _, mode := range []string{"lost-response-deleted", "false-success-retained", "already-absent", "inspection-denied", "foreign-labels", "wrong-app"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			cfg := fixtureConfig(t)
			labels := cfg.Labels
			owner := labels["tap.owner"]
			id := strings.Repeat("c", 64)
			c := runtimeagent.Command{Operation: "remove", Target: owner, WorkerID: labels["tap.worker"], Incarnation: labels["tap.incarnation"], AppID: labels["tap.app"], DeploymentID: labels["tap.deployment"], Generation: 1, SpecHash: labels["tap.spec"]}
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "ledger.sqlite")
			ledger, err := runtimeagent.OpenLedger(ctx, path, c.WorkerID, c.Incarnation)
			if err != nil {
				t.Fatal(err)
			}
			defer ledger.Close()
			// Private component fixture only: authorization is tested by Agent tests.
			// Seed the immutable local owner so this test isolates actual cleanup ordering.
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			_, err = db.Exec("INSERT INTO commands(id,nonce,hash,app,deployment,generation,spec_hash,operation,state) VALUES(?,?,?,?,?,?,?,'create','done')", owner, strings.Repeat("a", 64), "fixture", c.AppID, c.DeploymentID, c.Generation, c.SpecHash)
			if err != nil {
				t.Fatal(err)
			}
			db.Close()
			raw, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err = ledger.SaveResource(ctx, owner, runtimeagent.Resource{ID: id, Kind: "container", Service: "web", Expected: raw}); err != nil {
				t.Fatal(err)
			}
			var exists atomic.Bool
			exists.Store(mode != "already-absent")
			var deletes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v"+APIVersion+"/containers/"+id && r.URL.Path != "/v"+APIVersion+"/containers/"+id+"/json" {
					t.Error("unexpected object path", r.URL.Path)
					w.WriteHeader(403)
					return
				}
				if r.Method == "GET" {
					if mode == "inspection-denied" {
						w.WriteHeader(403)
						return
					}
					if !exists.Load() {
						w.WriteHeader(404)
						return
					}
					got := inspected(cfg)
					got.State.Running = false
					if mode == "foreign-labels" {
						got.Config.Labels = map[string]string{"tap.owner": "foreign"}
					}
					json.NewEncoder(w).Encode(got)
					return
				}
				if r.Method != "DELETE" {
					t.Error("unexpected mutation", r.Method)
					w.WriteHeader(403)
					return
				}
				deletes.Add(1)
				if mode == "lost-response-deleted" {
					exists.Store(false)
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					conn.Close()
					return
				}
				if !exists.Load() {
					w.WriteHeader(404)
					return
				}
				w.WriteHeader(204) // Deliberately leave it present in false-success mode.
			}))
			defer server.Close()
			client := &Client{http: server.Client()}
			client.http.Transport = routeTransport{base: server.URL, transport: http.DefaultTransport}
			enforcement := &cleanupEnforcement{}
			engine := &Engine{Client: client, Ledger: ledger, Enforcement: enforcement}
			if mode == "wrong-app" {
				c.AppID = factoryOther
			}
			err = engine.Remove(ctx, c, func() error { return nil })
			remaining, readErr := ledger.Resources(ctx, owner)
			if readErr != nil {
				t.Fatal(readErr)
			}
			success := mode == "lost-response-deleted" || mode == "already-absent"
			if success {
				if err != nil || len(remaining) != 0 || enforcement.releases.Load() != 1 {
					t.Fatal("confirmed absence did not release", err, len(remaining), enforcement.releases.Load())
				}
			} else {
				if err == nil || len(remaining) != 1 || enforcement.releases.Load() != 0 {
					t.Fatal("uncertainty/foreign ownership released", err, len(remaining), enforcement.releases.Load())
				}
				if mode != "false-success-retained" && deletes.Load() != 0 {
					t.Fatal("ownership denial mutated engine")
				}
			}
		})
	}
}
