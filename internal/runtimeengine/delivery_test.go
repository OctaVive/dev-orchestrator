package runtimeengine

import (
	"bytes"
	"context"
	"dev-orchestrator/internal/artifacts"
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/runtimeagent"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
)

type deliveryTransport struct {
	data []byte
	fail bool
}

func (d deliveryTransport) Fetch(_ context.Context, _ artifacts.RuntimeClaim, _ artifacts.RuntimeObject, w io.Writer) error {
	w.Write(d.data)
	if d.fail {
		return runtimeagent.ErrDenied
	}
	return nil
}

type deliveryMetadata struct{ object artifacts.RuntimeObject }

func (d deliveryMetadata) RuntimeArtifact(context.Context, runtimeagent.Command, contracts.RuntimeServiceV2) (artifacts.RuntimeObject, error) {
	return d.object, nil
}
func TestDeliveryVerifiesBeforeImportAndCleansSpool(t *testing.T) {
	data := []byte("opaque-image-archive")
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/v1."+APIVersion[2:]+"/images/load" {
			t.Error("wrong image load path", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		if !bytes.Equal(body, data) {
			t.Error("wrong import")
		}
		w.Write([]byte(`{"stream":"Loaded image"}`))
	}))
	defer server.Close()
	// Replace only the network route in this unit test; production Client accepts
	// an operator-owned Unix socket exclusively.
	client := &Client{http: server.Client()}
	client.http.Transport = routeTransport{base: server.URL, transport: http.DefaultTransport}
	for _, mode := range []string{"ok", "corrupt", "short", "transport-failure", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			scratch := t.TempDir()
			os.Chmod(scratch, 0700)
			payload := append([]byte(nil), data...)
			if mode == "corrupt" {
				payload[0] = '!'
			}
			if mode == "short" {
				payload = payload[:2]
			}
			before := calls.Load()
			d := Delivery{Client: client, Transport: deliveryTransport{data: payload, fail: mode == "transport-failure"}, Metadata: deliveryMetadata{object: artifacts.RuntimeObject{Digest: contracts.Digest(data), Bytes: int64(len(data))}}, Scratch: scratch}
			check := func() error {
				if mode == "revoked" {
					return runtimeagent.ErrDenied
				}
				return nil
			}
			e := d.Prepare(context.Background(), runtimeagent.Command{}, contracts.RuntimeServiceV2{}, check)
			if mode == "ok" {
				if e != nil || calls.Load() != before+1 {
					t.Fatal(e)
				}
			} else if e == nil || calls.Load() != before {
				t.Fatal("failed delivery reached engine", e)
			}
			entries, e := os.ReadDir(scratch)
			if e != nil || len(entries) != 0 {
				t.Fatal("spool remains")
			}
		})
	}
}

type routeTransport struct {
	base      string
	transport http.RoundTripper
}

func (r routeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	u := *req.URL
	clone.URL = &u
	// Test-only route; never used by production socket transport.
	baseReq, _ := http.NewRequest("GET", r.base, nil)
	clone.URL.Scheme = baseReq.URL.Scheme
	clone.URL.Host = baseReq.URL.Host
	return r.transport.RoundTrip(clone)
}
