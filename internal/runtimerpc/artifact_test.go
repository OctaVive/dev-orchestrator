package runtimerpc

import (
	"bytes"
	"context"
	"dev-orchestrator/internal/artifacts"
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/runtimeagent"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
)

func TestArtifactStreamIntegrityAndBounds(t *testing.T) {
	cfg, tlsCfg := tlsFixture(t)
	data := []byte("opaque-admitted-image-archive")
	object := artifacts.RuntimeObject{Digest: contracts.Digest(data), Bytes: int64(len(data))}
	var mode atomic.Value
	mode.Store("ok")
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/runtime/v1/artifact" || r.Method != "POST" {
			t.Error("wrong artifact path")
		}
		w.Header().Set("X-Artifact-Digest", object.Digest)
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		switch mode.Load().(string) {
		case "corrupt":
			b := append([]byte(nil), data...)
			b[0] = '!'
			w.Write(b)
		case "short":
			w.Write(data[:2])
		case "wrong-digest":
			w.Header().Set("X-Artifact-Digest", contracts.Digest([]byte("other")))
			w.Write(data)
		default:
			w.Write(data)
		}
	}))
	server.TLS = tlsCfg
	server.StartTLS()
	defer server.Close()
	cfg.Origin = server.URL
	c, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	var out bytes.Buffer
	if e = c.Fetch(context.Background(), artifacts.RuntimeClaim{WorkerID: id}, object, &out); e != nil || !bytes.Equal(out.Bytes(), data) {
		t.Fatal("valid artifact", e)
	}
	for _, m := range []string{"corrupt", "short", "wrong-digest"} {
		mode.Store(m)
		out.Reset()
		if e := c.Fetch(context.Background(), artifacts.RuntimeClaim{WorkerID: id}, object, &out); e != runtimeagent.ErrDenied {
			t.Fatal(m, e)
		}
	}
	bad := object
	bad.Bytes = 1<<30 + 1
	if e = c.Fetch(context.Background(), artifacts.RuntimeClaim{}, bad, &out); e != runtimeagent.ErrDenied {
		t.Fatal("size budget")
	}
}
