package runtimeengine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"dev-orchestrator/internal/contracts"
)

func TestLoadedImageRequiresExactOCIManifestIdentity(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	service := contracts.RuntimeServiceV2{Image: "registry.example.org/apps/web@" + digest, UID: 1000, GID: 1000}
	for _, mode := range []string{"exact", "config-id", "platform", "root-user", "volume"} {
		t.Run(mode, func(t *testing.T) {
			response := map[string]any{"Id": digest, "Architecture": "amd64", "Os": "linux", "Config": map[string]any{"User": "1000:1000"}}
			switch mode {
			case "config-id":
				response["Id"] = "sha256:" + strings.Repeat("b", 64)
			case "platform":
				response["Architecture"] = "arm64"
			case "root-user":
				response["Config"] = map[string]any{"User": "0:0"}
			case "volume":
				response["Config"] = map[string]any{"User": "1000:1000", "Volumes": map[string]any{"/data": map[string]any{}}}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/v"+APIVersion+"/images/"+digest+"/json" {
					t.Error("non-content-addressed lookup", r.URL.Path)
					w.WriteHeader(403)
					return
				}
				json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			client := &Client{http: server.Client()}
			client.http.Transport = routeTransport{base: server.URL, transport: http.DefaultTransport}
			err := (&Engine{Client: client}).verifyImage(context.Background(), service)
			if (err == nil) != (mode == "exact") {
				t.Fatal(mode, err)
			}
		})
	}
	if fixtureConfig(t).Image != digest {
		t.Fatal("candidate retained mutable registry lookup")
	}
}
