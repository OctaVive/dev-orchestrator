// Package ocifixture constructs known inert bytes; it never reads/parses an
// archive or executes a workload on the host.
package ocifixture

import (
	"archive/tar"
	"bytes"
	"dev-orchestrator/internal/contracts"
	"encoding/json"
)

func encode(v any) []byte { b, _ := json.Marshal(v); return b }
func tarBytes(files map[string][]byte) []byte {
	var out bytes.Buffer
	w := tar.NewWriter(&out)
	for name, b := range files {
		if e := w.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(b)), Format: tar.FormatUSTAR}); e != nil {
			panic(e)
		}
		w.Write(b)
	}
	w.Close()
	return out.Bytes()
}
func Image(vulnerable bool) []byte {
	pkg := "P:m07-inert\nV:1.0.0-r0\nA:x86_64\nS:0\nI:0\nT:Inert acceptance fixture\nL:MIT\no:m07-inert\nm:fixture\nt:0\nc:0000000000000000000000000000000000000000\n\n"
	if vulnerable {
		pkg = "P:busybox\nV:1.30.1-r0\nA:x86_64\nS:0\nI:0\nT:Inert package metadata only\nL:GPL-2.0\no:busybox\nm:fixture\nt:0\nc:0000000000000000000000000000000000000000\n\n"
	}
	layer := tarBytes(map[string][]byte{"etc/os-release": []byte("NAME=Alpine\nID=alpine\nVERSION_ID=3.23.0\n"), "lib/apk/db/installed": []byte(pkg)})
	desc := func(b []byte, media string) map[string]any {
		return map[string]any{"mediaType": media, "digest": contracts.Digest(b), "size": len(b)}
	}
	cfg := encode(map[string]any{"architecture": "amd64", "os": "linux", "rootfs": map[string]any{"type": "layers", "diff_ids": []string{contracts.Digest(layer)}}, "config": map[string]any{"User": "1000"}})
	manifest := encode(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": desc(cfg, "application/vnd.oci.image.config.v1+json"), "layers": []any{desc(layer, "application/vnd.oci.image.layer.v1.tar")}})
	index := encode(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": []any{desc(manifest, "application/vnd.oci.image.manifest.v1+json")}})
	return tarBytes(map[string][]byte{"oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`), "index.json": index, "blobs/sha256/" + contracts.Digest(cfg)[7:]: cfg, "blobs/sha256/" + contracts.Digest(layer)[7:]: layer, "blobs/sha256/" + contracts.Digest(manifest)[7:]: manifest})
}
