package ingest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/tests/fixtures/oci"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func guestOnly(t *testing.T) {
	t.Helper()
	if os.Getenv("M07_GUEST_TESTS") != "1" {
		t.Skip("artifact parsers execute only in disposable guest")
	}
	if _, e := os.Stat("/run/orchestrator-ingest-worker"); e != nil {
		t.Fatal("guest marker absent")
	}
}

type tarEntry struct {
	name string
	data []byte
	kind byte
	link string
}

func archive(entries []tarEntry) []byte {
	var out bytes.Buffer
	w := tar.NewWriter(&out)
	for _, e := range entries {
		k := e.kind
		if k == 0 {
			k = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Mode: 0644, Typeflag: k, Size: int64(len(e.data)), Linkname: e.link, Format: tar.FormatUSTAR}
		if k != tar.TypeReg {
			h.Size = 0
		}
		if err := w.WriteHeader(h); err != nil {
			panic(err)
		}
		if k == tar.TypeReg {
			w.Write(e.data)
		}
	}
	w.Close()
	return out.Bytes()
}
func jsonBytes(v any) []byte { b, _ := json.Marshal(v); return b }
func layout(layer []byte, gz bool, mutate func(map[string]any, map[string]any, map[string][]byte)) []byte {
	diff := contracts.Digest(layer)
	media := layerType
	if gz {
		var out bytes.Buffer
		w := gzip.NewWriter(&out)
		w.Write(layer)
		w.Close()
		layer = out.Bytes()
		media += "+gzip"
	}
	config := map[string]any{"architecture": "amd64", "os": "linux", "rootfs": map[string]any{"type": "layers", "diff_ids": []string{diff}}, "config": map[string]any{"User": "1000"}}
	blobs := map[string][]byte{}
	cb := jsonBytes(config)
	cd := contracts.Digest(cb)
	ld := contracts.Digest(layer)
	blobs[cd] = cb
	blobs[ld] = layer
	manifest := map[string]any{"schemaVersion": 2, "mediaType": manifestType, "config": descriptor{MediaType: configType, Digest: cd, Size: int64(len(cb))}, "layers": []descriptor{{MediaType: media, Digest: ld, Size: int64(len(layer))}}}
	if mutate != nil {
		oldConfigDigest := cd
		mutate(config, manifest, blobs)
		cb = jsonBytes(config)
		cd = contracts.Digest(cb)
		// Retain deliberately unreferenced fixture blobs; remove only the
		// old config so its rewritten descriptor stays internally consistent.
		for k := range blobs {
			if k != ld && k == oldConfigDigest {
				delete(blobs, k)
			}
		}
		blobs[cd] = cb
		manifest["config"] = descriptor{MediaType: configType, Digest: cd, Size: int64(len(cb))}
	}
	mb := jsonBytes(manifest)
	md := contracts.Digest(mb)
	blobs[md] = mb
	index := jsonBytes(map[string]any{"schemaVersion": 2, "manifests": []descriptor{{MediaType: manifestType, Digest: md, Size: int64(len(mb))}}})
	entries := []tarEntry{{name: "oci-layout", data: []byte(`{"imageLayoutVersion":"1.0.0"}`)}, {name: "index.json", data: index}}
	for d, b := range blobs {
		entries = append(entries, tarEntry{name: "blobs/sha256/" + d[7:], data: b})
	}
	return archive(entries)
}
func TestGuestOCIValidation(t *testing.T) {
	guestOnly(t)
	base := archive([]tarEntry{{name: "hello", data: []byte("inert")}})
	for _, gzip := range []bool{false, true} {
		name := "plain"
		if gzip {
			name = "gzip"
		}
		t.Run(name, func(t *testing.T) {
			data := layout(base, gzip, nil)
			r, e := Validate(bytes.NewReader(data), t.TempDir(), contracts.DefaultArtifactLimits())
			defer Release(r)
			if e != nil || !contracts.ValidDigest(r.ImageDigest) || r.ArchiveDigest != contracts.Digest(data) {
				t.Fatal(r, e)
			}
		})
	}
	for _, name := range []string{"internal-symlink", "internal-hardlink", "safe-whiteout"} {
		t.Run(name, func(t *testing.T) {
			entries := []tarEntry{{name: "file", data: []byte("inert")}}
			switch name {
			case "internal-symlink":
				entries = append(entries, tarEntry{name: "link", kind: tar.TypeSymlink, link: "file"})
			case "internal-hardlink":
				entries = append(entries, tarEntry{name: "link", kind: tar.TypeLink, link: "file"})
			case "safe-whiteout":
				entries = append(entries, tarEntry{name: ".wh.unused"})
			}
			v, e := Validate(bytes.NewReader(layout(archive(entries), false, nil)), t.TempDir(), contracts.DefaultArtifactLimits())
			defer Release(v)
			if e != nil {
				t.Fatal(e)
			}
		})
	}
	for _, name := range []string{"traversal", "absolute", "duplicate", "symlink", "device", "fifo", "bad-digest", "truncated", "extra-blob", "trailing", "platform", "root-user", "diff-id", "external-url", "layer-traversal", "layer-cycle", "layer-ancestor", "whiteout-link", "suid", "upload-limit", "expanded-limit", "entries", "ratio", "json-duplicate", "blob-size", "media-type", "pax", "gzip-truncated", "gzip-concatenated", "unreferenced-valid", "case-alias", "zero-user", "uid-overflow"} {
		t.Run(name, func(t *testing.T) {
			l := contracts.DefaultArtifactLimits()
			data := layout(base, false, nil)
			switch name {
			case "traversal":
				data = archive([]tarEntry{{name: "../escape", data: []byte("x")}})
			case "absolute":
				data = archive([]tarEntry{{name: "/escape", data: []byte("x")}})
			case "duplicate":
				data = archive([]tarEntry{{name: "index.json", data: []byte("{}")}, {name: "index.json", data: []byte("{}")}})
			case "symlink":
				data = archive([]tarEntry{{name: "index.json", kind: tar.TypeSymlink, link: "/etc/passwd"}})
			case "device":
				data = archive([]tarEntry{{name: "index.json", kind: tar.TypeChar}})
			case "fifo":
				data = archive([]tarEntry{{name: "index.json", kind: tar.TypeFifo}})
			case "bad-digest":
				data = bytes.Replace(data, []byte("inert"), []byte("evil!"), 1)
			case "truncated":
				data = data[:len(data)/2]
			case "extra-blob":
				entries := []tarEntry{{name: "blobs/sha256/" + strings.Repeat("0", 64), data: []byte("x")}}
				data = append(data[:len(data)-1024], archive(entries)...)
			case "trailing":
				data = append(data, []byte("second artifact")...)
			case "platform":
				data = layout(base, false, func(c, m map[string]any, b map[string][]byte) { c["architecture"] = "arm64" })
			case "root-user":
				data = layout(base, false, func(c, m map[string]any, b map[string][]byte) { c["config"] = map[string]any{"User": "0"} })
			case "diff-id":
				data = layout(base, false, func(c, m map[string]any, b map[string][]byte) {
					c["rootfs"] = map[string]any{"type": "layers", "diff_ids": []string{contracts.Digest(nil)}}
				})
			case "external-url":
				data = layout(base, false, func(c, m map[string]any, b map[string][]byte) {
					d := m["layers"].([]descriptor)
					d[0].URLs = []string{"https://metadata.invalid/layer"}
					m["layers"] = d
				})
			case "layer-traversal":
				data = layout(archive([]tarEntry{{name: "../../escape", data: []byte("x")}}), false, nil)
			case "layer-cycle":
				data = layout(archive([]tarEntry{{name: "a", kind: tar.TypeSymlink, link: "b"}, {name: "b", kind: tar.TypeSymlink, link: "a"}}), false, nil)
			case "layer-ancestor":
				data = layout(archive([]tarEntry{{name: "dir/file", data: []byte("x")}, {name: "dir", kind: tar.TypeSymlink, link: "elsewhere"}}), false, nil)
			case "whiteout-link":
				data = layout(archive([]tarEntry{{name: "link", kind: tar.TypeSymlink, link: "file"}, {name: ".wh.file"}}), false, nil)
			case "suid":
				var out bytes.Buffer
				w := tar.NewWriter(&out)
				w.WriteHeader(&tar.Header{Name: "file", Mode: 04755, Size: 0})
				w.Close()
				data = layout(out.Bytes(), false, nil)
			case "upload-limit":
				l.UploadBytes = 1024
			case "expanded-limit":
				l.ExpandedBytes = 1024
				data = layout(archive([]tarEntry{{name: "big", data: bytes.Repeat([]byte("x"), 2048)}}), false, nil)
			case "entries":
				l.Entries = 1
			case "ratio":
				l.Ratio = 1
				data = layout(archive([]tarEntry{{name: "big", data: bytes.Repeat([]byte("x"), 8192)}}), true, nil)
			case "blob-size":
				data = layout(base, false, func(c, m map[string]any, b map[string][]byte) {
					d := m["layers"].([]descriptor)
					d[0].Size++
					m["layers"] = d
				})
			case "media-type":
				data = layout(base, false, func(c, m map[string]any, b map[string][]byte) {
					d := m["layers"].([]descriptor)
					d[0].MediaType = "application/vnd.oci.image.layer.nondistributable.v1.tar"
					m["layers"] = d
				})
			case "pax":
				var out bytes.Buffer
				w := tar.NewWriter(&out)
				w.WriteHeader(&tar.Header{Name: "index.json", Mode: 0600, Size: 2, Format: tar.FormatPAX, PAXRecords: map[string]string{"comment": "fixture"}})
				w.Write([]byte("{}"))
				w.Close()
				data = out.Bytes()
			case "gzip-truncated", "gzip-concatenated":
				var out bytes.Buffer
				w := gzip.NewWriter(&out)
				w.Write(base)
				w.Close()
				compressed := out.Bytes()
				if name == "gzip-truncated" {
					compressed = compressed[:len(compressed)-4]
				} else {
					compressed = append(compressed, compressed...)
				}
				data = layout(compressed, false, func(c, m map[string]any, b map[string][]byte) {
					d := m["layers"].([]descriptor)
					d[0].MediaType = layerType + "+gzip"
					m["layers"] = d
					c["rootfs"] = map[string]any{"type": "layers", "diff_ids": []string{contracts.Digest(base)}}
				})
			case "unreferenced-valid":
				data = layout(base, false, func(c, m map[string]any, b map[string][]byte) { b[contracts.Digest([]byte("extra"))] = []byte("extra") })
			case "zero-user":
				data = layout(base, false, func(c, m map[string]any, b map[string][]byte) { c["config"] = map[string]any{"User": "00"} })
			case "uid-overflow":
				data = layout(base, false, func(c, m map[string]any, b map[string][]byte) { c["config"] = map[string]any{"User": "65536"} })
			case "case-alias":
				data = layout(base, false, func(c, m map[string]any, b map[string][]byte) { delete(c, "architecture"); c["Architecture"] = "amd64" })
			case "json-duplicate":
				data = archive([]tarEntry{{name: "oci-layout", data: []byte(`{"imageLayoutVersion":"bad","imageLayoutVersion":"1.0.0"}`)}, {name: "index.json", data: []byte(`{}`)}})
			}
			if r, e := Validate(bytes.NewReader(data), t.TempDir(), l); e == nil {
				t.Fatal("hostile artifact admitted", r)
			}
		})
	}
}
func testPolicy() contracts.BuildPolicy {
	return contracts.BuildPolicy{EgressPolicyHash: strings.Repeat("a", 64), UploadOrigin: "https://ingest.example.com", Version: 1, BuildSeconds: 1200, ScanSeconds: 300, Limits: contracts.DefaultArtifactLimits(), ScannerDigest: contracts.Digest([]byte("tool")), DatabaseDigest: contracts.Digest([]byte("db")), DatabaseCreatedAt: time.Now().Add(-time.Hour), DatabaseMaxAgeSeconds: 172800}
}
func TestGuestScanPolicy(t *testing.T) {
	guestOnly(t)
	for _, name := range []string{"clean", "high-unfixed", "critical", "exception", "wrong-digest", "expired", "unknown", "missing-coverage", "eol", "stale-db", "malformed"} {
		t.Run(name, func(t *testing.T) {
			p := testPolicy()
			digest := contracts.Digest([]byte("image"))
			vulns := []map[string]string{}
			allow := false
			switch name {
			case "clean":
				allow = true
			case "high-unfixed", "exception", "wrong-digest", "expired":
				vulns = []map[string]string{{"VulnerabilityID": "CVE-fixture", "PkgName": "fixture", "Severity": "HIGH"}}
			case "critical":
				vulns = []map[string]string{{"VulnerabilityID": "CVE-fixture", "PkgName": "fixture", "Severity": "CRITICAL"}}
			case "unknown":
				vulns = []map[string]string{{"VulnerabilityID": "CVE-fixture", "PkgName": "fixture", "Severity": "UNKNOWN"}}
			case "stale-db":
				p.DatabaseCreatedAt = time.Now().Add(-72 * time.Hour)
			}
			if name == "exception" || name == "wrong-digest" || name == "expired" {
				p.Exceptions = []contracts.ScanException{{Vulnerability: "CVE-fixture", Package: "fixture", Digest: digest, ExpiresAt: time.Now().Add(time.Hour)}}
				allow = name == "exception"
				if name == "wrong-digest" {
					p.Exceptions[0].Digest = contracts.Digest(nil)
				}
				if name == "expired" {
					p.Exceptions[0].ExpiresAt = time.Now().Add(-time.Second)
				}
			}
			report := map[string]any{"SchemaVersion": 2, "Metadata": map[string]any{"OS": map[string]any{"Family": "alpine", "Name": "3.23", "EOSL": name == "eol"}}, "Results": []any{map[string]any{"Class": "os-pkgs", "Type": "alpine", "Vulnerabilities": vulns}}}
			if name == "missing-coverage" {
				delete(report, "Metadata")
			}
			data := jsonBytes(report)
			if name == "malformed" {
				data = []byte("{")
			}
			_, _, e := evaluate(data, p, digest, time.Now())
			if (e == nil) != allow {
				t.Fatal("policy decision", e)
			}
		})
	}
}

func TestGuestRealTrivy(t *testing.T) {
	guestOnly(t)
	tool, e := os.ReadFile("/usr/bin/trivy")
	if e != nil {
		t.Fatal(e)
	}
	f, e := os.Open("/scan-cache/db/trivy.db")
	if e != nil {
		t.Fatal(e)
	}
	db, e := digestReader(f)
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	metaBytes, e := os.ReadFile("/scan-cache/db/metadata.json")
	if e != nil {
		t.Fatal(e)
	}
	var meta struct {
		UpdatedAt time.Time `json:"UpdatedAt"`
	}
	if json.Unmarshal(metaBytes, &meta) != nil {
		t.Fatal("database metadata")
	}
	for _, vulnerable := range []bool{false, true} {
		name := "clean"
		if vulnerable {
			name = "vulnerable"
		}
		t.Run(name, func(t *testing.T) {
			data := ocifixture.Image(vulnerable)
			dir := t.TempDir()
			file := dir + "/image.tar"
			os.WriteFile(file, data, 0600)
			v, e := Validate(bytes.NewReader(data), dir, contracts.DefaultArtifactLimits())
			defer Release(v)
			if e != nil {
				t.Fatal(e)
			}
			p := testPolicy()
			p.ScannerDigest = contracts.Digest(tool)
			p.DatabaseDigest = db
			p.DatabaseCreatedAt = meta.UpdatedAt
			cp := contracts.ClonePolicy{Version: 1, Hosts: []string{"example.com"}, Limits: contracts.DefaultCloneLimits()}
			clone := contracts.CloneJob{Version: 1, JobID: "11111111-1111-4111-8111-111111111111", DeploymentID: "22222222-2222-4222-8222-222222222222", LeaseID: "33333333-3333-4333-8333-333333333333", Attempt: 1, Generation: 1, ExpiresAt: time.Now().Add(20 * time.Minute), TemplateDigest: contracts.Digest(nil), PolicyHash: cp.Hash(), RepositoryURL: "https://example.com/repo", Branch: "main", ConfigPath: "Dockerfile", BuildContext: ".", Policy: cp}
			clone.Build = &contracts.BuildSettings{Policy: p, Dockerfile: "Dockerfile"}
			j := contracts.BuildJob{Version: 1, Clone: clone, SHA: strings.Repeat("a", 40), ContextID: strings.Repeat("b", 64), Policy: p, PolicyHash: p.Hash(), Dockerfile: "Dockerfile", ExpiresAt: clone.ExpiresAt}
			audit := t.TempDir()
			if e := os.Mkdir(audit+"/cache", 0700); e != nil {
				t.Fatal(e)
			}
			if e := os.Symlink("/scan-cache/db", audit+"/cache/db"); e != nil {
				t.Fatal(e)
			}
			report, e := runTool(context.Background(), audit, "json", v.LayoutPath)
			if e != nil {
				t.Fatal("real scanner failed", e)
			}
			high, critical, decision := evaluate(report, p, v.ImageDigest, time.Now())
			if vulnerable && (decision == nil || high+critical == 0) {
				t.Fatal("fixture did not exercise vulnerability denial", high, critical, decision)
			}
			if !vulnerable && decision != nil {
				t.Fatal("clean fixture policy denial", decision)
			}
			result, e := Scan(context.Background(), file, dir, j, v)
			if vulnerable {
				if e == nil {
					t.Fatal("vulnerable admitted", result)
				}
			} else {
				if e != nil || result.Outcome != "admitted" || result.ImageDigest != v.ImageDigest {
					diagnoseTrivy(t, v.LayoutPath, dir)
					t.Fatal("clean scan", result, e)
				}
			}
		})
	}
}

func diagnoseTrivy(t *testing.T, file, dir string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/trivy", "image", "--input", file, "--cache-dir", "/scan-cache", "--cache-backend", "memory", "--skip-db-update", "--skip-java-db-update", "--offline-scan", "--scanners", "vuln", "--list-all-pkgs", "--format", "json", "--ignorefile", "/dev/null", "--config", "/dev/null")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "TMPDIR=" + dir}
	out := &toolOutput{limit: 16384, cancel: cancel}
	cmd.Stdout = out
	cmd.Stderr = out
	e := cmd.Run()
	t.Log("fixture-only diagnostic", e, out.b.String())
}

func FuzzGuestOCI(f *testing.F) {
	if os.Getenv("M07_GUEST_TESTS") != "1" {
		f.Skip("guest-only parser fuzzing")
	}
	f.Add([]byte("malformed"))
	f.Add(layout(archive([]tarEntry{{name: "file", data: []byte("inert")}}), false, nil))
	f.Fuzz(func(t *testing.T, b []byte) {
		guestOnly(t)
		l := contracts.DefaultArtifactLimits()
		l.UploadBytes = 64 << 10
		l.ExpandedBytes = 128 << 10
		l.LayerBytes = 64 << 10
		l.Entries = 128
		v, _ := Validate(bytes.NewReader(b), t.TempDir(), l)
		Release(v)
	})
}
