package artifacts

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/policy"
)

const runtimeID = "11111111-1111-4111-8111-111111111111"

type runtimeAuth struct {
	object      RuntimeObject
	denied      bool
	calls       int
	revokeAfter int
}

func (a *runtimeAuth) AuthorizeRuntime(_ context.Context, peer RuntimePeer, c RuntimeClaim) (RuntimeObject, error) {
	a.calls++
	if a.denied || a.revokeAfter > 0 && a.calls > a.revokeAfter || peer.URI != "spiffe://tap/runtime-agent/"+runtimeID || len(peer.CertificateSHA256) != 64 || c.AdmissionID != "admitted" || c.AppID != runtimeID {
		return RuntimeObject{}, ErrDenied
	}
	return a.object, nil
}
func runtimeRequest(body string) *httptest.ResponseRecorder { return httptest.NewRecorder() }
func runtimeBody() string {
	return `{"worker_id":"` + runtimeID + `","incarnation":"` + runtimeID + `","app_id":"` + runtimeID + `","deployment_id":"` + runtimeID + `","generation":1,"spec_hash":"` + contracts.Digest([]byte("spec")) + `","policy_hash":"` + policy.Hash() + `","admission_id":"admitted","image":"registry.example.org/apps/web@sha256:` + strings.Repeat("a", 64) + `"}`
}
func serveRuntime(t *testing.T, d *RuntimeDownloads, body, uri string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", "https://artifacts.test/runtime/v1/artifact", strings.NewReader(body))
	u, e := url.Parse(uri)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{Raw: []byte("test-certificate"), NotAfter: time.Now().Add(time.Hour), URIs: []*url.URL{u}}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	w := httptest.NewRecorder()
	d.ServeHTTP(w, r)
	return w
}
func runtimeDownloadFixture(t *testing.T) (*RuntimeDownloads, *runtimeAuth, string) {
	t.Helper()
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil {
		t.Fatal("chmod")
	}
	data := []byte("opaque-admitted-archive")
	object := RuntimeObject{Digest: contracts.Digest(data), Bytes: int64(len(data))}
	path := filepath.Join(root, strings.TrimPrefix(object.Digest, "sha256:"))
	if os.WriteFile(path, data, 0600) != nil {
		t.Fatal("write")
	}
	auth := &runtimeAuth{object: object}
	d, e := NewRuntimeDownloads(root, auth)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { d.Close() })
	return d, auth, path
}
func TestRuntimeArtifactAuthorizationAndOpaqueDelivery(t *testing.T) {
	d, auth, _ := runtimeDownloadFixture(t)
	w := serveRuntime(t, d, runtimeBody(), "spiffe://tap/runtime-agent/"+runtimeID)
	if w.Code != 200 || w.Body.String() != "opaque-admitted-archive" || w.Header().Get("X-Artifact-Digest") != auth.object.Digest {
		t.Fatal("download", w.Code)
	}
	cases := map[string]struct{ body, uri string }{"relay": {runtimeBody(), "spiffe://tap/relay"}, "worker": {runtimeBody(), "spiffe://tap/runtime-agent/22222222-2222-4222-8222-222222222222"}, "admission": {strings.Replace(runtimeBody(), "admitted", "unadmitted", 1), "spiffe://tap/runtime-agent/" + runtimeID}, "unknown": {strings.Replace(runtimeBody(), `"generation":1`, `"generation":1,"path":"/etc/passwd"`, 1), "spiffe://tap/runtime-agent/" + runtimeID}, "duplicate": {strings.Replace(runtimeBody(), `"generation":1`, `"generation":1,"generation":1`, 1), "spiffe://tap/runtime-agent/" + runtimeID}, "tag": {strings.Replace(runtimeBody(), "@sha256:"+strings.Repeat("a", 64), ":latest", 1), "spiffe://tap/runtime-agent/" + runtimeID}}
	for n, c := range cases {
		t.Run(n, func(t *testing.T) {
			w := serveRuntime(t, d, c.body, c.uri)
			if w.Code != 403 || bytes.Contains(w.Body.Bytes(), []byte("opaque-admitted")) {
				t.Fatal("unauthorized download", w.Code)
			}
		})
	}
	auth.denied = true
	if w := serveRuntime(t, d, runtimeBody(), "spiffe://tap/runtime-agent/"+runtimeID); w.Code != 403 {
		t.Fatal("revocation")
	}
}
func TestRuntimeArtifactCorruptionAndSymlinkDenials(t *testing.T) {
	for _, kind := range []string{"corrupt", "symlink", "public", "wrong-size"} {
		t.Run(kind, func(t *testing.T) {
			d, a, path := runtimeDownloadFixture(t)
			switch kind {
			case "corrupt":
				os.WriteFile(path, []byte("changed-admitted-bytes!"), 0600)
			case "symlink":
				os.Remove(path)
				os.Symlink("/etc/passwd", path)
			case "public":
				os.Chmod(path, 0644)
			case "wrong-size":
				a.object.Bytes++
			}
			w := serveRuntime(t, d, runtimeBody(), "spiffe://tap/runtime-agent/"+runtimeID)
			if w.Code != 403 {
				t.Fatal("bad object served", w.Code)
			}
		})
	}
}
func TestRuntimeArtifactRevocationBeforeStreaming(t *testing.T) {
	d, a, _ := runtimeDownloadFixture(t)
	a.revokeAfter = 1
	w := serveRuntime(t, d, runtimeBody(), "spiffe://tap/runtime-agent/"+runtimeID)
	if w.Code != 403 || strings.Contains(w.Body.String(), "opaque") {
		t.Fatal("revoked bytes served")
	}
}
func TestRuntimeArtifactRequiresMTLSAndNoListing(t *testing.T) {
	d, _, _ := runtimeDownloadFixture(t)
	for _, method := range []string{"GET", "POST"} {
		r := httptest.NewRequest(method, "https://artifacts.test/runtime/v1/artifact", strings.NewReader(runtimeBody()))
		w := httptest.NewRecorder()
		d.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("unauthenticated retrieval")
		}
	}
}
