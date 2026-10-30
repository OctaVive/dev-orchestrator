package artifacts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/policy"
	"golang.org/x/sys/unix"
)

// RuntimeClaim contains identities only, never workload environment or paths.
// The durable authorization adapter must bind every field and current approval,
// worker lease/revocation, admission, scan policy and immutable artifact identity.
type RuntimeClaim struct {
	WorkerID     string `json:"worker_id"`
	Incarnation  string `json:"incarnation"`
	AppID        string `json:"app_id"`
	DeploymentID string `json:"deployment_id"`
	Generation   int64  `json:"generation"`
	SpecHash     string `json:"spec_hash"`
	PolicyHash   string `json:"policy_hash"`
	AdmissionID  string `json:"admission_id"`
	Image        string `json:"image"`
}
type RuntimeObject struct {
	Digest string
	Bytes  int64
}
type RuntimePeer struct {
	URI               string
	CertificateSHA256 string
}
type RuntimeAuthorizer interface {
	AuthorizeRuntime(context.Context, RuntimePeer, RuntimeClaim) (RuntimeObject, error)
}
type RuntimeDownloads struct {
	root   *os.Root
	auth   RuntimeAuthorizer
	mu     sync.Mutex
	active int
}

func NewRuntimeDownloads(root string, auth RuntimeAuthorizer) (*RuntimeDownloads, error) {
	st, e := os.Lstat(root)
	if e != nil || !st.IsDir() || st.Mode()&0077 != 0 || st.Mode()&os.ModeSymlink != 0 || auth == nil {
		return nil, ErrDenied
	}
	r, e := os.OpenRoot(root)
	if e != nil {
		return nil, ErrDenied
	}
	return &RuntimeDownloads{root: r, auth: auth}, nil
}
func (d *RuntimeDownloads) Close() error { return d.root.Close() }
func validRuntimeClaim(c RuntimeClaim) bool {
	return contracts.ValidJobID(c.WorkerID) && contracts.ValidJobID(c.Incarnation) && contracts.ValidJobID(c.AppID) && contracts.ValidJobID(c.DeploymentID) && c.Generation > 0 && c.Generation <= 9007199254740991 && contracts.ValidDigest(c.SpecHash) && contracts.ValidDigest(c.PolicyHash) && len(c.AdmissionID) > 0 && len(c.AdmissionID) <= 128 && policy.ValidImage(c.Image)
}

// ServeHTTP belongs only on a separate runtime mTLS listener. There is no GET,
// listing, caller-controlled path, upload grant reuse or HTTP range surface.
func (d *RuntimeDownloads) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	deny := func() { http.Error(w, "denied", http.StatusForbidden) }
	if r.Method != "POST" || r.URL.Path != "/runtime/v1/artifact" || r.URL.RawQuery != "" || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.PeerCertificates[0].URIs) != 1 {
		deny()
		return
	}
	claim, e := contracts.DecodeConfiguration[RuntimeClaim](http.MaxBytesReader(w, r.Body, 4096))
	if e != nil || !validRuntimeClaim(claim) {
		deny()
		return
	}
	certificate := r.TLS.PeerCertificates[0]
	if len(certificate.Raw) == 0 || !certificate.NotAfter.After(time.Now()) {
		deny()
		return
	}
	sum := sha256.Sum256(certificate.Raw)
	peer := RuntimePeer{URI: certificate.URIs[0].String(), CertificateSHA256: hex.EncodeToString(sum[:])}
	if peer.URI != "spiffe://tap/runtime-agent/"+claim.WorkerID {
		deny()
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	object, e := d.auth.AuthorizeRuntime(ctx, peer, claim)
	if e != nil || !contracts.ValidDigest(object.Digest) || object.Bytes < 1 || object.Bytes > 1<<30 {
		deny()
		return
	}
	d.mu.Lock()
	if d.active >= 2 {
		d.mu.Unlock()
		deny()
		return
	}
	d.active++
	d.mu.Unlock()
	defer func() { d.mu.Lock(); d.active--; d.mu.Unlock() }()
	f, e := d.root.OpenFile(strings.TrimPrefix(object.Digest, "sha256:"), os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if e != nil {
		deny()
		return
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode()&0077 != 0 || st.Size() != object.Bytes {
		deny()
		return
	}
	// Rehash before sending; management treats the admitted archive as opaque bytes.
	hash := sha256.New()
	n, e := io.Copy(hash, io.LimitReader(f, object.Bytes+1))
	if e != nil || n != object.Bytes || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != object.Digest {
		deny()
		return
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		deny()
		return
	}
	if next, e := d.auth.AuthorizeRuntime(ctx, peer, claim); e != nil || next != object {
		deny()
		return
	}
	controller := http.NewResponseController(w)
	_ = controller.SetWriteDeadline(time.Now().Add(30 * time.Second))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprint(object.Bytes))
	w.Header().Set("X-Artifact-Digest", object.Digest)
	w.Header().Set("Cache-Control", "no-store")
	buf := make([]byte, 32768)
	remaining := object.Bytes
	for remaining > 0 {
		// Revocation or a changed admission terminates the stream; clients must verify
		// the complete immutable digest before allowing an engine import.
		if ctx.Err() != nil || !certificate.NotAfter.After(time.Now()) {
			return
		}
		next, e := d.auth.AuthorizeRuntime(ctx, peer, claim)
		if e != nil || next != object {
			return
		}
		size := int64(len(buf))
		if remaining < size {
			size = remaining
		}
		n, e := io.ReadFull(f, buf[:size])
		if e != nil {
			return
		}
		if _, e = w.Write(buf[:n]); e != nil {
			return
		}
		remaining -= int64(n)
	}
}
