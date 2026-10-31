package runtimerpc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dev-orchestrator/internal/artifacts"
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/policy"
	"dev-orchestrator/internal/runtimeagent"
	"dev-orchestrator/internal/runtimeauthority"
)

type authorityFixture struct {
	grant       runtimeauthority.Grant
	fingerprint string
	denied      atomic.Bool
	wrongApp    atomic.Bool
}

func (f *authorityFixture) RuntimeLease(_ context.Context, p artifacts.RuntimePeer, worker, inc string) (time.Time, error) {
	if f.denied.Load() || p.URI != "spiffe://tap/runtime-agent/"+id || p.CertificateSHA256 != f.fingerprint || worker != id || inc != id {
		return time.Time{}, runtimeagent.ErrDenied
	}
	return time.Now().Add(30 * time.Second), nil
}
func (f *authorityFixture) RuntimeGrant(ctx context.Context, p artifacts.RuntimePeer, c runtimeagent.Command) (runtimeauthority.Grant, error) {
	if _, err := f.RuntimeLease(ctx, p, c.WorkerID, c.Incarnation); err != nil {
		return runtimeauthority.Grant{}, err
	}
	g := f.grant
	g.ExpiresAt = time.Now().Add(time.Second)
	if f.wrongApp.Load() {
		g.AppID = "22222222-2222-4222-8222-222222222222"
	}
	return g, nil
}
func (*authorityFixture) RuntimePoll(context.Context, artifacts.RuntimePeer, runtimeauthority.PollRequest) (*runtimeagent.Command, error) {
	return nil, nil
}
func (*authorityFixture) AuthorizeRuntime(context.Context, artifacts.RuntimePeer, artifacts.RuntimeClaim) (artifacts.RuntimeObject, error) {
	return artifacts.RuntimeObject{}, runtimeagent.ErrDenied
}
func TestCurrentAuthorityOverMTLS(t *testing.T) {
	cfg, tlsServer := tlsFixture(t)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	image := "registry.example.org/apps/web@sha256:" + strings.Repeat("a", 64)
	spec := contracts.RuntimeSpecV2{Version: 2, Profile: policy.Profile, PolicyHash: policy.Hash(), AppID: id, DeploymentID: id, SHA: strings.Repeat("b", 40), ContextID: strings.Repeat("c", 64), PlanHash: contracts.Digest([]byte("plan")), Services: []contracts.RuntimeServiceV2{{Name: "web", Image: image, AdmissionID: "admission", UID: 1000, GID: 1000, Resources: policy.Defaults(), Expose: []int{8080}}}, Ingress: contracts.Ingress{Service: "web", Port: 8080, HealthPath: "/health"}}
	command := runtimeagent.Command{Version: 3, Operation: "create", ID: id, WorkerID: id, Incarnation: id, AppID: id, DeploymentID: id, Generation: 1, Nonce: strings.Repeat("a", 64), KeyID: "controller", ExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano), SpecHash: policy.SpecHash(spec), PolicyHash: policy.Hash(), Spec: &spec}
	if command.Sign(key) != nil {
		t.Fatal("sign")
	}
	sum := sha256.Sum256(cfg.Identity.Certificate[0])
	state := &authorityFixture{fingerprint: hex.EncodeToString(sum[:]), grant: runtimeauthority.Grant{WorkerID: id, Incarnation: id, AppID: id, DeploymentID: id, Generation: 1, SpecHash: command.SpecHash, PolicyHash: policy.Hash(), SourceSHA: spec.SHA, ContextID: spec.ContextID, Images: []runtimeauthority.Image{{Admission: policy.Admission{ID: "admission", Image: image, PolicyHash: policy.Hash(), Platform: "linux/amd64", User: "1000:1000"}, Object: artifacts.RuntimeObject{Digest: contracts.Digest([]byte("archive")), Bytes: 7}}}}}
	handler, err := runtimeauthority.NewServer(state, map[string]ed25519.PublicKey{"controller": pub}, http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = tlsServer
	server.StartTLS()
	defer server.Close()
	cfg.Origin = server.URL
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	authority := &Authority{Client: client}
	ctx := context.Background()
	if authority.Valid(ctx, id, id) != nil || authority.Current(ctx, command) != nil || policy.ValidateRuntime(spec, authority) != nil {
		t.Fatal("valid current authority")
	}
	object, err := authority.RuntimeArtifact(ctx, command, spec.Services[0])
	if err != nil || object != state.grant.Images[0].Object {
		t.Fatal("exact artifact metadata", err)
	}
	if _, err = authority.Volume(id, id); err == nil || authority.Secret(id, id, id) == nil {
		t.Fatal("M10 boundary")
	}
	state.wrongApp.Store(true)
	if authority.Current(ctx, command) == nil {
		t.Fatal("cross-app grant")
	}
	if _, err = authority.Image(image); err == nil {
		t.Fatal("failed refresh retained old grant")
	}
	state.wrongApp.Store(false)
	if authority.Current(ctx, command) != nil {
		t.Fatal("refresh")
	}
	state.denied.Store(true)
	if authority.Valid(ctx, id, id) == nil || authority.Current(ctx, command) == nil {
		t.Fatal("reused TLS authorization revocation")
	}
	if _, err = authority.RuntimeArtifact(ctx, command, spec.Services[0]); err == nil {
		t.Fatal("revoked artifact metadata")
	}
}

func (f *authorityFixture) RuntimeTargetGrant(ctx context.Context, p artifacts.RuntimePeer, q runtimeauthority.TargetRequest) (runtimeauthority.Grant, error) {
	if _, err := f.RuntimeLease(ctx, p, q.WorkerID, q.Incarnation); err != nil {
		return runtimeauthority.Grant{}, err
	}
	g := f.grant
	g.OwnerID = q.OwnerID
	g.ExpiresAt = time.Now().Add(time.Second)
	return g, nil
}

type blockingRefresh struct{ started, release chan struct{} }

func (b *blockingRefresh) authorityPOST(ctx context.Context, _ string, _ any) ([]byte, error) {
	close(b.started)
	select {
	case <-b.release:
		return nil, runtimeagent.ErrDenied
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func TestRefreshDoesNotExposeTransientEmptyResolver(t *testing.T) {
	image := "registry.example.org/apps/web@sha256:" + strings.Repeat("a", 64)
	transport := &blockingRefresh{started: make(chan struct{}), release: make(chan struct{})}
	a := &Authority{Client: transport, grant: runtimeauthority.Grant{ExpiresAt: time.Now().Add(4 * time.Second), Images: []runtimeauthority.Image{{Admission: policy.Admission{Image: image}}}}}
	done := make(chan error, 1)
	go func() {
		done <- a.Current(context.Background(), runtimeagent.Command{Spec: &contracts.RuntimeSpecV2{}})
	}()
	<-transport.started
	if _, err := a.Image(image); err != nil {
		t.Fatal("in-flight refresh invalidated still-fresh resolver", err)
	}
	close(transport.release)
	if err := <-done; err == nil {
		t.Fatal("failed refresh succeeded")
	}
	if _, err := a.Image(image); err == nil {
		t.Fatal("failed refresh retained resolver")
	}
}
