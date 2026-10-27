//go:build linux

package provisionerrpc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/provisioner"
)

type matrixProcess struct {
	cmd  *exec.Cmd
	done chan error
	once sync.Once
}

func (p *matrixProcess) kill() { p.once.Do(func() { _ = p.cmd.Process.Kill(); <-p.done }) }
func matrixStart(t *testing.T, exe, log string, args ...string) *matrixProcess {
	t.Helper()
	f, e := os.OpenFile(log, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(exe, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/bin", "LANG=C"}
	cmd.Stdout = f
	cmd.Stderr = f
	if e = cmd.Start(); e != nil {
		f.Close()
		t.Fatal(e)
	}
	p := &matrixProcess{cmd: cmd, done: make(chan error, 1)}
	go func() { p.done <- cmd.Wait(); f.Close() }()
	t.Cleanup(p.kill)
	return p
}
func matrixUUID(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		t.Fatal(e)
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}

type matrixAPI struct {
	c          provisioner.LinuxConfig
	dir, addr  string
	base       []string
	client     *http.Client
	roots      *x509.CertPool
	pair       tls.Certificate
	api, guard *matrixProcess
	gen        int
}

func (s *matrixAPI) startAPI(t *testing.T) {
	s.gen++
	args := append([]string{}, s.base...)
	args = append(args, "-mode", "serve", "-listen", s.addr, "-authority", s.addr, "-controller-id", controller, "-controller-cert-sha256", fingerprint(s.pair.Leaf), "-client-ca", s.dir+"/ca.pem", "-tls-cert", s.dir+"/server.pem", "-tls-key", s.dir+"/server-key.pem")
	s.api = matrixStart(t, s.c.Executable, fmt.Sprintf("%s/api-%d.log", s.dir, s.gen), args...)
}
func (s *matrixAPI) startGuard(t *testing.T) {
	s.gen++
	args := append([]string{}, s.base...)
	args = append(args, "-mode", "guard")
	s.guard = matrixStart(t, s.c.Executable, fmt.Sprintf("%s/guard-%d.log", s.dir, s.gen), args...)
}
func (s *matrixAPI) call(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	var buf []byte
	if body != nil {
		var e error
		buf, e = json.Marshal(body)
		if e != nil {
			t.Fatal(e)
		}
	}
	r, e := http.NewRequest(method, "https://"+s.addr+path, bytes.NewReader(buf))
	if e != nil {
		t.Fatal(e)
	}
	if method == "POST" {
		r.Header.Set("Content-Type", "application/json")
	}
	res, e := s.client.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	out, e := io.ReadAll(io.LimitReader(res.Body, 32768))
	if e != nil {
		t.Fatal(e)
	}
	return res.StatusCode, out
}
func (s *matrixAPI) ready(t *testing.T) {
	t.Helper()
	end := time.Now().Add(8 * time.Second)
	for time.Now().Before(end) {
		res, e := s.client.Get("https://" + s.addr + "/internal/v1/capabilities")
		if e == nil {
			var c provisioner.Capabilities
			_ = json.NewDecoder(res.Body).Decode(&c)
			res.Body.Close()
			if res.StatusCode == 200 && c.ExecutionEnabled {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("test API/guard not ready")
}
func (s *matrixAPI) request(t *testing.T, ttl time.Duration) contracts.BuildLeaseRequest {
	return contracts.BuildLeaseRequest{SchemaVersion: 1, CommandID: matrixUUID(t), JobID: matrixUUID(t), AppID: matrixUUID(t), DeploymentID: matrixUUID(t), TemplateID: s.c.TemplateID, ProfileID: "build-small-v1", Nonce: strings.ReplaceAll(matrixUUID(t)+matrixUUID(t), "-", ""), ExpiresAt: time.Now().UTC().Add(ttl)}
}
func matrixSystem(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, e := exec.CommandContext(ctx, "/usr/bin/systemctl", args...).CombinedOutput()
	if e != nil {
		t.Fatalf("systemctl %v: %v %s", args, e, out)
	}
	return strings.TrimSpace(string(out))
}
func matrixUnitActive(t *testing.T, job string) bool {
	s := matrixSystem(t, "show", "orchestrator-build-"+job+".service", "-p", "ActiveState", "--value")
	return s != "inactive" && s != "failed" && s != ""
}
func (s *matrixAPI) waitExpired(t *testing.T, r contracts.BuildLeaseRequest) {
	t.Helper()
	for time.Now().Before(r.ExpiresAt.Add(5 * time.Second)) {
		if !matrixUnitActive(t, r.JobID) {
			t.Logf("job %s stopped; expiry observation lateness=%s", r.JobID, time.Since(r.ExpiresAt))
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("guest exceeded expiry +5s")
}
func (s *matrixAPI) release(t *testing.T, r contracts.BuildLeaseRequest) {
	t.Helper()
	status, out := s.call(t, "POST", "/internal/v1/build-leases/"+r.JobID+"/release", struct{}{})
	if status != 200 {
		t.Fatalf("release %d %s", status, out)
	}
	var l provisioner.Lease
	if e := json.Unmarshal(out, &l); e != nil || l.State != provisioner.Cleaned {
		t.Fatal("release not CLEANED", l.State, e)
	}
}
func matrixActualAPI(t *testing.T) *matrixAPI {
	t.Helper()
	root := os.Getenv("M04_MATRIX_ROOT")
	if root == "" || os.Getenv("M04_DISPOSABLE_HOST") != "YES-I-AUTHORIZE-REAL-KVM" {
		t.Skip("reviewed matrix lab not authorized")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires installed root test binary")
	}
	c, e := provisioner.LoadLinuxConfig(root + "/api/backend.json")
	if e != nil {
		t.Fatal(e)
	}
	dir := c.Root + "/rpc-" + matrixUUID(t)
	if e = os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	ca := newIssuer(t)
	server, _ := ca.leaf(t, "", true, 2*time.Hour)
	pair, _ := ca.leaf(t, "spiffe://dev-orchestrator/controller/"+controller, false, 2*time.Hour)
	if e = os.WriteFile(dir+"/ca.pem", ca.pem, 0600); e != nil {
		t.Fatal(e)
	}
	for _, v := range []struct {
		name string
		pair tls.Certificate
	}{{"server", server}, {"controller", pair}} {
		key, e := x509.MarshalPKCS8PrivateKey(v.pair.PrivateKey)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(dir+"/"+v.name+".pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: v.pair.Certificate[0]}), 0600); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(dir+"/"+v.name+"-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); e != nil {
			t.Fatal(e)
		}
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{pair}}}
	t.Cleanup(transport.CloseIdleConnections)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	addr := listener.Addr().String()
	listener.Close()
	s := &matrixAPI{c: c, dir: dir, addr: addr, roots: roots, pair: pair, client: &http.Client{Transport: transport, Timeout: 25 * time.Second}, base: []string{"-backend", "linux-kvm", "-linux-config", c.Root + "/backend.json", "-ledger", dir + "/leases.db"}}
	s.startGuard(t)
	s.startAPI(t)
	s.ready(t)
	// Actual production listener must reject absent, expired, foreign, wrong-role
	// and unpinned identities, in addition to the ordinary software TLS matrix.
	otherController, _ := ca.leaf(t, "spiffe://dev-orchestrator/controller/66666666-6666-4666-8666-666666666666", false, time.Hour)
	wrong, _ := ca.leaf(t, "spiffe://dev-orchestrator/worker/"+controller, false, time.Hour)
	unpinned, _ := ca.leaf(t, "spiffe://dev-orchestrator/controller/"+controller, false, time.Hour)
	expired, _ := ca.leaf(t, "spiffe://dev-orchestrator/controller/"+controller, false, -time.Second)
	otherCA := newIssuer(t)
	foreign, _ := otherCA.leaf(t, "spiffe://dev-orchestrator/controller/"+controller, false, time.Hour)
	for name, cert := range map[string]*tls.Certificate{"absent": nil, "expired": &expired, "foreign": &foreign, "worker": &wrong, "wrong-controller": &otherController, "unpinned": &unpinned} {
		cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
		if cert != nil {
			cfg.Certificates = []tls.Certificate{*cert}
		}
		tr := &http.Transport{TLSClientConfig: cfg}
		client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
		res, e := client.Get("https://" + addr + "/internal/v1/capabilities")
		tr.CloseIdleConnections()
		if name == "worker" || name == "unpinned" || name == "wrong-controller" {
			if e != nil {
				t.Fatal(e)
			}
			res.Body.Close()
			if res.StatusCode != 403 {
				t.Fatal(name, res.StatusCode)
			}
		} else {
			if e == nil {
				res.Body.Close()
				t.Fatal("bad mTLS accepted", name)
			}
		}
		t.Log("production mTLS rejection", name)
	}
	return s
}
func TestMatrixHostV04ActualAPIReplay(t *testing.T) {
	s := matrixActualAPI(t)
	r := s.request(t, 90*time.Second)
	status, out := s.call(t, "POST", "/internal/v1/build-leases", r)
	if status != 201 {
		t.Fatalf("create %d %s", status, out)
	}
	t.Log("owned API job", r.JobID)
	t.Cleanup(func() { s.release(t, r) })
	pid := matrixSystem(t, "show", "orchestrator-build-"+r.JobID+".service", "-p", "MainPID", "--value")
	disk, e := os.Stat(s.c.Root + "/" + r.JobID + ".raw")
	if e != nil {
		t.Fatal(e)
	}
	state, e := os.ReadFile(s.c.Root + "/" + r.JobID + ".json")
	if e != nil {
		t.Fatal(e)
	}
	var before struct{ Value struct{ Deadline int64 } }
	if e = json.Unmarshal(state, &before); e != nil {
		t.Fatal(e)
	}
	status, out = s.call(t, "POST", "/internal/v1/build-leases", r)
	if status != 200 {
		t.Fatalf("duplicate %d %s", status, out)
	}
	for _, kind := range []string{"expiry", "nonce", "other-job"} {
		bad := r
		switch kind {
		case "expiry":
			bad.ExpiresAt = bad.ExpiresAt.Add(time.Second)
		case "nonce":
			bad.Nonce = strings.Repeat("d", 64)
		case "other-job":
			bad.JobID = matrixUUID(t)
			bad.CommandID = matrixUUID(t)
		}
		status, out = s.call(t, "POST", "/internal/v1/build-leases", bad)
		if status != 409 {
			t.Fatalf("%s %d %s", kind, status, out)
		}
		t.Log("conflict rejected", kind)
	}
	if matrixSystem(t, "show", "orchestrator-build-"+r.JobID+".service", "-p", "MainPID", "--value") != pid {
		t.Fatal("duplicate guest")
	}
	current, e := os.Stat(s.c.Root + "/" + r.JobID + ".raw")
	if e != nil || !os.SameFile(disk, current) {
		t.Fatal("duplicate disk")
	}
	state, e = os.ReadFile(s.c.Root + "/" + r.JobID + ".json")
	if e != nil {
		t.Fatal(e)
	}
	var after struct{ Value struct{ Deadline int64 } }
	if e = json.Unmarshal(state, &after); e != nil || after.Value.Deadline != before.Value.Deadline {
		t.Fatal("deadline changed", e)
	}
	s.release(t, r)
	status, out = s.call(t, "POST", "/internal/v1/build-leases", r)
	if status != 200 {
		t.Fatalf("cleaned replay %d %s", status, out)
	}
	var lease provisioner.Lease
	if e = json.Unmarshal(out, &lease); e != nil || lease.State != provisioner.Cleaned {
		t.Fatal("replay resurrection", e)
	}
	if matrixUnitActive(t, r.JobID) {
		t.Fatal("cleaned unit resurrected")
	}
	if _, e = os.Stat(s.c.Root + "/" + r.JobID + ".raw"); !os.IsNotExist(e) {
		t.Fatal("cleaned disk present")
	}
	t.Log("same PID/disk/deadline across replay; CLEANED replay remains fenced")
}
func TestMatrixHostV09V10ActualServiceLoss(t *testing.T) {
	for _, which := range []string{"controller", "api", "guard"} {
		t.Run(which, func(t *testing.T) {
			s := matrixActualAPI(t)
			r := s.request(t, 18*time.Second)
			status, out := s.call(t, "POST", "/internal/v1/build-leases", r)
			if status != 201 {
				t.Fatalf("create %d %s", status, out)
			}
			t.Log("owned API job", r.JobID)
			switch which {
			case "controller":
				s.client.CloseIdleConnections()
			case "api":
				s.api.kill()
			case "guard":
				s.guard.kill()
				time.Sleep(11 * time.Second)
				other := s.request(t, time.Minute)
				status, out = s.call(t, "POST", "/internal/v1/build-leases", other)
				if status != 503 {
					t.Fatalf("stale guard admitted %d %s", status, out)
				}
				t.Log("fresh admission denied after guard stale")
			}
			s.waitExpired(t, r)
			if which == "api" {
				s.startAPI(t)
			}
			if which == "guard" {
				s.startGuard(t)
			}
			s.ready(t)
			s.release(t, r)
			status, out = s.call(t, "POST", "/internal/v1/build-leases", r)
			if status != 400 { // Expired command is rejected by the strict contract before replay lookup.
				t.Fatalf("expired replay %d %s", status, out)
			}
			t.Log("service restart reconciled; expired command cannot create duplicate")
		})
	}
}
