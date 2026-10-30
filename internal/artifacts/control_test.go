package artifacts

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestArtifactServiceControlAndUpload(t *testing.T) {
	s := newStore(t)
	dest := t.TempDir()
	os.Chmod(dest, 0700)
	socket := filepath.Join(t.TempDir(), "control.sock")
	listener, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	server := http.Server{Handler: s.ControlHandler(dest)}
	go server.Serve(listener)
	defer server.Close()
	client := NewClient(socket)
	b := Binding{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", 1, 1}
	id, token, e := client.Issue(b, 1024, time.Now().Add(time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	upload := httptest.NewTLSServer(s.Handler())
	defer upload.Close()
	request, _ := http.NewRequest("PUT", upload.URL+"/"+id, strings.NewReader("opaque fixture"))
	request.Header.Set("Authorization", "Bearer "+token)
	r, e := upload.Client().Do(request)
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 201 {
		t.Fatal(r.StatusCode)
	}
	receipt, e := client.Receipt(id)
	if e != nil || receipt.Binding != b {
		t.Fatal(receipt, e)
	}
	object, e := client.Promote(receipt, "ignored-controller-path")
	if e != nil || len(object) != 64 {
		t.Fatal(object, e)
	}
	if _, e = client.Promote(receipt, ""); e != nil {
		t.Fatal("promotion retry", e)
	}
	client.Revoke(id)
	if _, e = client.Receipt(id); e == nil {
		t.Fatal("revoked receipt")
	}
	// The guest-facing listener cannot issue grants or invoke promotion.
	for _, path := range []string{"/issue", "/promote", "/receipt"} {
		request, _ = http.NewRequest("POST", upload.URL+path, strings.NewReader("{}"))
		r, e = upload.Client().Do(request)
		if e != nil {
			t.Fatal(e)
		}
		r.Body.Close()
		if r.StatusCode == 200 {
			t.Fatal("control on public interface")
		}
	}
	_ = context.Background()
}
func TestQuarantineRetentionAndReservation(t *testing.T) {
	s := newStore(t)
	b := Binding{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", 1, 1}
	id, token, e := s.Issue(b, 1024, time.Now().Add(time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Put(context.Background(), id, token, strings.NewReader("opaque")); e != nil {
		t.Fatal(e)
	}
	if e = s.Sweep(time.Now().Add(2 * time.Minute)); e != nil || s.used != 6 {
		t.Fatal("retention reservation released early", e)
	}
	if e = s.Sweep(time.Now().Add(25 * time.Hour)); e != nil || s.used != 0 {
		t.Fatal("retention cleanup", s.used, e)
	}
	if _, e = os.Stat(filepath.Join(s.root, id)); !os.IsNotExist(e) {
		t.Fatal("expired quarantine remains")
	}
}

func TestArtifactHostReserve(t *testing.T) {
	for _, c := range []struct {
		name              string
		available         uint64
		reserved, request int64
		want              bool
	}{{"floor", 4 << 30, 0, 1, false}, {"available", 5 << 30, 0, 1 << 30, true}, {"pending", 5 << 30, 1 << 30, 1, false}, {"underflow", 1, 0, 1, false}, {"negative", 8 << 30, -1, 1, false}, {"overflow", 8 << 30, 1 << 62, 1 << 62, false}} {
		t.Run(c.name, func(t *testing.T) {
			if reserveFits(c.available, c.reserved, c.request) != c.want {
				t.Fatal("host reserve bypass")
			}
		})
	}
}
