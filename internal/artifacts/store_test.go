package artifacts

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	s, e := OpenWithReserve(dir, 4096, 0)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func TestUploadQuarantine(t *testing.T) {
	s := newStore(t)
	b := Binding{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", 1, 1}
	id, token, e := s.Issue(b, 1024, time.Now().Add(time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Put(context.Background(), id, "wrong", strings.NewReader("x")); e == nil {
		t.Fatal("wrong token")
	}
	r, e := s.Put(context.Background(), id, token, strings.NewReader("opaque archive bytes"))
	if e != nil || r.Bytes != 20 {
		t.Fatal(r, e)
	}
	if _, e = s.Put(context.Background(), id, token, strings.NewReader("overwrite")); e == nil {
		t.Fatal("replay")
	}
	f, e := s.Read(r)
	if e != nil {
		t.Fatal(e)
	}
	data, _ := io.ReadAll(f)
	f.Close()
	if string(data) != "opaque archive bytes" {
		t.Fatal("bytes changed")
	}
	s.Revoke(id)
	if _, e = s.Read(r); e == nil {
		t.Fatal("revoked read")
	}
	reopened, e := OpenWithReserve(s.root, 4096, 0)
	if e != nil || reopened.used != 20 {
		t.Fatal("restart accounting", e)
	}
	if _, e = reopened.Put(context.Background(), id, token, strings.NewReader("x")); e == nil {
		t.Fatal("grant survived restart")
	}
}
func TestUploadLimitsAndFencing(t *testing.T) {
	for _, name := range []string{"oversize", "cancel", "revoked", "expiry", "capacity", "tamper"} {
		t.Run(name, func(t *testing.T) {
			s := newStore(t)
			id, token, e := s.Issue(Binding{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", 1, 1}, 1024, time.Now().Add(time.Minute))
			if e != nil {
				t.Fatal(e)
			}
			ctx := context.Background()
			input := []byte("payload")
			switch name {
			case "oversize":
				input = bytes.Repeat([]byte{'a'}, 1025)
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "revoked":
				s.Revoke(id)
			case "expiry":
				s.grants[id].expiry = time.Now().Add(-time.Second)
			case "capacity":
				if _, _, e := s.Issue(Binding{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", 1, 1}, 4096, time.Now().Add(time.Minute)); e == nil {
					t.Fatal("unreserved capacity")
				}
				return
			}
			r, e := s.Put(ctx, id, token, bytes.NewReader(input))
			if name == "tamper" {
				if e != nil {
					t.Fatal(e)
				}
				os.WriteFile(s.root+"/"+id, []byte("changed"), 0600)
				if _, e = s.Read(r); e == nil {
					t.Fatal("tamper accepted")
				}
				return
			}
			if e == nil {
				t.Fatal("upload accepted")
			}
		})
	}
}
