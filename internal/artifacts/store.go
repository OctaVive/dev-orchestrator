// Package artifacts accepts opaque bytes. It never parses workload archives.
package artifacts

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"dev-orchestrator/internal/contracts"
	"encoding/hex"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var ErrDenied = errors.New("artifact upload denied")

type Binding struct {
	JobID        string
	DeploymentID string
	Attempt      int64
	Generation   int64
}
type Receipt struct {
	ObjectID string
	Digest   string
	Bytes    int64
	Binding  Binding
}
type grant struct {
	charge   int64
	consumed bool
	binding  Binding
	token    [32]byte
	expiry   time.Time
	limit    int64
	writing  bool
	receipt  *Receipt
	revoked  bool
}
type Store struct {
	minFree   uint64
	inflight  int
	promotion sync.Mutex
	mu        sync.Mutex
	root      string
	capacity  int64
	used      int64
	grants    map[string]*grant
}

// Open fails closed on insecure storage. Grants are intentionally revoked by
// restart; existing opaque files still count toward capacity and are quarantined.
func Open(root string, capacity int64) (*Store, error) { return OpenWithReserve(root, capacity, 4<<30) }

// OpenWithReserve is operator configuration, never repository input. The
// default Open preserves 4 GiB; isolated unit fixtures may use a smaller volume.
func OpenWithReserve(root string, capacity int64, minFree uint64) (*Store, error) {
	if minFree > 16<<30 {
		return nil, ErrDenied
	}
	if capacity < 1024 {
		return nil, ErrDenied
	}
	st, e := os.Lstat(root)
	if e != nil || !st.IsDir() || st.Mode()&0077 != 0 || st.Mode()&os.ModeSymlink != 0 {
		return nil, ErrDenied
	}
	s := &Store{minFree: minFree, root: root, capacity: capacity, grants: map[string]*grant{}}
	entries, e := os.ReadDir(root)
	if e != nil {
		return nil, e
	}
	for _, entry := range entries {
		st, e := entry.Info()
		if e != nil || !st.Mode().IsRegular() || entry.Type()&os.ModeSymlink != 0 {
			return nil, ErrDenied
		}
		s.used += st.Size()
		if s.used > capacity {
			return nil, ErrDenied
		}
	}
	return s, nil
}
func (s *Store) Issue(b Binding, limit int64, expiry time.Time) (id, token string, err error) {
	if !contracts.ValidJobID(b.JobID) || !contracts.ValidJobID(b.DeploymentID) || b.Attempt < 1 || b.Generation < 1 || limit < 1024 || limit > 1<<30 || !expiry.After(time.Now()) || expiry.After(time.Now().Add(30*time.Minute)) {
		return "", "", ErrDenied
	}
	raw := make([]byte, 32)
	if _, e := rand.Read(raw); e != nil {
		return "", "", e
	}
	token = hex.EncodeToString(raw)
	key := make([]byte, 16)
	if _, e := rand.Read(key); e != nil {
		return "", "", e
	}
	id = hex.EncodeToString(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit > s.capacity-s.used || len(s.grants) >= 128 || !hostReserve(s.root, s.used, limit, s.minFree) {
		return "", "", ErrDenied
	}
	s.used += limit
	s.grants[id] = &grant{charge: limit, binding: b, token: sha256.Sum256([]byte(token)), expiry: expiry, limit: limit}
	return id, token, nil
}
func (s *Store) Revoke(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if g := s.grants[id]; g != nil {
		g.revoked = true
		g.expiry = time.Now()
	}
}
func (s *Store) Put(ctx context.Context, id, token string, r io.Reader) (Receipt, error) {
	s.mu.Lock()
	g := s.grants[id]
	sum := sha256.Sum256([]byte(token))
	if g == nil || subtle.ConstantTimeCompare(sum[:], g.token[:]) != 1 || g.revoked || !time.Now().Before(g.expiry) || g.writing || g.consumed || g.receipt != nil || s.inflight >= 2 {
		s.mu.Unlock()
		return Receipt{}, ErrDenied
	}
	g.writing = true
	g.consumed = true
	s.inflight++
	s.mu.Unlock()
	var n int64
	defer func() {
		s.mu.Lock()
		g.writing = false
		s.inflight--
		s.used -= g.charge - n
		g.charge = n
		s.mu.Unlock()
	}()
	// Each grant owns one O_EXCL object. Interrupted objects remain charged and
	// quarantined; the same grant cannot overwrite or append them.
	file, e := os.OpenFile(filepath.Join(s.root, id), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return Receipt{}, ErrDenied
	}
	defer file.Close()
	hash := sha256.New()
	buf := make([]byte, 32768)
	for {
		if ctx.Err() != nil {
			return Receipt{}, ErrDenied
		}
		s.mu.Lock()
		active := !g.revoked && time.Now().Before(g.expiry)
		s.mu.Unlock()
		if !active {
			return Receipt{}, ErrDenied
		}
		read, e := r.Read(buf)
		if int64(read) > g.limit-n {
			return Receipt{}, ErrDenied
		}
		if read > 0 {
			written, w := io.MultiWriter(file, hash).Write(buf[:read])
			n += int64(written)
			if w != nil {
				return Receipt{}, ErrDenied
			}
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return Receipt{}, ErrDenied
		}
	}
	if n == 0 || file.Sync() != nil {
		return Receipt{}, ErrDenied
	}
	dir, e := os.Open(s.root)
	if e != nil {
		return Receipt{}, ErrDenied
	}
	e = dir.Sync()
	dir.Close()
	if e != nil {
		return Receipt{}, ErrDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil || g.revoked || !time.Now().Before(g.expiry) {
		return Receipt{}, ErrDenied
	}
	receipt := Receipt{id, "sha256:" + hex.EncodeToString(hash.Sum(nil)), n, g.binding}
	g.receipt = &receipt
	g.writing = false
	return receipt, nil
}
func (s *Store) Read(receipt Receipt) (*os.File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.grants[receipt.ObjectID]
	if g == nil || g.receipt == nil || *g.receipt != receipt || g.revoked {
		return nil, ErrDenied
	}
	f, e := os.Open(filepath.Join(s.root, receipt.ObjectID))
	if e != nil {
		return nil, ErrDenied
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, receipt.Bytes+1))
	if e != nil || n != receipt.Bytes || "sha256:"+hex.EncodeToString(h.Sum(nil)) != receipt.Digest {
		f.Close()
		return nil, ErrDenied
	}
	if _, e = f.Seek(0, 0); e != nil {
		f.Close()
		return nil, ErrDenied
	}
	return f, nil
}

// Handler is mounted on a dedicated TLS listener; it is not a management route.
// Server must set ReadHeaderTimeout/ReadTimeout/WriteTimeout and MaxHeaderBytes.
func (s *Store) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "PUT" || r.URL.RawQuery != "" || strings.Count(r.URL.Path, "/") != 1 {
			http.Error(w, "denied", 403)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/")
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == r.Header.Get("Authorization") || len(token) != 64 {
			http.Error(w, "denied", 403)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		receipt, e := s.Put(ctx, id, token, http.MaxBytesReader(w, r.Body, 1<<30))
		if e != nil {
			http.Error(w, "denied", 403)
			return
		}
		w.Header().Set("ETag", "\""+receipt.Digest+"\"")
		w.WriteHeader(http.StatusCreated)
	})
}

// Promote copies only already rehashed opaque bytes to a private artifact store.
// An orphan copy is never an admission record. Admission is committed separately
// after this durable copy succeeds; retrieval must check the metadata ledger.
func (s *Store) Promote(r Receipt, destination string) (string, error) {
	s.promotion.Lock()
	defer s.promotion.Unlock()
	st, e := os.Lstat(destination)
	if e != nil || !st.IsDir() || st.Mode()&0077 != 0 || st.Mode()&os.ModeSymlink != 0 {
		return "", ErrDenied
	}
	source, e := s.Read(r)
	if e != nil {
		return "", e
	}
	defer source.Close()
	name := strings.TrimPrefix(r.Digest, "sha256:")
	target := filepath.Join(destination, name)
	validateTarget := func() error {
		st, e := os.Lstat(target)
		if e != nil || !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
			return ErrDenied
		}
		f, e := os.Open(target)
		if e != nil {
			return ErrDenied
		}
		defer f.Close()
		actual, e := f.Stat()
		if e != nil || !os.SameFile(st, actual) {
			return ErrDenied
		}
		h := sha256.New()
		n, e := io.Copy(h, io.LimitReader(f, r.Bytes+1))
		if e != nil || n != r.Bytes || "sha256:"+hex.EncodeToString(h.Sum(nil)) != r.Digest {
			return ErrDenied
		}
		return nil
	}
	if _, e = os.Lstat(target); e == nil {
		if e = validateTarget(); e != nil {
			return "", e
		}
		return name, nil
	} else if !os.IsNotExist(e) {
		return "", ErrDenied
	}
	entries, e := os.ReadDir(destination)
	if e != nil {
		return "", ErrDenied
	}
	var used int64
	for _, entry := range entries {
		st, e := entry.Info()
		if e != nil || !st.Mode().IsRegular() || entry.Type()&os.ModeSymlink != 0 || st.Size() > (16<<30)-used {
			return "", ErrDenied
		}
		used += st.Size()
	}
	if r.Bytes > (16<<30)-used || !hostReserve(destination, 0, r.Bytes, s.minFree) {
		return "", ErrDenied
	}
	pending, e := os.CreateTemp(destination, ".pending-")
	if e != nil {
		return "", ErrDenied
	}
	defer pending.Close()
	defer os.Remove(pending.Name())
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(pending, h), source)
	if e != nil || n != r.Bytes || "sha256:"+hex.EncodeToString(h.Sum(nil)) != r.Digest || pending.Sync() != nil {
		return "", ErrDenied
	}
	if e = pending.Close(); e != nil {
		return "", ErrDenied
	}
	// Link publishes a fully fsynced inode without replacing existing content.
	if e = os.Link(pending.Name(), target); e != nil {
		if !os.IsExist(e) || validateTarget() != nil {
			return "", ErrDenied
		}
	}
	if e = os.Remove(pending.Name()); e != nil {
		return "", ErrDenied
	}
	dir, e := os.Open(destination)
	if e != nil {
		return "", ErrDenied
	}
	e = dir.Sync()
	dir.Close()
	if e != nil {
		return "", ErrDenied
	}
	return name, nil
}

func (s *Store) Receipt(id string) (Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.grants[id]
	if g == nil || g.receipt == nil || g.revoked {
		return Receipt{}, ErrDenied
	}
	return *g.receipt, nil
}

// Sweep releases only expired inactive grants and opaque objects older than the
// fixed 24-hour quarantine retention. Admitted copies live in another directory.
func (s *Store) Sweep(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, g := range s.grants {
		if g.writing || now.Before(g.expiry) {
			continue
		}
		g.revoked = true
		p := filepath.Join(s.root, id)
		st, e := os.Lstat(p)
		if e == nil {
			if !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
				return ErrDenied
			}
			if now.Sub(st.ModTime()) < 24*time.Hour {
				continue
			}
			if e = os.Remove(p); e != nil {
				return ErrDenied
			}
		} else if !os.IsNotExist(e) {
			return ErrDenied
		}
		s.used -= g.charge
		delete(s.grants, id)
	}
	entries, e := os.ReadDir(s.root)
	if e != nil {
		return ErrDenied
	}
	for _, entry := range entries {
		if _, active := s.grants[entry.Name()]; active {
			continue
		}
		st, e := entry.Info()
		if e != nil || !st.Mode().IsRegular() || entry.Type()&os.ModeSymlink != 0 {
			return ErrDenied
		}
		if now.Sub(st.ModTime()) < 24*time.Hour {
			continue
		}
		if len(entry.Name()) != 32 {
			return ErrDenied
		}
		if e = os.Remove(filepath.Join(s.root, entry.Name())); e != nil {
			return ErrDenied
		}
		s.used -= st.Size()
	}
	return nil
}

// Preserve management free space even when artifact retention reaches its cap.
// Broader host reservation/scheduling remains the controller's responsibility.
func hostReserve(root string, reserved, requested int64, minFree uint64) bool {
	var fs unix.Statfs_t
	if unix.Statfs(root, &fs) != nil || fs.Bsize <= 0 {
		return false
	}
	available := uint64(fs.Bavail) * uint64(fs.Bsize)
	return reserveFitsFloor(available, reserved, requested, minFree)
}
func reserveFits(available uint64, reserved, requested int64) bool {
	return reserveFitsFloor(available, reserved, requested, 4<<30)
}
func reserveFitsFloor(available uint64, reserved, requested int64, minFree uint64) bool {
	if reserved < 0 || requested < 0 || available < minFree {
		return false
	}
	free := available - minFree
	return uint64(reserved) <= free && uint64(requested) <= free-uint64(reserved)
}
