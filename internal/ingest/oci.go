// Package ingest parses workload artifacts only inside disposable ingest VMs.
// Management must never call Validate on an untrusted artifact.
package ingest

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"dev-orchestrator/internal/contracts"
)

var ErrDenied = errors.New("artifact denied")
var ErrLimit = errors.New("artifact limit")

const manifestType = "application/vnd.oci.image.manifest.v1+json"
const configType = "application/vnd.oci.image.config.v1+json"
const layerType = "application/vnd.oci.image.layer.v1.tar"

type descriptor struct {
	MediaType    string          `json:"mediaType"`
	Digest       string          `json:"digest"`
	Size         int64           `json:"size"`
	URLs         []string        `json:"urls,omitempty"`
	Data         json.RawMessage `json:"data,omitempty"`
	ArtifactType string          `json:"artifactType,omitempty"`
	Platform     *struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
	} `json:"platform,omitempty"`
}
type Verified struct {
	LayoutPath    string // guest-local; never part of a wire result
	ImageDigest   string
	ArchiveDigest string
	Entries       int
	ExpandedBytes int64
}
type counted struct {
	r    io.Reader
	left int64
}

func (c *counted) Read(p []byte) (int, error) {
	if c.left <= 0 {
		var b [1]byte
		n, e := c.r.Read(b[:])
		if n > 0 {
			return 0, ErrLimit
		}
		return 0, e
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, e := c.r.Read(p)
	c.left -= int64(n)
	return n, e
}
func safeName(s string, l contracts.ArtifactLimits) (string, error) {
	s = strings.TrimSuffix(strings.TrimPrefix(s, "./"), "/")
	if s == "" || s == "." || len(s) > l.PathBytes || strings.HasPrefix(s, "/") || strings.ContainsAny(s, "\\\x00:\r\n\t") || path.Clean(s) != s || strings.Count(s, "/")+1 > l.Depth {
		return "", ErrDenied
	}
	for _, c := range s {
		if c < 32 || c == 127 {
			return "", ErrDenied
		}
	}
	if s == ".." || strings.HasPrefix(s, "../") {
		return "", ErrDenied
	}
	return s, nil
}
func readJSON(p string, max int64, v any) error {
	f, e := os.Open(p)
	if e != nil {
		return ErrDenied
	}
	defer f.Close()
	b, e := contracts.ReadJSONObject(f, max)
	if e != nil {
		return ErrDenied
	}
	if int64(len(b)) > max {
		return ErrLimit
	}
	if e = canonicalJSON(b, reflect.TypeOf(v).Elem()); e != nil {
		return e
	}
	if e = json.Unmarshal(b, v); e != nil {
		return ErrDenied
	}
	return nil
}

// Validate never extracts a layer. Outer layout regular blobs are copied only
// into a private guest scratch directory with server-chosen paths.
func Validate(r io.Reader, scratch string, l contracts.ArtifactLimits) (Verified, error) {
	var result Verified
	if l.Validate() != nil {
		return result, ErrDenied
	}
	dir, e := os.MkdirTemp(scratch, "oci-")
	if e != nil {
		return result, e
	}
	success := false
	defer func() {
		if !success {
			os.RemoveAll(dir)
		}
	}()
	if e = os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0700); e != nil {
		return result, e
	}
	hasher := sha256.New()
	input := &counted{r: io.TeeReader(r, hasher), left: l.UploadBytes}
	tr := tar.NewReader(input)
	files := map[string]string{}
	seen := map[string]bool{}
	var total int64
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return result, ErrDenied
		}
		result.Entries++
		if result.Entries > l.Entries {
			return result, ErrLimit
		}
		if h.Name == "./" && h.Typeflag == tar.TypeDir {
			continue
		}
		name, e := safeName(h.Name, l)
		if e != nil {
			return result, e
		}
		if seen[name] {
			return result, ErrDenied
		}
		seen[name] = true
		if h.Format == tar.FormatGNU || len(h.PAXRecords) > 0 || h.Size < 0 {
			return result, ErrDenied
		}
		if h.Typeflag == tar.TypeDir {
			if name != "blobs" && name != "blobs/sha256" {
				return result, ErrDenied
			}
			continue
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			return result, ErrDenied
		}
		if name != "index.json" && name != "oci-layout" && !(strings.HasPrefix(name, "blobs/sha256/") && len(strings.TrimPrefix(name, "blobs/sha256/")) == 64 && contracts.ValidDigest("sha256:"+strings.TrimPrefix(name, "blobs/sha256/"))) {
			return result, ErrDenied
		}
		if h.Size > l.UploadBytes-total {
			return result, ErrLimit
		}
		total += h.Size
		if (name == "index.json" || name == "oci-layout") && h.Size > l.JSONBytes {
			return result, ErrLimit
		}
		file := filepath.Join(dir, name)
		f, e := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return result, e
		}
		hash := sha256.New()
		_, e = io.CopyN(io.MultiWriter(f, hash), tr, h.Size)
		ce := f.Close()
		if e != nil || ce != nil {
			return result, ErrDenied
		}
		if strings.HasPrefix(name, "blobs/") && "sha256:"+hex.EncodeToString(hash.Sum(nil)) != "sha256:"+path.Base(name) {
			return result, ErrDenied
		}
		files[name] = file
	}
	// Drain padding and reject nonzero trailing data/second archives. Bytes are
	// still counted and included in the transport digest.
	tail := make([]byte, 32768)
	for {
		n, e := input.Read(tail)
		for _, b := range tail[:n] {
			if b != 0 {
				return result, ErrDenied
			}
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return result, e
		}
	}
	result.ArchiveDigest = "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	var layout struct {
		Version string `json:"imageLayoutVersion"`
	}
	if readJSON(files["oci-layout"], l.JSONBytes, &layout) != nil || layout.Version != "1.0.0" {
		return result, ErrDenied
	}
	var index struct {
		SchemaVersion int             `json:"schemaVersion"`
		MediaType     string          `json:"mediaType"`
		Manifests     []descriptor    `json:"manifests"`
		Subject       json.RawMessage `json:"subject"`
		ArtifactType  string          `json:"artifactType,omitempty"`
	}
	if readJSON(files["index.json"], l.JSONBytes, &index) != nil || index.SchemaVersion != 2 || len(index.Manifests) != 1 || len(index.Subject) > 0 || index.ArtifactType != "" {
		return result, ErrDenied
	}
	used := map[string]bool{"oci-layout": true, "index.json": true}
	check := func(d descriptor, media string) (string, error) {
		if d.MediaType != media || !contracts.ValidDigest(d.Digest) || d.Size < 0 || len(d.URLs) > 0 || len(d.Data) > 0 || d.ArtifactType != "" {
			return "", ErrDenied
		}
		if d.Platform != nil && (d.Platform.Architecture != "amd64" || d.Platform.OS != "linux") {
			return "", ErrDenied
		}
		key := "blobs/sha256/" + d.Digest[7:]
		p, ok := files[key]
		if !ok {
			return "", ErrDenied
		}
		st, e := os.Stat(p)
		if e != nil || st.Size() != d.Size {
			return "", ErrDenied
		}
		used[key] = true
		return p, nil
	}
	mp, e := check(index.Manifests[0], manifestType)
	if e != nil {
		return result, e
	}
	var m struct {
		SchemaVersion int             `json:"schemaVersion"`
		MediaType     string          `json:"mediaType"`
		Config        descriptor      `json:"config"`
		Layers        []descriptor    `json:"layers"`
		Subject       json.RawMessage `json:"subject"`
		ArtifactType  string          `json:"artifactType,omitempty"`
	}
	if readJSON(mp, l.JSONBytes, &m) != nil || m.SchemaVersion != 2 || m.MediaType != manifestType || len(m.Layers)+2 > l.Descriptors || len(m.Subject) > 0 || m.ArtifactType != "" {
		return result, ErrDenied
	}
	cp, e := check(m.Config, configType)
	if e != nil {
		return result, e
	}
	var cfg struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
		RootFS       struct {
			Type    string   `json:"type"`
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
		Config struct {
			User    string                     `json:"User"`
			Volumes map[string]json.RawMessage `json:"Volumes"`
			OnBuild []string                   `json:"OnBuild"`
			Env     []string                   `json:"Env"`
		} `json:"config"`
	}
	if readJSON(cp, l.JSONBytes, &cfg) != nil || cfg.Architecture != "amd64" || cfg.OS != "linux" || cfg.RootFS.Type != "layers" || len(cfg.RootFS.DiffIDs) != len(m.Layers) || len(cfg.Config.Volumes) > 0 || len(cfg.Config.OnBuild) > 0 {
		return result, ErrDenied
	}
	// Runtime images must declare a non-root user. Named users are not accepted
	// until runtime policy can resolve them independently.
	user := strings.Split(cfg.Config.User, ":")[0]
	uid, uidErr := strconv.ParseUint(user, 10, 16)
	if uidErr != nil || uid == 0 || strings.Trim(user, "0123456789") != "" {
		return result, ErrDenied
	}
	links := map[string]string{}
	types := map[string]byte{}
	for i, d := range m.Layers {
		if d.MediaType != layerType && d.MediaType != layerType+"+gzip" {
			return result, ErrDenied
		}
		lp, e := check(d, d.MediaType)
		if e != nil {
			return result, e
		}
		diff, n, entries, e := validateLayer(lp, d, l, l.ExpandedBytes-result.ExpandedBytes, links, types)
		if e != nil {
			return result, e
		}
		if diff != cfg.RootFS.DiffIDs[i] {
			return result, ErrDenied
		}
		result.ExpandedBytes += n
		result.Entries += entries
		if result.Entries > l.Entries {
			return result, ErrLimit
		}
	}
	if len(used) != len(files) {
		return result, ErrDenied
	}
	result.ImageDigest = index.Manifests[0].Digest
	result.LayoutPath = dir
	if e = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		mode := os.FileMode(0400)
		if info.IsDir() {
			mode = 0500
		}
		return os.Chmod(p, mode)
	}); e != nil {
		return Verified{}, e
	}
	success = true
	return result, nil
}
func validateLayer(file string, d descriptor, l contracts.ArtifactLimits, remaining int64, links map[string]string, types map[string]byte) (string, int64, int, error) {
	f, e := os.Open(file)
	if e != nil {
		return "", 0, 0, e
	}
	defer f.Close()
	var source io.Reader = f
	var compressed *bufio.Reader
	if strings.HasSuffix(d.MediaType, "+gzip") {
		compressed = bufio.NewReader(f)
		gz, e := gzip.NewReader(compressed)
		if e != nil {
			return "", 0, 0, ErrDenied
		}
		defer gz.Close()
		gz.Multistream(false)
		source = gz
	}
	max := l.LayerBytes
	if remaining < max {
		max = remaining
	}
	if d.Size > 0 && d.Size <= max/l.Ratio {
		max = d.Size * l.Ratio
	}
	counter := &counted{r: source, left: max}
	hash := sha256.New()
	reader := io.TeeReader(counter, hash)
	tr := tar.NewReader(reader)
	count := 0
	seen := map[string]bool{}
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", 0, count, ErrDenied
		}
		count++
		if count > l.Entries {
			return "", 0, count, ErrLimit
		}
		if (h.Name == "./" || h.Name == ".") && h.Typeflag == tar.TypeDir && h.Size == 0 {
			continue
		}
		name, e := safeName(h.Name, l)
		if e != nil {
			return "", 0, count, e
		}
		if seen[name] || h.Format == tar.FormatGNU || len(h.PAXRecords) > 0 || h.Mode&06000 != 0 {
			return "", 0, count, ErrDenied
		}
		seen[name] = true
		for ancestor := path.Dir(name); ancestor != "."; ancestor = path.Dir(ancestor) {
			if t, ok := types[ancestor]; ok && t != tar.TypeDir {
				return "", 0, count, ErrDenied
			}
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA && h.Size != 0 {
			return "", 0, count, ErrDenied
		}
		if strings.HasPrefix(path.Base(name), ".wh.") {
			if h.Typeflag != tar.TypeReg || h.Size != 0 {
				return "", 0, count, ErrDenied
			}
			if len(links) > 0 {
				return "", 0, count, ErrDenied
			}
			continue
		}
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeRegA, tar.TypeDir:
			delete(links, name)
		case tar.TypeSymlink, tar.TypeLink:
			target := h.Linkname
			if h.Typeflag == tar.TypeSymlink {
				target = path.Join(path.Dir(name), target)
			}
			target, e = safeName(target, l)
			if e != nil || strings.HasPrefix(h.Linkname, "/") {
				return "", 0, count, ErrDenied
			}
			if h.Typeflag == tar.TypeLink && types[target] != tar.TypeReg {
				return "", 0, count, ErrDenied
			}
			links[name] = target
		default:
			return "", 0, count, ErrDenied
		}
		if h.Typeflag != tar.TypeDir {
			for existing := range types {
				if strings.HasPrefix(existing, name+"/") {
					return "", 0, count, ErrDenied
				}
			}
		}
		types[name] = h.Typeflag
		// Reject cycles and link ancestors conservatively, including forward links.
		for start := range links {
			cur := start
			visited := map[string]bool{}
			for {
				if visited[cur] {
					return "", 0, count, ErrDenied
				}
				visited[cur] = true
				next, ok := links[cur]
				if !ok {
					break
				}
				for a := path.Dir(next); a != "."; a = path.Dir(a) {
					if _, ok := links[a]; ok {
						return "", 0, count, ErrDenied
					}
				}
				cur = next
			}
		}
		if _, e = io.Copy(io.Discard, tr); e != nil {
			return "", 0, count, e
		}
	}
	// Hash the entire uncompressed stream, checking checksums and final padding.
	buf := make([]byte, 32768)
	for {
		n, e := reader.Read(buf)
		if !bytes.Equal(buf[:n], make([]byte, n)) {
			return "", 0, count, ErrDenied
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", 0, count, e
		}
	}
	if compressed != nil {
		if _, e := compressed.ReadByte(); e != io.EOF {
			return "", 0, count, ErrDenied
		}
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), max - counter.left, count, nil
}

// Release discards a verified guest-local view after its scanner is finished.
func Release(v Verified) {
	if v.LayoutPath == "" {
		return
	}
	_ = filepath.Walk(v.LayoutPath, func(p string, st os.FileInfo, e error) error {
		if e == nil && st.IsDir() {
			return os.Chmod(p, 0700)
		}
		return e
	})
	_ = os.RemoveAll(v.LayoutPath)
}

// OCI permits extensions, but aliases of known JSON keys must retain their
// exact specification spelling. Duplicate exact keys were already rejected.
func canonicalJSON(b []byte, t reflect.Type) error {
	if t == reflect.TypeOf(json.RawMessage{}) {
		return nil
	}
	if t.Kind() == reflect.Pointer {
		if bytes.Equal(b, []byte("null")) {
			return nil
		}
		return canonicalJSON(b, t.Elem())
	}
	if t.Kind() == reflect.Slice {
		var values []json.RawMessage
		if json.Unmarshal(b, &values) != nil {
			return ErrDenied
		}
		for _, value := range values {
			if e := canonicalJSON(value, t.Elem()); e != nil {
				return e
			}
		}
		return nil
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	var values map[string]json.RawMessage
	if json.Unmarshal(b, &values) != nil {
		return ErrDenied
	}
	for key, value := range values {
		for n := 0; n < t.NumField(); n++ {
			field := t.Field(n)
			tag := strings.Split(field.Tag.Get("json"), ",")[0]
			if strings.EqualFold(key, tag) {
				if key != tag {
					return ErrDenied
				}
				if e := canonicalJSON(value, field.Type); e != nil {
					return e
				}
			}
		}
	}
	return nil
}
