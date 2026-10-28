// Package egress implements the external build HTTPS policy boundary.
package egress

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"
)

var ErrDenied = errors.New("egress denied")

// DecodePolicy rejects duplicate keys, unknown fields and trailing documents.
func DecodePolicy(r io.Reader) (Policy, error) {
	var p Policy
	data, err := io.ReadAll(io.LimitReader(r, 65537))
	if err != nil || len(data) > 65536 || !utf8.Valid(data) {
		return p, ErrDenied
	}
	d := json.NewDecoder(bytes.NewReader(data))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return p, ErrDenied
	}
	seen := map[string]bool{}
	for d.More() {
		tok, err = d.Token()
		key, ok := tok.(string)
		if err != nil || !ok || seen[key] {
			return p, ErrDenied
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return p, ErrDenied
		}
	}
	if _, err = d.Token(); err != nil {
		return p, ErrDenied
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || p.Validate() != nil {
		return Policy{}, ErrDenied
	}
	return p, nil
}

type Policy struct {
	Version         int            `json:"version"`
	Hosts           []string       `json:"hosts"`
	Deny            []netip.Prefix `json:"deny"`
	MaxConnections  int            `json:"max_connections"`
	MaxBytes        int64          `json:"max_bytes"`
	DurationSeconds int            `json:"duration_seconds"`
	BytesPerSecond  int64          `json:"bytes_per_second,omitempty"`
}

func hostname(h string) bool {
	if len(h) > 253 || !strings.Contains(h, ".") || strings.ToLower(h) != h {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	_, err := netip.ParseAddr(h)
	return err != nil
}

func (p Policy) Validate() error {
	if p.Version != 1 || p.MaxConnections < 1 || p.MaxConnections > 1024 || p.MaxBytes < 1 || p.MaxBytes > 1<<30 || p.DurationSeconds < 1 || p.DurationSeconds > 3600 || p.BytesPerSecond < 0 || p.BytesPerSecond > 64<<20 || p.BytesPerSecond > 0 && p.BytesPerSecond < 1024 {
		return ErrDenied
	}
	seen := map[string]bool{}
	for _, h := range p.Hosts {
		if !hostname(h) || seen[h] {
			return ErrDenied
		}
		seen[h] = true
	}
	for _, n := range p.Deny {
		if !n.IsValid() || n != n.Masked() {
			return ErrDenied
		}
	}
	return nil
}

func (p Policy) Hash() string {
	b, _ := json.Marshal(p)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func (p Policy) Duration() time.Duration { return time.Duration(p.DurationSeconds) * time.Second }
func (p Policy) Rate() int64 {
	if p.BytesPerSecond == 0 {
		return 1 << 20
	}
	return p.BytesPerSecond
}
func (p Policy) Authority(a string) (string, error) {
	h, port, err := net.SplitHostPort(a)
	if err != nil || port != "443" || !hostname(h) {
		return "", ErrDenied
	}
	for _, allowed := range p.Hosts {
		if h == allowed {
			return h, nil
		}
	}
	return "", ErrDenied
}

// Conservative special-purpose registry: IPv6 is restricted to global unicast
// 2000::/3, with protocol assignment, documentation and transition space denied.
var special = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range strings.Fields("0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/3 2001::/23 2001:db8::/32 2002::/16 3fff::/20") {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func (p Policy) Public(a netip.Addr) bool {
	if !a.IsValid() || a.Is4In6() || a.Zone() != "" || !a.IsGlobalUnicast() {
		return false
	}
	if a.Is6() && !netip.MustParsePrefix("2000::/3").Contains(a) {
		return false
	}
	for _, n := range append(append([]netip.Prefix{}, special...), p.Deny...) {
		if n.Contains(a) {
			return false
		}
	}
	return true
}
