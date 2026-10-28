package egress

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func testPolicy() Policy {
	return Policy{Version: 1, Hosts: []string{"example.com"}, MaxConnections: 2, MaxBytes: 65536, DurationSeconds: 30}
}
func TestPolicy(t *testing.T) {
	p := testPolicy()
	if p.Validate() != nil {
		t.Fatal("valid policy")
	}
	for _, a := range []string{"example.com", "EXAMPLE.com:443", "example.com:80", "127.0.0.1:443", "[::1]:443", "user@example.com:443", "example.com.:443", "example%2ecom:443", "other.example:443", "example.com:0443"} {
		if _, e := p.Authority(a); e == nil {
			t.Errorf("accepted %q", a)
		}
	}
	if h, e := p.Authority("example.com:443"); e != nil || h != "example.com" {
		t.Fatal("approved authority")
	}
	p.Hosts = nil
	if p.Validate() != nil {
		t.Fatal("empty allowlist is valid default deny")
	}
	if _, e := p.Authority("example.com:443"); e == nil {
		t.Fatal("empty allowlist allowed")
	}
	p.Version = 2
	if p.Validate() == nil {
		t.Fatal("unknown version")
	}
	p = testPolicy()
	p.Hosts = append(p.Hosts, p.Hosts[0])
	if p.Validate() == nil {
		t.Fatal("duplicate")
	}
}
func TestAddressClassification(t *testing.T) {
	p := testPolicy()
	for _, s := range []string{"0.0.0.0", "10.1.2.3", "100.100.100.200", "127.0.0.1", "169.254.169.254", "172.31.255.255", "192.168.1.1", "192.0.0.9", "192.0.2.1", "198.19.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "255.255.255.255", "::", "::1", "::ffff:8.8.8.8", "64:ff9b::808:808", "fc00::1", "fe80::1", "ff02::1", "2001:db8::1", "2001::1", "2002::1", "3fff::1"} {
		if p.Public(netip.MustParseAddr(s)) {
			t.Errorf("public: %s", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !p.Public(netip.MustParseAddr(s)) {
			t.Errorf("denied control: %s", s)
		}
	}
	p.Deny = []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24")}
	if p.Public(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("infrastructure override")
	}
}
func FuzzAuthority(f *testing.F) {
	f.Add("example.com:443")
	f.Fuzz(func(t *testing.T, s string) {
		p := testPolicy()
		if h, e := p.Authority(s); e == nil && (s != "example.com:443" || h != "example.com") {
			t.Fatal("authority bypass")
		}
	})
}

func TestDecodePolicy(t *testing.T) {
	for _, s := range []string{`{"version":1,"version":1}`, `{"version":2}`, `{} {}`, `{"unexpected":1}`} {
		if _, e := DecodePolicy(strings.NewReader(s)); e == nil {
			t.Fatal("ambiguous policy accepted")
		}
	}
}

func FuzzPolicyDecode(f *testing.F) {
	f.Add(`{"version":1,"hosts":["example.com"],"deny":[],"max_connections":4,"max_bytes":65536,"duration_seconds":30}`)
	f.Add(`{"version":1,"version":2}`)
	f.Fuzz(func(t *testing.T, input string) {
		p, e := DecodePolicy(strings.NewReader(input))
		if e != nil {
			return
		}
		if p.Validate() != nil {
			t.Fatal("invalid decoded policy")
		}
		data, e := json.Marshal(p)
		if e != nil {
			t.Fatal(e)
		}
		again, e := DecodePolicy(bytes.NewReader(data))
		if e != nil || again.Hash() != p.Hash() {
			t.Fatal("policy identity did not survive serialization")
		}
	})
}
