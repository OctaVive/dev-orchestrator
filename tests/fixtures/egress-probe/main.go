//go:build linux

// Fixed credential-free guest-root packet fixtures. Not a platform executable.
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
)

func sum(v []byte) uint16 {
	var s uint32
	for len(v) > 1 {
		s += uint32(binary.BigEndian.Uint16(v))
		v = v[2:]
	}
	if len(v) > 0 {
		s += uint32(v[0]) << 8
	}
	for s>>16 != 0 {
		s = (s & 65535) + (s >> 16)
	}
	return ^uint16(s)
}
func frame(kind uint16, payload []byte) []byte {
	b := append([]byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, byte(kind >> 8), byte(kind)}, payload...)
	return b
}
func v4(dst string, proto byte, data []byte) []byte {
	src := net.ParseIP("192.0.2.2").To4()
	target := net.ParseIP(dst).To4()
	pseudo := append(append([]byte{}, src...), target...)
	pseudo = append(pseudo, 0, proto, byte(len(data)>>8), byte(len(data)))
	pseudo = append(pseudo, data...)
	if proto == 6 {
		binary.BigEndian.PutUint16(data[16:], sum(pseudo))
	} else {
		binary.BigEndian.PutUint16(data[6:], sum(pseudo))
	}
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], uint16(20+len(data)))
	h[8] = 64
	h[9] = proto
	copy(h[12:], src)
	copy(h[16:], target)
	binary.BigEndian.PutUint16(h[10:], sum(h))
	return frame(0x0800, append(h, data...))
}
func tcp() []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b, 44444)
	binary.BigEndian.PutUint16(b[2:], 443)
	b[12] = 0x50
	b[13] = 2
	binary.BigEndian.PutUint16(b[14:], 4096)
	return b
}
func udp(port uint16, data []byte) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b, 44445)
	binary.BigEndian.PutUint16(b[2:], port)
	binary.BigEndian.PutUint16(b[4:], uint16(8+len(data)))
	return append(b, data...)
}
func v6(src, dst string, next byte, data []byte) []byte {
	s, d := net.ParseIP(src).To16(), net.ParseIP(dst).To16()
	pseudo := append(append([]byte{}, s...), d...)
	pseudo = append(pseudo, 0, 0, byte(len(data)>>8), byte(len(data)), 0, 0, 0, next)
	pseudo = append(pseudo, data...)
	off := 2
	if next == 6 {
		off = 16
	}
	binary.BigEndian.PutUint16(data[off:], sum(pseudo))
	h := make([]byte, 40)
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:], uint16(len(data)))
	h[6] = next
	h[7] = 255
	copy(h[8:], s)
	copy(h[24:], d)
	return frame(0x86dd, append(h, data...))
}
func report(name string, denied bool) {
	if denied {
		fmt.Printf("%s OBSERVED-DENY\n", name)
	} else {
		fmt.Printf("%s UNEXPECTED-ALLOW\n", name)
	}
}
func connect(authority string) (net.Conn, *bufio.Reader, bool) {
	c, e := net.DialTimeout("tcp", "192.0.2.1:8443", 3*time.Second)
	if e != nil {
		return nil, nil, false
	}
	c.SetDeadline(time.Now().Add(8 * time.Second))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
	r := bufio.NewReader(c)
	line, e := r.ReadString('\n')
	if e != nil {
		c.Close()
		return nil, nil, false
	}
	ok := strings.Contains(line, " 200 ")
	for {
		line, e = r.ReadString('\n')
		if e != nil {
			c.Close()
			return nil, nil, false
		}
		if line == "\r\n" {
			break
		}
	}
	if !ok {
		c.Close()
		return nil, nil, false
	}
	return c, r, true
}

type buffered struct {
	net.Conn
	r *bufio.Reader
}

func (c *buffered) Read(v []byte) (int, error) { return c.r.Read(v) }
func tunnel(sni string) (*tls.Conn, bool) {
	c, r, ok := connect("ok.m05.test:443")
	if !ok {
		return nil, false
	}
	data, e := os.ReadFile("/build-ca.pem")
	if e != nil {
		c.Close()
		return nil, false
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(data)
	t := tls.Client(&buffered{c, r}, &tls.Config{RootCAs: roots, ServerName: sni})
	if t.Handshake() != nil {
		t.Close()
		return nil, false
	}
	return t, true
}
func protocols() {
	c, _, ok := connect("unapproved.m05.test:443")
	report("N08-arbitrary-CONNECT", !ok)
	if c != nil {
		c.Close()
	}
	c, _, ok = connect("11.0.0.1:443")
	report("N08-IP-CONNECT", !ok)
	if c != nil {
		c.Close()
	}
	bad, ok := tunnel("wrong.m05.test")
	report("N07-SNI", !ok)
	if bad != nil {
		bad.Close()
	}
	for _, p := range []struct{ name, request string }{
		{"N08-nested-CONNECT", "CONNECT private.m05.test:443 HTTP/1.1\r\nHost: private.m05.test:443\r\n\r\n"},
		{"N07-HTTP-authority", "GET /wrong-authority-target HTTP/1.1\r\nHost: private.m05.test\r\n\r\n"},
		{"U08-oversized-header", "GET /oversized-request HTTP/1.1\r\nHost: ok.m05.test\r\nX-Large: " + strings.Repeat("x", 40000) + "\r\n\r\n"},
	} {
		t, ok := tunnel("ok.m05.test")
		if !ok {
			report(p.name, false)
			continue
		}
		io.WriteString(t, p.request)
		data, _ := io.ReadAll(t)
		t.Close()
		report(p.name, len(data) == 0)
	}
	t, ok := tunnel("ok.m05.test")
	if ok {
		io.WriteString(t, "GET /reuse-first HTTP/1.1\r\nHost: ok.m05.test\r\n\r\nGET /reuse-second HTTP/1.1\r\nHost: private.m05.test\r\n\r\n")
		reader := bufio.NewReader(t)
		resp, e := http.ReadResponse(reader, nil)
		first := false
		if e == nil {
			data, e := io.ReadAll(resp.Body)
			resp.Body.Close()
			first = e == nil && resp.StatusCode == 200 && strings.Contains(string(data), "M05 controlled")
		}
		_, second := http.ReadResponse(reader, nil)
		report("N08-authority-reuse", first && second != nil)
		t.Close()
	} else {
		report("N08-authority-reuse", false)
	}
	t, ok = tunnel("ok.m05.test")
	if ok {
		io.WriteString(t, "GET /large HTTP/1.1\r\nHost: ok.m05.test\r\n\r\n")
		resp, e := http.ReadResponse(bufio.NewReader(t), nil)
		bounded := false
		if e == nil {
			data, e := io.ReadAll(resp.Body)
			resp.Body.Close()
			bounded = e != nil && len(data) <= 1048576 && len(data) > 65536
		}
		report("U08-response-budget", bounded)
		t.Close()
	} else {
		report("U08-response-budget", false)
	}
	var held []*tls.Conn
	for i := 0; i < 4; i++ {
		t, ok := tunnel("ok.m05.test")
		if ok {
			held = append(held, t)
		}
	}
	c, _, ok = connect("ok.m05.test:443")
	report("U08-concurrency", len(held) == 4 && !ok)
	if c != nil {
		c.Close()
	}
	for _, t := range held {
		t.Close()
	}
	c, e := net.DialTimeout("tcp", "192.0.2.1:8443", 3*time.Second)
	if e != nil {
		report("U08-slow-header", false)
		return
	}
	c.SetDeadline(time.Now().Add(8 * time.Second))
	io.WriteString(c, "CONNE")
	start := time.Now()
	data, e := io.ReadAll(c)
	elapsed := time.Since(start)
	c.Close()
	timedout := false
	if ne, ok := e.(net.Error); ok {
		timedout = ne.Timeout()
	}
	fmt.Printf("U08-slow-header-evidence elapsed_ms=%d response_bytes=%d timeout=%t\n", elapsed.Milliseconds(), len(data), timedout)
	report("U08-slow-header", !timedout && !strings.HasPrefix(string(data), "HTTP/1.1 200") && len(data) < 4096 && elapsed >= 4*time.Second && elapsed < 7*time.Second)
}
func main() {
	protocols()
	iface, e := net.InterfaceByName("eth0")
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	fd, e := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 0x0300)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	defer syscall.Close(fd)
	dns := []byte{0x5a, 0x5a, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 2, 'o', 'k', 3, 'm', '0', '5', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1}
	ra := make([]byte, 16)
	ra[0] = 134
	ra[4] = 64
	binary.BigEndian.PutUint16(ra[6:], 1800)
	raFrame := v6("fe80::2", "ff02::1", 58, ra)
	copy(raFrame[:6], []byte{0x33, 0x33, 0, 0, 0, 1})
	fixtures := []struct {
		name string
		data []byte
	}{
		{"N02-direct-public-v4", v4("11.0.0.1", 6, tcp())},
		{"N02-direct-public-v6", v6("2003::2", "2003::11", 6, tcp())},
		{"N03-private-canary", v4("127.0.0.77", 6, tcp())},
		{"N03-infrastructure-canary", v4("11.0.0.3", 6, tcp())},
		{"N03-metadata", v4("169.254.169.254", 6, tcp())},
		{"N04-UDP-DNS", v4("11.0.0.1", 17, udp(53, dns))},
		{"N04-UDP-443", v4("11.0.0.1", 17, udp(443, []byte("M05 UDP QUIC transport canary")))},
		{"N05-IPv6-RA", raFrame},
	}
	for _, f := range fixtures {
		for i := 0; i < 3; i++ {
			if e = syscall.Sendto(fd, f.data, 0, &syscall.SockaddrLinklayer{Ifindex: iface.Index, Protocol: 0x0300}); e != nil {
				fmt.Fprintln(os.Stderr, e)
				os.Exit(1)
			}
			time.Sleep(10 * time.Millisecond)
		}
		fmt.Printf("%s SENT\n", f.name)
	}
}
