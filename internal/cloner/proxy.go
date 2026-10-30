//go:build linux

package cloner

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// meterProxy adds a per-job aggregate encrypted-transfer cap. The external
// broker remains the destination security boundary; this proxy cannot bypass it.
type meterProxy struct {
	listener    net.Listener
	server      *http.Server
	ctx         context.Context
	cancel      context.CancelFunc
	authority   string
	used        atomic.Int64
	maximum     atomic.Int64
	exceeded    atomic.Bool
	slots       chan struct{}
	mu          sync.Mutex
	connections map[net.Conn]bool
}

func newMeterProxy(ctx context.Context, authority string, max int64, cancel context.CancelFunc) (*meterProxy, error) {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		return nil, e
	}
	p := &meterProxy{listener: l, ctx: ctx, cancel: cancel, authority: authority, slots: make(chan struct{}, 4), connections: map[net.Conn]bool{}}
	p.maximum.Store(max)
	p.server = &http.Server{Handler: p, ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
	go func() { _ = p.server.Serve(l) }()
	return p, nil
}
func (p *meterProxy) close() {
	_ = p.server.Close()
	p.mu.Lock()
	defer p.mu.Unlock()
	for c := range p.connections {
		_ = c.Close()
	}
}
func (p *meterProxy) add(c net.Conn) { p.mu.Lock(); p.connections[c] = true; p.mu.Unlock() }
func (p *meterProxy) remove(c net.Conn) {
	_ = c.Close()
	p.mu.Lock()
	delete(p.connections, c)
	p.mu.Unlock()
}
func (p *meterProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "CONNECT" || r.Host != p.authority || r.URL.Host != p.authority || r.ContentLength > 0 {
		http.Error(w, "denied", 403)
		return
	}
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	default:
		http.Error(w, "limit", 429)
		return
	}
	// Fixed M05 guest broker listener. No caller-supplied upstream endpoint.
	c, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(p.ctx, "tcp4", "192.0.2.1:8443")
	if e != nil {
		http.Error(w, "denied", 502)
		return
	}
	p.add(c)
	defer p.remove(c)
	if d, ok := p.ctx.Deadline(); ok {
		_ = c.SetDeadline(d)
	}
	if _, e = io.WriteString(c, "CONNECT "+p.authority+" HTTP/1.1\r\nHost: "+p.authority+"\r\n\r\n"); e != nil {
		return
	}
	br := bufio.NewReaderSize(c, 4096)
	// Broker response is trusted bounded syntax. Never expose its error body.
	resp, e := http.ReadResponse(br, r)
	if e != nil || resp.StatusCode != 200 {
		http.Error(w, "denied", 502)
		return
	}
	guest, rw, e := w.(http.Hijacker).Hijack()
	if e != nil {
		return
	}
	p.add(guest)
	defer p.remove(guest)
	if d, ok := p.ctx.Deadline(); ok {
		_ = guest.SetDeadline(d)
	}
	if _, e = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); e != nil {
		return
	}
	if rw.Flush() != nil {
		return
	}
	done := make(chan struct{})
	go func() { _, _ = io.Copy(&meterWriter{p: p, w: c}, rw); _ = c.Close(); close(done) }()
	_, _ = io.Copy(&meterWriter{p: p, w: guest}, br)
	_ = guest.Close()
	_ = c.Close()
	<-done
}

type meterWriter struct {
	p *meterProxy
	w io.Writer
}

func (m *meterWriter) Write(b []byte) (int, error) {
	if m.p.used.Add(int64(len(b))) > m.p.maximum.Load() {
		m.p.exceeded.Store(true)
		m.p.cancel()
		return 0, errLimit
	}
	return m.w.Write(b)
}
