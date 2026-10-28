package egress

import (
	"context"
	"io"
	"net"
	"sync"
	"time"
)

// LimitListener bounds pre-CONNECT/slow-header sockets as well as admitted
// tunnels. Waiting for a slot never creates an additional handler goroutine.
func LimitListener(l net.Listener, max int) net.Listener {
	if max < 1 {
		max = 1
	}
	return &limitedListener{Listener: l, slots: make(chan struct{}, max), done: make(chan struct{})}
}

type limitedListener struct {
	net.Listener
	slots chan struct{}
	done  chan struct{}
	once  sync.Once
}

func (l *limitedListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}
func (l *limitedListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, e := l.Listener.Accept()
	if e != nil {
		<-l.slots
		return nil, e
	}
	return &limitedConn{Conn: c, release: func() { <-l.slots }}, nil
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error { e := c.Conn.Close(); c.once.Do(c.release); return e }

// Each direction has at most one 16 KiB burst and then is paced to its byte
// rate. Cancellation interrupts pacing, so revoked leases hold no rate slots.
type pacer struct {
	ctx  context.Context
	rate int64
	next time.Time
}

func (p *pacer) wait(n int) error {
	now := time.Now()
	if p.next.Before(now) {
		p.next = now
	}
	delay := time.Until(p.next)
	p.next = p.next.Add(time.Duration(int64(n) * int64(time.Second) / p.rate))
	if delay <= 0 {
		return p.ctx.Err()
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-t.C:
		return p.ctx.Err()
	case <-p.ctx.Done():
		return p.ctx.Err()
	}
}

type pacedReader struct {
	r io.Reader
	p pacer
}

func (r *pacedReader) Read(v []byte) (int, error) {
	if len(v) > 16384 {
		v = v[:16384]
	}
	if e := r.p.wait(len(v)); e != nil {
		return 0, e
	}
	return r.r.Read(v)
}

type pacedWriter struct {
	w io.Writer
	p pacer
}

func (w *pacedWriter) Write(v []byte) (int, error) {
	total := 0
	for len(v) > 0 {
		n := min(len(v), 16384)
		if e := w.p.wait(n); e != nil {
			return total, e
		}
		written, e := w.w.Write(v[:n])
		total += written
		v = v[written:]
		if e != nil {
			return total, e
		}
		if written != n {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
