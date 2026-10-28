package egress

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestConnectionLimitAndCloseUnblocksAccept(t *testing.T) {
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	limited := LimitListener(listener, 1)
	defer limited.Close()
	peer, e := net.Dial("tcp4", listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	first, e := limited.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer first.Close()
	waiting := make(chan error, 1)
	go func() {
		c, e := limited.Accept()
		if c != nil {
			c.Close()
		}
		waiting <- e
	}()
	select {
	case <-waiting:
		t.Fatal("admitted beyond limit")
	case <-time.After(20 * time.Millisecond):
	}
	limited.Close()
	select {
	case e := <-waiting:
		if !errors.Is(e, net.ErrClosed) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("accept leaked on shutdown")
	}
	first.Close() // double close must not leak/block a semaphore release
}
func TestRateAndByteBudget(t *testing.T) {
	var out bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	writer := &pacedWriter{w: &out, p: pacer{ctx: ctx, rate: 1024}}
	if _, e := writer.Write([]byte("secret")); e == nil || out.Len() != 0 {
		t.Fatal("cancelled transfer continued")
	}
	budget := &budgetWriter{w: &out, left: 4}
	if _, e := io.WriteString(budget, "12345"); e == nil || out.Len() != 0 {
		t.Fatal("output budget exceeded")
	}
	p := pacer{ctx: context.Background(), rate: 1024}
	if e := p.wait(1024); e != nil {
		t.Fatal(e)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	p.ctx = ctx
	start := time.Now()
	if e := p.wait(1024); !errors.Is(e, context.DeadlineExceeded) || time.Since(start) > 500*time.Millisecond {
		t.Fatal("pacing ignored cancellation", e)
	}
}
func FuzzAddressClassification(f *testing.F) {
	f.Add("::ffff:127.0.0.1")
	f.Add("8.8.8.8")
	f.Fuzz(func(t *testing.T, s string) {
		p := testPolicy()
		a, e := netip.ParseAddr(s)
		if e != nil {
			return
		}
		if p.Public(a) && (a.Is4In6() || a.Zone() != "" || !a.IsGlobalUnicast()) {
			t.Fatal("classification bypass")
		}
	})
}
