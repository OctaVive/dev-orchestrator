//go:build linux

package provisioner

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// No packet-capture dependency or production capture mode. AF_PACKET belongs
// to the selected namespace; files are private lab evidence in pcap format.
type labCapture struct {
	fd       int
	file     *os.File
	done     chan struct{}
	wg       sync.WaitGroup
	summary  map[string]int
	host     bool
	stopOnce sync.Once
	err      error
}

func startLabCapture(t *testing.T, n *hostNetwork, path string, host bool) *labCapture {
	t.Helper()
	fd := -1
	open := func() error {
		var e error
		fd, e = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0x0300)
		if e != nil {
			return e
		}
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 4<<20)
		index := 0
		if n != nil {
			i, e := net.InterfaceByName("tap0")
			if e != nil {
				unix.Close(fd)
				return e
			}
			index = i.Index
		}
		return unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: index, Protocol: 0x0300})
	}
	var e error
	if n != nil {
		e = inNamespace(n, open)
	} else {
		e = open()
	}
	if e != nil {
		if fd >= 0 {
			unix.Close(fd)
		}
		t.Fatal(e)
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		unix.Close(fd)
		t.Fatal(e)
	}
	header := []uint32{0xa1b2c3d4, 0x00040002, 0, 0, 65535, 1}
	for _, v := range header {
		if e = binary.Write(f, binary.LittleEndian, v); e != nil {
			t.Fatal(e)
		}
	}
	c := &labCapture{fd: fd, file: f, done: make(chan struct{}), summary: map[string]int{}, host: host}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer unix.Close(fd)
		defer func() {
			stats, e := unix.GetsockoptTpacketStats(fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
			if e != nil {
				c.err = e
			} else {
				c.summary["capture_drops"] = int(stats.Drops)
			}
		}()
		buffer := make([]byte, 65535)
		for {
			select {
			case <-c.done:
				return
			default:
			}
			poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			_, e := unix.Poll(poll, 50)
			if e != nil {
				continue
			}
			if poll[0].Revents&unix.POLLIN == 0 {
				continue
			}
			size, _, e := unix.Recvfrom(fd, buffer, 0)
			if e != nil || size < 14 {
				continue
			}
			data := buffer[:size]
			src, dst := "", ""
			protocol := binary.BigEndian.Uint16(data[12:14])
			if protocol == 0x0800 && len(data) >= 34 {
				src = net.IP(data[26:30]).String()
				dst = net.IP(data[30:34]).String()
			}
			if protocol == 0x86dd && len(data) >= 54 {
				src = net.IP(data[22:38]).String()
				dst = net.IP(data[38:54]).String()
			}
			guestMAC := string(data[6:12]) == string([]byte{2, 0, 0, 0, 0, 2}) || string(data[6:12]) == string([]byte{2, 0, 0, 0, 0, 3})
			escaped := guestMAC || strings.HasPrefix(src, "192.0.2.")
			selected := !host || escaped || strings.HasPrefix(src, "11.0.0.") || strings.HasPrefix(dst, "11.0.0.") || src == "2003::11" || dst == "2003::11" || src == "127.0.0.55" || dst == "127.0.0.55" || src == "127.0.0.56" || dst == "127.0.0.56" || src == "127.0.0.77" || dst == "127.0.0.77" || dst == "169.254.169.254"
			if !selected {
				continue
			}
			c.summary["frames"]++
			if host && escaped {
				c.summary["guest_frames_on_host"]++
			}
			if host && (dst == "127.0.0.77" || dst == "11.0.0.3" || dst == "169.254.169.254") {
				c.summary["protected_destination_frames"]++
			}
			if protocol == 0x86dd {
				c.summary["ipv6"]++
			}
			now := time.Now()
			for _, v := range []uint32{uint32(now.Unix()), uint32(now.Nanosecond() / 1000), uint32(size), uint32(size)} {
				if e := binary.Write(f, binary.LittleEndian, v); e != nil {
					c.err = e
					return
				}
			}
			if _, e := f.Write(data); e != nil {
				c.err = e
				return
			}
		}
	}()
	return c
}
func (c *labCapture) stop() {
	if c == nil {
		return
	}
	c.stopOnce.Do(func() {
		close(c.done)
		c.wg.Wait()
		if e := c.file.Sync(); e != nil {
			c.err = e
		}
		if e := c.file.Close(); e != nil {
			c.err = e
		}
	})
}
func labIngressDrops(ctxRules string) uint64 {
	var doc struct {
		Nftables []struct {
			Rule struct {
				Family string            `json:"family"`
				Chain  string            `json:"chain"`
				Expr   []json.RawMessage `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if json.Unmarshal([]byte(ctxRules), &doc) != nil {
		return 0
	}
	var total uint64
	for _, entry := range doc.Nftables {
		if entry.Rule.Family != "netdev" || entry.Rule.Chain != "ingress" {
			continue
		}
		drop := false
		var packets uint64
		for _, raw := range entry.Rule.Expr {
			var e map[string]json.RawMessage
			json.Unmarshal(raw, &e)
			if _, ok := e["drop"]; ok {
				drop = true
			}
			if counter, ok := e["counter"]; ok {
				var c struct{ Packets uint64 }
				json.Unmarshal(counter, &c)
				packets = c.Packets
			}
		}
		if drop {
			total += packets
		}
	}
	return total
}
func writeCaptureSummary(t *testing.T, dir string, guest, host *labCapture, drops uint64) {
	t.Helper()
	if guest.err != nil || host.err != nil || guest.summary["capture_drops"] != 0 || host.summary["capture_drops"] != 0 {
		t.Fatal("incomplete capture", guest.err, host.err, guest.summary, host.summary)
	}
	data, e := json.MarshalIndent(map[string]any{"guest": guest.summary, "host": host.summary, "ingress_drop_packets": drops}, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "capture-summary.json"), data, 0600); e != nil {
		t.Fatal(e)
	}
}
