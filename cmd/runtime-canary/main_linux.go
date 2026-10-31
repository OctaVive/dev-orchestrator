// runtime-canary is a trusted fixture image program. Resource attack modes are
// executable only as a confined non-root workload with a readonly root and NNP.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func confined() bool {
	if os.Geteuid() != 1000 || os.Getenv("TAP_CANARY_CONTAINER") != "1" {
		return false
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil || !strings.Contains(string(status), "NoNewPrivs:\t1\n") || !strings.Contains(string(status), "CapEff:\t0000000000000000\n") {
		return false
	}
	mounts, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(mounts), "\n") {
		f := strings.Fields(line)
		if len(f) > 6 && f[4] == "/" && strings.Contains(","+f[5]+",", ",ro,") {
			return true
		}
	}
	return false
}
func denied(address string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return true
	}
	conn.Close()
	return false
}
func probe() map[string]bool {
	r := map[string]bool{"host_ipv4_denied": denied("10.88.0.1:9099"), "host_ipv6_denied": denied("[fd00:88::1]:9099"), "metadata_denied": denied("169.254.169.254:80"), "management_denied": denied("10.88.0.1:9443"), "external_denied": denied("1.1.1.1:443")}
	for _, path := range []string{"/etc/hosts", "/etc/hostname", "/etc/resolv.conf"} {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err == nil {
			f.Close()
		}
		r["readonly_"+strings.TrimPrefix(path, "/etc/")] = err != nil
	}
	for name, path := range map[string]string{"engine_socket": "/var/run/docker.sock", "agent_credentials": "/var/lib/tap-runtime/agent/identity.key", "control_socket": "/run/tap-runtime/measure.sock", "systemd_socket": "/run/user/1000/bus"} {
		_, err := os.Stat(path)
		r[name+"_absent"] = err != nil
	}
	for name, dir := range map[string]string{"tmp_writable": "/tmp", "run_writable": "/run"} {
		f, err := os.CreateTemp(dir, "tap-canary-")
		if err != nil {
			r[name] = false
			continue
		}
		_, writeErr := f.Write([]byte("bounded"))
		closeErr := f.Close()
		removeErr := os.Remove(f.Name())
		r[name] = writeErr == nil && closeErr == nil && removeErr == nil
	}
	return r
}
func attack(mode string) {
	switch mode {
	case "memory":
		var all [][]byte
		for {
			block := make([]byte, 1<<20)
			for n := range block {
				block[n] = 1
			}
			all = append(all, block)
			runtime.KeepAlive(all)
		}
	case "cpu":
		runtime.GOMAXPROCS(2)
		for i := 0; i < 2; i++ {
			go func() {
				buffer := make([]byte, 65536)
				for {
					sum := sha256.Sum256(buffer)
					copy(buffer, sum[:])
				}
			}()
		}
		select {}
	case "pids":
		children := []*exec.Cmd{}
		for n := 0; n < 1024; n++ {
			c := exec.Command("/runtime-canary", "sleep")
			if c.Start() != nil {
				break
			}
			children = append(children, c)
		}
		select {}
	case "tmp", "writable":
		path := "/tmp/bomb"
		if mode == "writable" {
			path = "/run/bomb"
		}
		f, err := os.Create(path)
		if err != nil {
			return
		}
		defer f.Close()
		block := make([]byte, 1<<20)
		for {
			if _, err = f.Write(block); err != nil {
				os.Stdout.WriteString("canary_write_bounded\n")
				select {}
			}
		}
	case "logs":
		block := []byte(strings.Repeat("L", 65535) + "\n")
		for {
			if _, err := os.Stdout.Write(block); err != nil {
				return
			}
		}
	case "crash":
		time.Sleep(2 * time.Second)
		os.Exit(1)
	}
}
func main() {
	if !confined() {
		os.Exit(1)
	}
	mode := "serve"
	if len(os.Args) == 2 {
		mode = os.Args[1]
	} else if len(os.Args) > 2 {
		os.Exit(1)
	}
	if mode == "sleep" {
		time.Sleep(5 * time.Minute)
		return
	}
	switch mode {
	case "serve", "memory", "cpu", "pids", "tmp", "writable", "logs", "crash":
	default:
		os.Exit(1)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		io.WriteString(w, "tap-runtime-ready")
	})
	mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		json.NewEncoder(w).Encode(probe())
	})
	server := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 4096}
	if mode != "serve" {
		go func() { time.Sleep(time.Second); attack(mode) }()
	}
	if server.ListenAndServe() != nil {
		os.Exit(1)
	}
}
