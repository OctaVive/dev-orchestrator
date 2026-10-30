// artifact-service handles opaque quarantine bytes and a private controller
// interface. It never parses OCI, repository files or scanner reports.
package main

import (
	"context"
	"crypto/tls"
	"dev-orchestrator/internal/artifacts"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	root := flag.String("quarantine", "", "private quarantine directory")
	admitted := flag.String("artifacts", "", "private admitted artifact directory")
	control := flag.String("control", "", "new Unix socket in a private directory")
	listen := flag.String("listen", "", "dedicated TLS upload address")
	cert := flag.String("cert", "", "upload TLS certificate")
	key := flag.String("key", "", "upload TLS private key")
	capacity := flag.Int64("capacity", 4<<30, "fixed quarantine capacity bytes")
	flag.Parse()
	if *listen == "" || *cert == "" || *key == "" {
		log.Fatal("artifact service configuration denied")
	}
	for _, p := range []string{*root, *admitted, filepath.Dir(*control)} {
		st, e := os.Lstat(p)
		if e != nil || !st.IsDir() || st.Mode()&0077 != 0 || st.Mode()&os.ModeSymlink != 0 {
			log.Fatal("artifact service private directory required")
		}
	}
	s, e := artifacts.Open(*root, *capacity)
	if e != nil {
		log.Fatal("artifact storage unavailable")
	}
	socket, e := net.Listen("unix", *control)
	if e != nil {
		log.Fatal("artifact control unavailable")
	}
	defer socket.Close()
	if os.Chmod(*control, 0600) != nil {
		log.Fatal("artifact control permissions denied")
	}
	defer os.Remove(*control)
	upload := &http.Server{Addr: *listen, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	controller := &http.Server{Handler: s.ControlHandler(*admitted), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute, MaxHeaderBytes: 8192}
	failures := make(chan error, 2)
	go func() { failures <- upload.ListenAndServeTLS(*cert, *key) }()
	go func() { failures <- controller.Serve(socket) }()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if s.Sweep(now) != nil {
					cancel()
					return
				}
			}
		}
	}()
	select {
	case <-ctx.Done():
	case <-failures:
	}
	shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	_ = upload.Shutdown(shutdown)
	_ = controller.Shutdown(shutdown)
}
