//go:build linux

package builder

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"dev-orchestrator/internal/contracts"
	"net/http"
	"net/url"
	"os"
	"time"
)

func Upload(ctx context.Context, path string, a contracts.BuildAuthorization) error {
	if a.Validate(a.Job.Clone, time.Now()) != nil {
		return ErrDenied
	}
	ca, e := os.ReadFile("/build-ca.pem")
	if e != nil {
		return ErrDenied
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return ErrDenied
	}
	proxy, _ := url.Parse("http://192.0.2.1:8443")
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, MaxIdleConns: 1, ResponseHeaderTimeout: 10 * time.Second}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrDenied }}
	f, e := os.Open(path)
	if e != nil {
		return ErrDenied
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || st.Size() > a.Job.Policy.Limits.UploadBytes {
		return ErrLimit
	}
	req, e := http.NewRequestWithContext(ctx, "PUT", a.Job.Policy.UploadOrigin+"/"+a.ObjectID, f)
	if e != nil {
		return ErrDenied
	}
	req.ContentLength = st.Size()
	req.Header.Set("Authorization", "Bearer "+a.Token)
	response, e := client.Do(req)
	if e != nil {
		return ErrDenied
	}
	response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return ErrDenied
	}
	return nil
}
