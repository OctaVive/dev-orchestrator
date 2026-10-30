// Package runtimeengine implements a bounded Docker Engine HTTP adapter. It has
// no shell, caller-selected API path, host path, Docker options or exec endpoint.
package runtimeengine

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"dev-orchestrator/internal/runtimeagent"
)

// API 1.47 is an explicit minimum contract; deployment must pin/test the daemon.
const APIVersion = "1.47"
const maxResponse = 1 << 20

var objectID = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Client struct{ http *http.Client }

func NewClient(socket string) (*Client, error) {
	if !filepath.IsAbs(socket) || filepath.Clean(socket) != socket || strings.IndexByte(socket, 0) >= 0 {
		return nil, runtimeagent.ErrDenied
	}
	t := &http.Transport{Proxy: nil, MaxIdleConns: 2, MaxConnsPerHost: 2, ResponseHeaderTimeout: 5 * time.Second, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socket)
	}}
	return &Client{http: &http.Client{Transport: t, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return runtimeagent.ErrDenied }}}, nil
}
func (c *Client) call(ctx context.Context, method, path string, body, out any) error {
	var r io.Reader
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil || len(b) > 128<<10 {
			return runtimeagent.ErrDenied
		}
		r = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, method, "http://engine/v"+APIVersion+path, r)
	if e != nil {
		return runtimeagent.ErrDenied
	}
	req.Header.Set("Content-Type", "application/json")
	res, e := c.http.Do(req)
	if e != nil {
		return runtimeagent.ErrUncertain
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return runtimeagent.ErrDenied
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, maxResponse+1))
	if e != nil || len(b) > maxResponse {
		return runtimeagent.ErrDenied
	}
	if out != nil {
		if json.Unmarshal(b, out) != nil {
			return runtimeagent.ErrDenied
		}
	}
	return nil
}
func escape(s string) string { return url.PathEscape(s) }
