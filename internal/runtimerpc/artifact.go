package runtimerpc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"dev-orchestrator/internal/artifacts"
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/runtimeagent"
)

// Fetch transfers opaque admitted bytes to a private spool. The caller must not
// import any bytes until Fetch succeeds and must enforce scratch disk capacity.
func (c *Client) Fetch(ctx context.Context, claim artifacts.RuntimeClaim, expected artifacts.RuntimeObject, w io.Writer) error {
	if !contracts.ValidDigest(expected.Digest) || expected.Bytes < 1 || expected.Bytes > 1<<30 {
		return runtimeagent.ErrDenied
	}
	b, e := json.Marshal(claim)
	if e != nil || len(b) > 4096 {
		return runtimeagent.ErrDenied
	}
	req, e := http.NewRequestWithContext(ctx, "POST", c.origin+"/runtime/v1/artifact", bytes.NewReader(b))
	if e != nil {
		return runtimeagent.ErrDenied
	}
	req.Header.Set("Content-Type", "application/json")
	res, e := c.http.Do(req)
	if e != nil {
		return runtimeagent.ErrDenied
	}
	defer res.Body.Close()
	if !c.validPeer(res.TLS) || res.StatusCode != http.StatusOK || res.Header.Get("X-Artifact-Digest") != expected.Digest || res.Header.Get("Content-Length") != strconv.FormatInt(expected.Bytes, 10) {
		return runtimeagent.ErrDenied
	}
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(w, h), io.LimitReader(res.Body, expected.Bytes+1))
	if e != nil || n != expected.Bytes || "sha256:"+hex.EncodeToString(h.Sum(nil)) != expected.Digest {
		return runtimeagent.ErrDenied
	}
	if !c.validPeer(res.TLS) {
		return runtimeagent.ErrDenied
	}
	return nil
}
