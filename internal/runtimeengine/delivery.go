package runtimeengine

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"

	"dev-orchestrator/internal/artifacts"
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/runtimeagent"
)

type ArtifactTransport interface {
	Fetch(context.Context, artifacts.RuntimeClaim, artifacts.RuntimeObject, io.Writer) error
}
type ArtifactMetadata interface {
	RuntimeArtifact(context.Context, runtimeagent.Command, contracts.RuntimeServiceV2) (artifacts.RuntimeObject, error)
}
type Delivery struct {
	Client    *Client
	Transport ArtifactTransport
	Metadata  ArtifactMetadata
	Scratch   string
}

var _ ImageDelivery = (*Delivery)(nil)

func (d *Delivery) Prepare(ctx context.Context, c runtimeagent.Command, s contracts.RuntimeServiceV2, check func() error) (result error) {
	if d.Client == nil || d.Transport == nil || d.Metadata == nil || check() != nil {
		return runtimeagent.ErrDenied
	}
	object, e := d.Metadata.RuntimeArtifact(ctx, c, s)
	if e != nil || !contracts.ValidDigest(object.Digest) || object.Bytes < 1 || object.Bytes > 1<<30 {
		return runtimeagent.ErrDenied
	}
	st, e := os.Lstat(d.Scratch)
	if e != nil || !st.IsDir() || st.Mode()&0077 != 0 || st.Mode()&os.ModeSymlink != 0 {
		return runtimeagent.ErrDenied
	}
	root, e := os.OpenRoot(d.Scratch)
	if e != nil {
		return runtimeagent.ErrDenied
	}
	defer root.Close()
	random := make([]byte, 32)
	if _, e = rand.Read(random); e != nil {
		return runtimeagent.ErrDenied
	}
	name := "download-" + hex.EncodeToString(random)
	f, e := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return runtimeagent.ErrDenied
	}
	defer func() {
		if f.Close() != nil {
			result = runtimeagent.ErrUncertain
		}
		if root.Remove(name) != nil {
			result = runtimeagent.ErrUncertain
		}
	}()
	claim := artifacts.RuntimeClaim{WorkerID: c.WorkerID, Incarnation: c.Incarnation, AppID: c.AppID, DeploymentID: c.DeploymentID, Generation: c.Generation, SpecHash: c.SpecHash, PolicyHash: c.PolicyHash, AdmissionID: s.AdmissionID, Image: s.Image}
	if d.Transport.Fetch(ctx, claim, object, f) != nil || f.Sync() != nil {
		os.Stderr.WriteString("runtime_delivery_transfer_denied\n")
		return runtimeagent.ErrDenied
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return runtimeagent.ErrDenied
	}
	hash := sha256.New()
	n, e := io.Copy(hash, io.LimitReader(f, object.Bytes+1))
	if e != nil || n != object.Bytes || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != object.Digest {
		return runtimeagent.ErrDenied
	}
	if next, e := d.Metadata.RuntimeArtifact(ctx, c, s); e != nil || next != object || check() != nil {
		return runtimeagent.ErrDenied
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return runtimeagent.ErrDenied
	}
	if err := d.Client.load(ctx, f, object.Bytes); err != nil {
		os.Stderr.WriteString("runtime_delivery_import_denied\n")
		return err
	}
	return nil
}
func (c *Client) load(ctx context.Context, source io.Reader, size int64) error {
	req, e := http.NewRequestWithContext(ctx, "POST", "http://engine/v"+APIVersion+"/images/load?quiet=true", io.LimitReader(source, size))
	if e != nil {
		return runtimeagent.ErrDenied
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/x-tar")
	res, e := c.http.Do(req)
	if e != nil {
		return runtimeagent.ErrUncertain
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return runtimeagent.ErrDenied
	}
	body, e := io.ReadAll(io.LimitReader(res.Body, maxResponse+1))
	if e != nil || len(body) > maxResponse {
		return runtimeagent.ErrDenied
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	count := 0
	for {
		var message struct {
			Error       string          `json:"error"`
			ErrorDetail json.RawMessage `json:"errorDetail"`
			Stream      string          `json:"stream"`
		}
		e = decoder.Decode(&message)
		if e == io.EOF {
			break
		}
		count++
		if e != nil || count > 1024 || message.Error != "" || len(message.ErrorDetail) > 0 {
			return runtimeagent.ErrDenied
		}
	}
	if count == 0 {
		return runtimeagent.ErrDenied
	}
	return nil
}
