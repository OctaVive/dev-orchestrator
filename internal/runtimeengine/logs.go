package runtimeengine

import (
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"strconv"

	"dev-orchestrator/internal/runtimeagent"
)

// Docker non-TTY stdout/stderr frames are decoded with independent frame/total
// limits. Never expose raw daemon errors, frame headers or unbounded log streams.
func decodeLogs(r io.Reader, limit int) ([]byte, error) {
	if limit < 1 || limit > runtimeagent.MaxLogs {
		return nil, runtimeagent.ErrDenied
	}
	var out []byte
	var header [8]byte
	for frames := 0; frames < 1024; frames++ {
		n, e := io.ReadFull(r, header[:])
		if e == io.EOF && n == 0 {
			return out, nil
		}
		if e != nil || header[0] < 1 || header[0] > 2 || header[1] != 0 || header[2] != 0 || header[3] != 0 {
			return nil, runtimeagent.ErrDenied
		}
		size := binary.BigEndian.Uint32(header[4:])
		if uint64(size) > uint64(limit-len(out)) {
			return nil, runtimeagent.ErrDenied
		}
		start := len(out)
		out = append(out, make([]byte, int(size))...)
		if _, e := io.ReadFull(r, out[start:]); e != nil {
			return nil, runtimeagent.ErrDenied
		}
	}
	return nil, runtimeagent.ErrDenied
}
func (c *Client) logs(ctx context.Context, id string, limit int) ([]byte, error) {
	if !objectID.MatchString(id) {
		return nil, runtimeagent.ErrDenied
	}
	req, e := http.NewRequestWithContext(ctx, "GET", "http://engine/v"+APIVersion+"/containers/"+id+"/logs?stdout=true&stderr=true&follow=false&timestamps=false&tail="+strconv.Itoa(100), nil)
	if e != nil {
		return nil, runtimeagent.ErrDenied
	}
	res, e := c.http.Do(req)
	if e != nil {
		return nil, runtimeagent.ErrDenied
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, runtimeagent.ErrDenied
	}
	return decodeLogs(res.Body, limit)
}
