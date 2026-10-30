package contracts

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"time"
)

// CloneInput is an immutable raw device: magic, big-endian JSON length, one
// strict JSON object, then zero padding to a sector boundary. No archive parser.
func CloneInput(j CloneJob, now time.Time) ([]byte, error) {
	if e := j.Validate(now); e != nil {
		return nil, e
	}
	b, e := json.Marshal(j)
	if e != nil || len(b) > MaxCloneJobBytes {
		return nil, ErrTooLarge
	}
	result := make([]byte, ((len(b)+12+511)/512)*512)
	copy(result, []byte("TAPCLN01"))
	binary.BigEndian.PutUint32(result[8:12], uint32(len(b)))
	copy(result[12:], b)
	return result, nil
}
func ReadCloneInput(r io.Reader, now time.Time) (CloneJob, error) {
	var header [12]byte
	if _, e := io.ReadFull(r, header[:]); e != nil || string(header[:8]) != "TAPCLN01" {
		return CloneJob{}, ErrMalformedJSON
	}
	n := binary.BigEndian.Uint32(header[8:])
	if n == 0 || n > MaxCloneJobBytes {
		return CloneJob{}, ErrTooLarge
	}
	b := make([]byte, n)
	if _, e := io.ReadFull(r, b); e != nil {
		return CloneJob{}, ErrMalformedJSON
	}
	return DecodeCloneJob(bytes.NewReader(b), now)
}
