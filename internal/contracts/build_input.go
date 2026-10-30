package contracts

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"time"
)

const buildInputMagic = "TAPBLD01"

func BuildInput(j BuildJob, now time.Time) ([]byte, error) {
	if j.Validate(now) != nil {
		return nil, ErrInvalidRequest
	}
	b, e := json.Marshal(j)
	if e != nil || len(b) > MaxBuildJobBytes {
		return nil, ErrTooLarge
	}
	var out bytes.Buffer
	out.WriteString(buildInputMagic)
	binary.Write(&out, binary.BigEndian, uint32(len(b)))
	out.Write(b)
	for out.Len()%512 != 0 {
		out.WriteByte(0)
	}
	return out.Bytes(), nil
}
func ReadBuildInput(r io.Reader, now time.Time) (BuildJob, error) {
	var head [12]byte
	if _, e := io.ReadFull(r, head[:]); e != nil || string(head[:8]) != buildInputMagic {
		return BuildJob{}, ErrMalformedJSON
	}
	n := binary.BigEndian.Uint32(head[8:])
	if n == 0 || n > MaxBuildJobBytes {
		return BuildJob{}, ErrTooLarge
	}
	b := make([]byte, n)
	if _, e := io.ReadFull(r, b); e != nil {
		return BuildJob{}, ErrMalformedJSON
	}
	return DecodeBuildJob(bytes.NewReader(b), now)
}
