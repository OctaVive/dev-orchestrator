package contracts

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"
)

const (
	MaxDeploymentBytes = 64 << 10
	MaxCommandBytes    = 128 << 10
	maxJSONDepth       = 32
)

// Errors intentionally omit input values: bodies may contain sensitive runtime
// environment data. HTTP adapters must not log raw decoder/schema errors.
var (
	ErrTooLarge       = errors.New("contract payload exceeds size limit")
	ErrMalformedJSON  = errors.New("contract requires one unambiguous UTF-8 JSON object")
	ErrSchema         = errors.New("contract schema validation failed")
	ErrInvalidRequest = errors.New("deployment request policy validation failed")
	ErrCommandContext = errors.New("agent command context validation failed")
)

func readObject(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, ErrMalformedJSON
	}
	if int64(len(b)) > limit {
		return nil, ErrTooLarge
	}
	if !utf8.Valid(b) {
		return nil, ErrMalformedJSON
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return nil, ErrMalformedJSON
	}
	if err := scanObject(d, 1); err != nil {
		return nil, ErrMalformedJSON
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrMalformedJSON
	}
	return b, nil
}

func scanObject(d *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return ErrMalformedJSON
	}
	keys := make(map[string]bool)
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return err
		}
		s, ok := key.(string)
		if !ok || keys[s] {
			return ErrMalformedJSON
		}
		keys[s] = true
		if err := scanValue(d, depth+1); err != nil {
			return err
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		return ErrMalformedJSON
	}
	return nil
}

func scanValue(d *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return ErrMalformedJSON
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	// All numeric wire fields are integers. Reject exponent/decimal encodings
	// and integer overflow before the schema engine's arbitrary-precision math.
	// A small body must not be able to request an enormous numeric allocation.
	if n, ok := t.(json.Number); ok {
		if len(n) > 20 {
			return ErrMalformedJSON
		}
		if _, err := strconv.ParseInt(string(n), 10, 64); err != nil {
			return ErrMalformedJSON
		}
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		return scanObject(d, depth)
	case '[':
		for d.More() {
			if err := scanValue(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return ErrMalformedJSON
		}
		return nil
	default:
		return ErrMalformedJSON
	}
}

func decodeTyped[T any](b []byte) (T, error) {
	var out T
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&out); err != nil {
		return out, ErrSchema
	}
	return out, nil
}
