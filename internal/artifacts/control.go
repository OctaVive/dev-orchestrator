package artifacts

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"
)

// ControlHandler is served ONLY on a private Unix socket owned by the service
// account. It is never attached to the guest-facing TLS upload listener.
func (s *Store) ControlHandler(artifactRoot string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "denied", 403)
			return
		}
		var request struct {
			Binding Binding
			Limit   int64
			Expiry  time.Time
			ID      string
			Receipt Receipt
		}
		decoder := json.NewDecoder(io.LimitReader(r.Body, 4097))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
			http.Error(w, "denied", 403)
			return
		}
		var response any
		var e error
		switch r.URL.Path {
		case "/issue":
			var id, token string
			id, token, e = s.Issue(request.Binding, request.Limit, request.Expiry)
			response = struct{ ID, Token string }{id, token}
		case "/receipt":
			response, e = s.Receipt(request.ID)
		case "/revoke":
			s.Revoke(request.ID)
			response = struct{}{}
		case "/promote":
			var id string
			id, e = s.Promote(request.Receipt, artifactRoot)
			response = struct{ ID string }{id}
		default:
			http.Error(w, "denied", 403)
			return
		}
		if e != nil {
			http.Error(w, "denied", 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})
}

// Client reaches a fixed operator-owned Unix socket, never a guest URL.
type Client struct{ HTTP *http.Client }

func NewClient(socket string) *Client {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	return &Client{HTTP: &http.Client{Transport: transport, Timeout: 2 * time.Minute}}
}
func (c *Client) call(path string, request, response any) error {
	b, e := json.Marshal(request)
	if e != nil {
		return ErrDenied
	}
	r, e := c.HTTP.Post("http://artifact-control"+path, "application/json", bytes.NewReader(b))
	if e != nil {
		return ErrDenied
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return ErrDenied
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, 4097))
	decoder.DisallowUnknownFields()
	if decoder.Decode(response) != nil || decoder.Decode(new(any)) != io.EOF {
		return ErrDenied
	}
	return nil
}
func (c *Client) Issue(b Binding, limit int64, expiry time.Time) (string, string, error) {
	var response struct{ ID, Token string }
	e := c.call("/issue", struct {
		Binding Binding
		Limit   int64
		Expiry  time.Time
	}{b, limit, expiry}, &response)
	return response.ID, response.Token, e
}
func (c *Client) Receipt(id string) (Receipt, error) {
	var r Receipt
	e := c.call("/receipt", struct{ ID string }{id}, &r)
	return r, e
}
func (c *Client) Revoke(id string) { _ = c.call("/revoke", struct{ ID string }{id}, &struct{}{}) }
func (c *Client) Promote(r Receipt, _ string) (string, error) {
	var response struct{ ID string }
	e := c.call("/promote", struct{ Receipt Receipt }{r}, &response)
	return response.ID, e
}
