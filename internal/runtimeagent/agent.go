package runtimeagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/policy"
)

// Approval must consult trusted durable approval/admission/revocation state, not
// fields asserted by a browser, build guest or command sender.
type Approval interface {
	Current(context.Context, Command) error
}
type Lease interface {
	Valid(context.Context, string, string) error
}

// Engine implements only typed operations. check must be called immediately
// before each mutation and after long-running calls, including service starts.
// Failure always leaves an explicit uncertain intent; it never authorizes retry.
type Engine interface {
	Probe(context.Context, Command, func() error) (Inventory, error)
	Prepare(context.Context, Command, func() error) error
	Create(context.Context, Command, func() error) error
	Inspect(context.Context, Command) (string, error)
	Logs(context.Context, Command) ([]byte, error)
	Stop(context.Context, Command, func() error) error
	Remove(context.Context, Command, func() error) error
}

type Result struct {
	CommandID string     `json:"command_id"`
	Code      string     `json:"code"`
	State     string     `json:"state,omitempty"`
	Logs      string     `json:"logs,omitempty"`
	Inventory *Inventory `json:"inventory,omitempty"`
}

func encodeResult(r Result) ([]byte, error) {
	b, e := json.Marshal(r)
	if e != nil || len(b) > 64<<10 {
		return nil, ErrDenied
	}
	return b, nil
}
func decodeResult(b []byte, r *Result) error { return json.Unmarshal(b, r) }
func validIdentity(worker, incarnation string) bool {
	return contracts.ValidJobID(worker) && contracts.ValidJobID(incarnation)
}

type Config struct {
	WorkerID, Incarnation string
	Keys                  map[string]ed25519.PublicKey
	InventoryKey          ed25519.PrivateKey
	Resolver              policy.Resolver
	Approval              Approval
	Lease                 Lease
	Engine                Engine
	Ledger                *Ledger
	Now                   func() time.Time
}
type Agent struct {
	config       Config
	diagnostic   sync.Mutex
	diagnosticAt time.Time
}

func (a *Agent) denied(stage string) error {
	a.diagnostic.Lock()
	defer a.diagnostic.Unlock()
	if time.Since(a.diagnosticAt) >= 30*time.Second {
		os.Stderr.WriteString("runtime_preflight_" + stage + "_denied\n")
		a.diagnosticAt = time.Now()
	}
	return ErrDenied
}

func New(c Config) (*Agent, error) {
	if !validIdentity(c.WorkerID, c.Incarnation) || c.Ledger == nil || c.Ledger.worker != c.WorkerID || c.Ledger.incarnation != c.Incarnation || c.Engine == nil || c.Approval == nil || c.Lease == nil || c.Resolver == nil || len(c.Keys) == 0 || len(c.InventoryKey) != ed25519.PrivateKeySize {
		return nil, ErrDenied
	}
	keys := map[string]ed25519.PublicKey{}
	for k, v := range c.Keys {
		if !policy.ValidName(k) || len(v) != ed25519.PublicKeySize {
			return nil, ErrDenied
		}
		if bytes.Equal(v, c.InventoryKey.Public().(ed25519.PublicKey)) {
			return nil, ErrDenied
		}
		keys[k] = append(ed25519.PublicKey(nil), v...)
	}
	c.Keys = keys
	c.InventoryKey = append(ed25519.PrivateKey(nil), c.InventoryKey...)
	if c.Now == nil {
		c.Now = time.Now
	}
	return &Agent{config: c}, nil
}
func (a *Agent) check(ctx context.Context, c Command, mutation bool) error {
	if ctx.Err() != nil {
		return a.denied("context")
	}
	if c.Validate(a.config.Now(), a.config.WorkerID, a.config.Incarnation, a.config.Keys) != nil {
		return a.denied("command")
	}
	if a.config.Lease.Valid(ctx, c.WorkerID, c.Incarnation) != nil {
		return a.denied("lease")
	}
	if c.Operation == "create" || c.Operation == "prepare" {
		if a.config.Approval.Current(ctx, c) != nil {
			return a.denied("approval")
		}
		if policy.ValidateRuntime(*c.Spec, a.config.Resolver) != nil {
			return a.denied("policy")
		}
		for _, s := range c.Spec.Services {
			if len(s.Volumes) != 0 || len(s.Secrets) != 0 {
				return ErrUnsupported
			}
		}
		if mutation && !a.config.Ledger.current(ctx, c) {
			return ErrConflict
		}
	}
	return nil
}
func (a *Agent) Execute(ctx context.Context, c Command) (Result, error) {
	// Freeze caller-owned maps/slices before checking signatures or waiting on a lock.
	b, e := json.Marshal(c)
	if e != nil {
		return Result{}, ErrDenied
	}
	c, e = DecodeBytes(b)
	if e != nil {
		return Result{}, ErrDenied
	}
	a.config.Ledger.mu.Lock()
	defer a.config.Ledger.mu.Unlock()
	if e = a.check(ctx, c, false); e != nil {
		return Result{}, e
	}
	expiry, _ := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	ctx, cancel := context.WithDeadline(ctx, expiry)
	defer cancel()
	previous, cached, e := a.config.Ledger.reserve(ctx, c)
	if e != nil {
		return Result{}, e
	}
	if cached {
		return previous, nil
	}
	// Revoke a long-running engine/artifact request even when it is not calling
	// a stage callback. The same current lease/approval/fence checks are used;
	// cancellation leaves the durable intent charged until confirmed cleanup.
	ctx, revoke := context.WithCancel(ctx)
	defer revoke()
	watchDone := make(chan struct{})
	monitorExit := make(chan struct{})
	defer func() { close(watchDone); revoke(); <-monitorExit }()
	go func() {
		defer close(monitorExit)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-watchDone:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				fresh, stop := context.WithTimeout(ctx, 2*time.Second)
				err := a.check(fresh, c, true)
				stop()
				if err != nil {
					revoke()
					return
				}
			}
		}
	}()
	r := Result{CommandID: c.ID, Code: "ok"}
	check := func() error { return a.check(ctx, c, true) }
	var opErr error
	createStarted := false
	switch c.Operation {
	case "probe":
		inventory, e := a.config.Engine.Probe(ctx, c, check)
		if e != nil || inventory.ReadyFor(a.config.Now(), c.WorkerID, c.Incarnation, c.AppID) != nil || inventory.Challenge != c.Nonce {
			opErr = ErrUnsupported
		} else {
			if inventory.Sign(a.config.InventoryKey) != nil {
				opErr = ErrDenied
				break
			}
			r.Inventory = &inventory
		}
	case "prepare", "create":
		inventory, e := a.config.Engine.Probe(ctx, c, check)
		if e != nil || inventory.ReadyFor(a.config.Now(), c.WorkerID, c.Incarnation, c.AppID) != nil || inventory.Challenge != c.Nonce {
			opErr = ErrUnsupported
			break
		}
		if opErr = check(); opErr != nil {
			break
		}
		if c.Operation == "prepare" {
			opErr = a.config.Engine.Prepare(ctx, c, check)
		} else {
			createStarted = true
			opErr = a.config.Engine.Create(ctx, c, check)
		}
		if opErr == nil {
			opErr = check()
		}
	case "inspect":
		r.State, opErr = a.config.Engine.Inspect(ctx, c)
	case "logs":
		var raw []byte
		raw, opErr = a.config.Engine.Logs(ctx, c)
		if len(raw) > c.LogLimit {
			opErr = ErrDenied
		} else {
			r.Logs = sanitizeLogs(raw)
		}
	case "stop":
		opErr = a.config.Engine.Stop(ctx, c, check)
	case "remove":
		opErr = a.config.Engine.Remove(ctx, c, check)
	}
	// Only bounded closed status values may escape an engine adapter.
	if r.State != "" && r.State != "created" && r.State != "running" && r.State != "healthy" && r.State != "stopped" && r.State != "removed" {
		opErr = ErrDenied
		r.State = ""
	}
	if opErr == nil {
		opErr = a.check(ctx, c, true)
	}
	uncertain := opErr != nil && (c.Operation == "prepare" || c.Operation == "create" || c.Operation == "stop" || c.Operation == "remove")
	if opErr != nil && createStarted {
		cleanup, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		target := c
		target.Operation = "remove"
		target.Target = c.ID
		target.Spec = nil
		_ = a.config.Engine.Remove(cleanup, target, func() error {
			if cleanup.Err() != nil {
				return ErrDenied
			}
			return nil
		})
		cleanupCancel()
	}

	if opErr != nil {
		r = Result{CommandID: c.ID, Code: "denied"}
		if uncertain {
			r.Code = "uncertain"
		}
	}
	// Persist even when the operation's context was cancelled; never drop the intent.
	saveCtx, saveCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer saveCancel()
	if a.config.Ledger.finish(saveCtx, c.ID, r, uncertain) != nil {
		return Result{}, ErrLedger
	}
	if uncertain {
		return r, ErrUncertain
	}
	if opErr != nil {
		return r, ErrDenied
	}
	return r, nil
}
func sanitizeLogs(b []byte) string {
	if !utf8.Valid(b) {
		b = []byte(strings.ToValidUTF8(string(b), "\uFFFD"))
	}
	out := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return '\uFFFD'
		}
		return r
	}, string(b))
	if len(out) > MaxLogs {
		out = out[:MaxLogs]
		for !utf8.ValidString(out) {
			out = out[:len(out)-1]
		}
	}
	return out
}
