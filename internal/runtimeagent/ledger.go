package runtimeagent

import (
	"context"
	"database/sql"
	"errors"
	"golang.org/x/sys/unix"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	_ "modernc.org/sqlite"
)

// Ledger is deliberately separate from management storage. A single process owns
// dispatch; SQLite transactions also fence multiple processes at reservation.
type Ledger struct {
	db                  *sql.DB
	lock                *os.File
	mu                  sync.Mutex
	worker, incarnation string
}

const schema = `
CREATE TABLE identity (singleton INTEGER PRIMARY KEY CHECK(singleton=1), worker TEXT NOT NULL, incarnation TEXT NOT NULL);
CREATE TABLE commands (id TEXT PRIMARY KEY, nonce TEXT NOT NULL UNIQUE, hash TEXT NOT NULL, app TEXT NOT NULL, deployment TEXT NOT NULL, generation INTEGER NOT NULL, spec_hash TEXT NOT NULL, operation TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('pending','done','uncertain')), outcome BLOB);
CREATE TABLE resources (owner TEXT NOT NULL REFERENCES commands(id), id TEXT PRIMARY KEY, kind TEXT NOT NULL, service TEXT NOT NULL, expected BLOB NOT NULL);
CREATE TABLE fences (app TEXT PRIMARY KEY, generation INTEGER NOT NULL, deployment TEXT NOT NULL, spec_hash TEXT NOT NULL);
CREATE TABLE targets (id TEXT PRIMARY KEY REFERENCES commands(id), stopped INTEGER NOT NULL DEFAULT 0 CHECK(stopped IN(0,1)));
PRAGMA application_id=1413566546;
PRAGMA user_version=1;
`

func OpenLedger(ctx context.Context, path, worker, incarnation string) (*Ledger, error) {
	if !validIdentity(worker, incarnation) || path == "" || path == ":memory:" || strings.HasPrefix(path, "file:") {
		return nil, ErrDenied
	}
	abs, e := filepath.Abs(path)
	if e != nil {
		return nil, ErrDenied
	}
	// Inspect every ancestor: do not follow a symlink into another account's data.
	for p := filepath.Dir(abs); ; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return nil, ErrDenied
		}
		if p == filepath.Dir(abs) && (st.Mode().Perm()&0077 != 0 || !owned(st)) {
			return nil, ErrDenied
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	f, e := os.OpenFile(abs, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if e == nil {
		f.Close()
	} else if !errors.Is(e, os.ErrExist) {
		return nil, ErrLedger
	}
	st, e := os.Lstat(abs)
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || !owned(st) {
		return nil, ErrDenied
	}
	lock, e := os.OpenFile(abs, os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, ErrLedger
	}
	if unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		lock.Close()
		return nil, ErrLedger
	}
	success := false
	defer func() {
		if !success {
			lock.Close()
		}
	}()
	u := url.URL{Scheme: "file", Path: abs}
	q := url.Values{}
	for _, p := range []string{"journal_mode(WAL)", "synchronous(FULL)", "foreign_keys(ON)", "trusted_schema(OFF)", "busy_timeout(5000)"} {
		q.Add("_pragma", p)
	}
	u.RawQuery = q.Encode()
	db, e := sql.Open("sqlite", u.String())
	if e != nil {
		return nil, ErrLedger
	}
	db.SetMaxOpenConns(1)
	l := &Ledger{db: db, lock: lock, worker: worker, incarnation: incarnation}
	e = l.transaction(ctx, func(tx *sql.Tx) error {
		var app, version int
		if tx.QueryRowContext(ctx, "PRAGMA application_id").Scan(&app) != nil || tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version) != nil {
			return ErrLedger
		}
		if app == 0 && version == 0 {
			var n int
			if tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&n) != nil || n != 0 {
				return ErrLedger
			}
			if _, e := tx.ExecContext(ctx, schema); e != nil {
				return ErrLedger
			}
			if _, e := tx.ExecContext(ctx, "INSERT INTO identity VALUES(1,?,?)", worker, incarnation); e != nil {
				return ErrLedger
			}
		} else if app != 1413566546 || version != 1 {
			return ErrLedger
		}
		var w, i string
		if tx.QueryRowContext(ctx, "SELECT worker,incarnation FROM identity WHERE singleton=1").Scan(&w, &i) != nil || w != worker || i != incarnation {
			return ErrLedger
		}
		return nil
	})
	if e == nil {
		var check string
		if db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&check) != nil || check != "ok" {
			e = ErrLedger
		}
	}
	if e != nil {
		db.Close()
		return nil, e
	}
	success = true
	return l, nil
}
func (l *Ledger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.db.Close()
	le := l.lock.Close()
	if e != nil || le != nil {
		return ErrLedger
	}
	return nil
}
func (l *Ledger) transaction(ctx context.Context, f func(*sql.Tx) error) error {
	tx, e := l.db.BeginTx(ctx, nil)
	if e != nil {
		return ErrLedger
	}
	defer tx.Rollback()
	if e = f(tx); e != nil {
		return e
	}
	if tx.Commit() != nil {
		return ErrLedger
	}
	return nil
}

// reserve never resumes a pending mutation after restart. It is reconciled or
// explicitly cleaned by a newly authorized stop/remove command.
func (l *Ledger) reserve(ctx context.Context, c Command) (Result, bool, error) {
	var previous Result
	cached := false
	e := l.transaction(ctx, func(tx *sql.Tx) error {
		var h, state string
		var raw []byte
		e := tx.QueryRowContext(ctx, "SELECT hash,state,outcome FROM commands WHERE id=?", c.ID).Scan(&h, &state, &raw)
		if e == nil {
			if h != c.Hash() {
				return ErrConflict
			}
			if state != "done" {
				return ErrUncertain
			}
			if decodeResult(raw, &previous) != nil {
				return ErrLedger
			}
			cached = true
			return nil
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return ErrLedger
		}
		var gen int64
		var deployment, hash string
		e = tx.QueryRowContext(ctx, "SELECT generation,deployment,spec_hash FROM fences WHERE app=?", c.AppID).Scan(&gen, &deployment, &hash)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return ErrLedger
		}
		if c.Operation == "create" || c.Operation == "prepare" {
			if c.Generation < gen || c.Generation == gen && (deployment != c.DeploymentID || hash != c.SpecHash) {
				return ErrConflict
			}
			// A second create identity for a generation cannot restart an intentionally stopped target.
			if c.Operation == "create" {
				var n int
				if tx.QueryRowContext(ctx, "SELECT count(*) FROM commands WHERE app=? AND generation=? AND operation='create'", c.AppID, c.Generation).Scan(&n) != nil {
					return ErrLedger
				}
				if n != 0 {
					return ErrConflict
				}
			}
			if _, e = tx.ExecContext(ctx, "INSERT INTO fences VALUES(?,?,?,?) ON CONFLICT(app) DO UPDATE SET generation=excluded.generation,deployment=excluded.deployment,spec_hash=excluded.spec_hash", c.AppID, c.Generation, c.DeploymentID, c.SpecHash); e != nil {
				return ErrLedger
			}
		}
		if c.Target != "" {
			var a, d, s, op string
			var g int64
			if tx.QueryRowContext(ctx, "SELECT app,deployment,generation,spec_hash,operation FROM commands WHERE id=?", c.Target).Scan(&a, &d, &g, &s, &op) != nil || a != c.AppID || d != c.DeploymentID || g != c.Generation || s != c.SpecHash || op != "create" {
				return ErrDenied
			}
			if c.Operation == "stop" || c.Operation == "remove" {
				if _, e = tx.ExecContext(ctx, "UPDATE targets SET stopped=1 WHERE id=?", c.Target); e != nil {
					return ErrLedger
				}
			}
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO commands(id,nonce,hash,app,deployment,generation,spec_hash,operation,state) VALUES(?,?,?,?,?,?,?,?,'pending')", c.ID, c.Nonce, c.Hash(), c.AppID, c.DeploymentID, c.Generation, c.SpecHash, c.Operation); e != nil {
			return ErrConflict
		}
		if c.Operation == "create" {
			if _, e = tx.ExecContext(ctx, "INSERT INTO targets(id) VALUES(?)", c.ID); e != nil {
				return ErrLedger
			}
		}
		return nil
	})
	return previous, cached, e
}
func (l *Ledger) finish(ctx context.Context, id string, r Result, uncertain bool) error {
	b, e := encodeResult(r)
	if e != nil {
		return ErrLedger
	}
	state := "done"
	if uncertain {
		state = "uncertain"
	}
	res, e := l.db.ExecContext(ctx, "UPDATE commands SET state=?,outcome=? WHERE id=? AND state='pending'", state, b, id)
	if e != nil {
		return ErrLedger
	}
	n, e := res.RowsAffected()
	if e != nil || n != 1 {
		return ErrLedger
	}
	return nil
}
func (l *Ledger) current(ctx context.Context, c Command) bool {
	var gen int64
	var d, h string
	if l.db.QueryRowContext(ctx, "SELECT generation,deployment,spec_hash FROM fences WHERE app=?", c.AppID).Scan(&gen, &d, &h) != nil || gen != c.Generation || d != c.DeploymentID || h != c.SpecHash {
		return false
	}
	if c.Operation == "create" {
		var stopped int
		if l.db.QueryRowContext(ctx, "SELECT stopped FROM targets WHERE id=?", c.ID).Scan(&stopped) != nil || stopped != 0 {
			return false
		}
	}
	return true
}

// Resource is a private durable record, not part of the command protocol.
// Expected is the complete agent-generated configuration, never raw inspect output.
type Resource struct {
	ID       string
	Kind     string
	Service  string
	Expected []byte
}

func (l *Ledger) SaveResource(ctx context.Context, owner string, r Resource) error {
	if r.ID == "" || len(r.ID) > 128 || (r.Kind != "container" && r.Kind != "network") || len(r.Expected) > 64<<10 {
		return ErrDenied
	}
	_, e := l.db.ExecContext(ctx, "INSERT INTO resources(owner,id,kind,service,expected) VALUES(?,?,?,?,?)", owner, r.ID, r.Kind, r.Service, r.Expected)
	if e != nil {
		return ErrLedger
	}
	return nil
}
func (l *Ledger) Resources(ctx context.Context, owner string) ([]Resource, error) {
	rows, e := l.db.QueryContext(ctx, "SELECT id,kind,service,expected FROM resources WHERE owner=? ORDER BY kind,id", owner)
	if e != nil {
		return nil, ErrLedger
	}
	defer rows.Close()
	var out []Resource
	for rows.Next() {
		var r Resource
		if rows.Scan(&r.ID, &r.Kind, &r.Service, &r.Expected) != nil {
			return nil, ErrLedger
		}
		out = append(out, r)
	}
	if rows.Err() != nil {
		return nil, ErrLedger
	}
	return out, nil
}
func (l *Ledger) ForgetResource(ctx context.Context, owner, id string) error {
	_, e := l.db.ExecContext(ctx, "DELETE FROM resources WHERE owner=? AND id=?", owner, id)
	if e != nil {
		return ErrLedger
	}
	return nil
}
