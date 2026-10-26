package provisioner

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"modernc.org/sqlite"
)

//go:embed schema.sql
var ledgerSchema string

const ledgerApplicationID = 0x4f524350

type Ledger struct{ db *sql.DB }

// OpenLedger requires a separate host-local private file, not the management
// DB, a URI, shared filesystem or guest mount. Windows ACL/parent ownership and
// local mount validation are operator duties; Unix private modes are checked.
func OpenLedger(ctx context.Context, path string) (*Ledger, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if path == "" || path == ":memory:" || strings.HasPrefix(path, "file:") || strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, "//") {
		return nil, ErrInvalid
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, ErrInvalid
	}
	parent, err := os.Lstat(filepath.Dir(abs))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && parent.Mode().Perm()&0077 != 0 {
		return nil, ErrInvalid
	}
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err == nil {
		if err := f.Close(); err != nil {
			return nil, ErrLedger
		}
	} else if !errors.Is(err, os.ErrExist) {
		return nil, ErrLedger
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, ErrInvalid
	}
	uriPath := filepath.ToSlash(abs)
	if filepath.VolumeName(abs) != "" {
		uriPath = "/" + uriPath
	}
	u := url.URL{Scheme: "file", Path: uriPath}
	q := url.Values{}
	for _, pragma := range []string{"busy_timeout(5000)", "foreign_keys(ON)", "journal_mode(WAL)", "synchronous(FULL)", "trusted_schema(OFF)"} {
		q.Add("_pragma", pragma)
	}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, ErrLedger
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	l := &Ledger{db: db}
	if err := connectLedger(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	var journal string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil || journal != "wal" {
		db.Close()
		return nil, ErrLedger
	}
	for query, expected := range map[string]int{"PRAGMA foreign_keys": 1, "PRAGMA synchronous": 2, "PRAGMA trusted_schema": 0, "PRAGMA busy_timeout": 5000} {
		var actual int
		if err := db.QueryRowContext(ctx, query).Scan(&actual); err != nil || actual != expected {
			db.Close()
			return nil, ErrLedger
		}
	}
	err = l.write(ctx, func(conn *sql.Conn) error {
		var app, version, tables int
		if err := conn.QueryRowContext(ctx, "PRAGMA application_id").Scan(&app); err != nil {
			return ErrVersion
		}
		if err := conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
			return ErrVersion
		}
		if app == 0 && version == 0 {
			if err := conn.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&tables); err != nil || tables != 0 {
				return ErrVersion
			}
			if _, err := conn.ExecContext(ctx, ledgerSchema); err != nil {
				return ErrVersion
			}
			if _, err := conn.ExecContext(ctx, "INSERT INTO ledger_meta(id,checksum) VALUES (1,?)", digest([]byte(ledgerSchema))); err != nil {
				return ErrVersion
			}
			if _, err := conn.ExecContext(ctx, fmt.Sprintf("PRAGMA application_id=%d", ledgerApplicationID)); err != nil {
				return ErrVersion
			}
			if _, err := conn.ExecContext(ctx, "PRAGMA user_version=1"); err != nil {
				return ErrVersion
			}
		} else if app != ledgerApplicationID || version != 1 {
			return ErrVersion
		}
		var checksum string
		if err := conn.QueryRowContext(ctx, "SELECT checksum FROM ledger_meta WHERE id=1").Scan(&checksum); err != nil || checksum != digest([]byte(ledgerSchema)) {
			return ErrVersion
		}
		return nil
	})
	if err == nil {
		err = l.check(ctx)
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return l, nil
}

func connectLedger(ctx context.Context, db *sql.DB) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		err := db.PingContext(ctx)
		if err == nil {
			return nil
		}
		var e *sqlite.Error
		if !errors.As(err, &e) || (e.Code()&255 != 5 && e.Code()&255 != 6) {
			return ledgerError(ctx, err)
		}
		t := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

func (l *Ledger) Close() error { return l.db.Close() }

func (l *Ledger) write(ctx context.Context, fn func(*sql.Conn) error) error {
	c, err := l.db.Conn(ctx)
	if err != nil {
		return ledgerError(ctx, err)
	}
	defer c.Close()
	if _, err := c.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		_ = c.Raw(func(any) error { return driver.ErrBadConn })
		return ledgerError(ctx, err)
	}
	committed := false
	defer func() {
		if !committed {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := c.ExecContext(cleanup, "ROLLBACK"); err != nil {
				_ = c.Raw(func(any) error { return driver.ErrBadConn })
			}
		}
	}()
	if err := fn(c); err != nil {
		return err
	}
	if _, err := c.ExecContext(ctx, "COMMIT"); err != nil {
		return ledgerError(ctx, err)
	}
	committed = true
	return nil
}

func (l *Ledger) check(ctx context.Context) error {
	var result string
	if err := l.db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&result); err != nil || result != "ok" {
		return ErrLedger
	}
	rows, err := l.db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return ErrLedger
	}
	defer rows.Close()
	if rows.Next() || rows.Err() != nil {
		return ErrLedger
	}
	return nil
}

func ledgerError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	var e *sqlite.Error
	if errors.As(err, &e) && e.Code()&255 == 19 {
		return ErrConflict
	}
	return ErrLedger // Raw SQL, proof material and request data never escape.
}

func digest(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
