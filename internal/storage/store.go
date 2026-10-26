// Package storage owns the management SQLite database. It is not an
// authorization boundary: callers must supply already-authorized intents.
package storage

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"modernc.org/sqlite"
)

var (
	ErrInvalidInput    = errors.New("invalid metadata operation")
	ErrNotFound        = errors.New("metadata record not found")
	ErrConflict        = errors.New("metadata version, generation or idempotency conflict")
	ErrInvalidState    = errors.New("invalid deployment state transition")
	ErrSchemaMismatch  = errors.New("metadata migration history does not match this binary")
	ErrUpgradeRequired = errors.New("metadata upgrade requires a verified backup and an explicit upgrade workflow")
	ErrIntegrity       = errors.New("metadata integrity check failed")
	ErrDatabase        = errors.New("metadata database operation failed")
)

// Store uses one pooled connection to serialize writes within this process.
// SQLite BEGIN IMMEDIATE also serializes writes/migrations across processes.
// Do not expose this handle or mount its database into application containers.
type Store struct {
	db *sql.DB
}

// Open accepts an operator-controlled local file path, never a SQLite URI or
// request parameter. Its parent must already be a private, service-owned local
// directory; Unix permissions are checked, Windows ACLs are the operator's duty.
// Network filesystems, shared DB files and multi-controller operation are unsupported.
func Open(ctx context.Context, path string) (*Store, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	db, err := openDatabase(ctx, path)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	list, err := loadMigrations()
	if err == nil {
		err = s.migrate(ctx, list)
	}
	if err == nil {
		err = s.CheckIntegrity(ctx)
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func openDatabase(ctx context.Context, path string) (*sql.DB, error) {
	if path == "" || strings.HasPrefix(path, "file:") || path == ":memory:" ||
		strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, "//") {
		return nil, ErrInvalidInput
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, ErrInvalidInput
	}
	parent, err := os.Lstat(filepath.Dir(abs))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 ||
		runtime.GOOS != "windows" && parent.Mode().Perm()&0077 != 0 {
		return nil, errors.New("metadata parent must be an existing private directory")
	}
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err == nil {
		if err := f.Close(); err != nil {
			return nil, ErrDatabase
		}
	} else if !errors.Is(err, os.ErrExist) {
		return nil, ErrDatabase
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("metadata file must be a private regular file, not a symlink")
	}
	uriPath := filepath.ToSlash(abs)
	if filepath.VolumeName(abs) != "" {
		uriPath = "/" + uriPath
	}
	u := url.URL{Scheme: "file", Path: uriPath}
	q := url.Values{}
	// Applied to every physical connection, including a replacement after error.
	for _, pragma := range []string{"busy_timeout(5000)", "foreign_keys(ON)", "journal_mode(WAL)", "synchronous(FULL)", "trusted_schema(OFF)"} {
		q.Add("_pragma", pragma)
	}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, ErrDatabase
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := initializeConnection(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	var journal string
	var foreignKeys, synchronous int
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil || journal != "wal" {
		db.Close()
		return nil, ErrDatabase
	}
	if err := db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil || foreignKeys != 1 {
		db.Close()
		return nil, ErrDatabase
	}
	if err := db.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil || synchronous != 2 {
		db.Close()
		return nil, ErrDatabase
	}
	return db, nil
}

// Concurrent first open may briefly return SQLITE_BUSY while another handle
// switches the new file into WAL. SQLite does not invoke its busy handler for
// every journal-mode race, so retry only these transient errors within a bound.
func initializeConnection(ctx context.Context, db *sql.DB) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		err := db.PingContext(ctx)
		if err == nil {
			return nil
		}
		var sqliteError *sqlite.Error
		if !errors.As(err, &sqliteError) || (sqliteError.Code()&0xff != 5 && sqliteError.Code()&0xff != 6) {
			return databaseError(ctx, err)
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (s *Store) Close() error { return s.db.Close() }

// write holds no network/build operations. A rollback is attempted with a fresh
// bounded context even if the caller cancels. A failed rollback discards the
// physical connection so no transaction can leak into its next pooled use.
func (s *Store) write(ctx context.Context, fn func(*sql.Conn) error) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return databaseError(ctx, err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		// A cancellation/I/O error can make BEGIN's outcome uncertain. Drop
		// this connection rather than risk pooling a live transaction.
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		return databaseError(ctx, err)
	}
	committed := false
	defer func() {
		if !committed {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := conn.ExecContext(cleanup, "ROLLBACK"); err != nil {
				// Returning driver.ErrBadConn forces database/sql to discard it.
				_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			}
		}
	}()
	if err := fn(conn); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		// Outcome may be uncertain after I/O failure. Caller must reread/retry
		// by idempotency/version, never blindly replay external effects.
		return databaseError(ctx, err)
	}
	committed = true
	return nil
}

func databaseError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	var sqliteError *sqlite.Error
	if errors.As(err, &sqliteError) && sqliteError.Code()&0xff == 19 { // SQLITE_CONSTRAINT
		if sqliteError.Code() == 1555 || sqliteError.Code() == 2067 { // PRIMARYKEY / UNIQUE
			return ErrConflict
		}
		return ErrInvalidInput
	}
	return ErrDatabase // Do not expose SQL, driver errors or secret field values.
}

// CheckIntegrity checks SQLite consistency and foreign keys. It is not a backup
// verification or defense against a host attacker able to rewrite the DB.
func (s *Store) CheckIntegrity(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, "PRAGMA quick_check")
	if err != nil {
		return databaseError(ctx, err)
	}
	valid := false
	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil || result != "ok" {
			rows.Close()
			return ErrIntegrity
		}
		valid = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil || !valid {
		return ErrIntegrity
	}
	rows, err = s.db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return databaseError(ctx, err)
	}
	defer rows.Close()
	if rows.Next() || rows.Err() != nil {
		return ErrIntegrity
	}
	return nil
}
