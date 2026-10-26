package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
	"time"

	"dev-orchestrator/migrations"
)

type migration struct {
	version  int
	name     string
	checksum string
	sql      string
}

var migrationName = regexp.MustCompile(`^([0-9]{3})_[a-z0-9_]+\.sql$`)

func loadMigrations() ([]migration, error) { return readMigrations(migrations.Files) }

func readMigrations(files fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(files, ".")
	if err != nil {
		return nil, ErrSchemaMismatch
	}
	var list []migration
	for _, entry := range entries { // ReadDir is lexically sorted.
		if entry.IsDir() {
			return nil, ErrSchemaMismatch
		}
		parts := migrationName.FindStringSubmatch(entry.Name())
		if parts == nil {
			return nil, ErrSchemaMismatch
		}
		version, _ := strconv.Atoi(parts[1])
		if version != len(list)+1 {
			return nil, ErrSchemaMismatch
		}
		b, err := fs.ReadFile(files, entry.Name())
		if err != nil || len(b) == 0 {
			return nil, ErrSchemaMismatch
		}
		sum := sha256.Sum256(b)
		list = append(list, migration{version: version, name: entry.Name(), checksum: hex.EncodeToString(sum[:]), sql: string(b)})
	}
	if len(list) == 0 {
		return nil, ErrSchemaMismatch
	}
	return list, nil
}

func (s *Store) migrate(ctx context.Context, list []migration) error {
	if len(list) == 0 {
		return ErrSchemaMismatch
	}
	// This is the startup version lock, not a lock file subject to stale PID
	// cleanup. SQLite releases the write lock on process death.
	return s.write(ctx, func(conn *sql.Conn) error {
		if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY CHECK (version > 0),
            name TEXT NOT NULL UNIQUE,
            checksum TEXT NOT NULL CHECK (length(checksum) = 64),
            applied_at INTEGER NOT NULL
        ) STRICT`); err != nil {
			return ErrSchemaMismatch
		}
		rows, err := conn.QueryContext(ctx, "SELECT version, name, checksum FROM schema_migrations ORDER BY version")
		if err != nil {
			return ErrSchemaMismatch
		}
		applied := 0
		for rows.Next() {
			var version int
			var name, checksum string
			if err := rows.Scan(&version, &name, &checksum); err != nil || version != applied+1 || version > len(list) {
				rows.Close()
				return ErrSchemaMismatch
			}
			m := list[version-1]
			if m.version != version || m.name != name || m.checksum != checksum {
				rows.Close()
				return ErrSchemaMismatch
			}
			applied++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return ErrSchemaMismatch
		}
		var userVersion int
		if err := conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&userVersion); err != nil || userVersion != applied {
			return ErrSchemaMismatch
		}
		if applied > 0 && applied < len(list) {
			// Initial schema bootstrap is automatic. Future existing-data upgrades
			// deliberately stop until a verified-backup workflow is implemented.
			return ErrUpgradeRequired
		}
		for _, m := range list[applied:] {
			if _, err := conn.ExecContext(ctx, m.sql); err != nil {
				return fmt.Errorf("apply embedded migration %s: %w", m.name, ErrSchemaMismatch)
			}
			if _, err := conn.ExecContext(ctx, "INSERT INTO schema_migrations (version,name,checksum,applied_at) VALUES (?,?,?,?)",
				m.version, m.name, m.checksum, time.Now().UTC().UnixNano()); err != nil {
				return ErrSchemaMismatch
			}
			// Only the trusted integer migration version is rendered into SQL.
			if _, err := conn.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", m.version)); err != nil {
				return ErrSchemaMismatch
			}
		}
		return nil
	})
}
