package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// UpgradeWithBackup is an explicit offline operator action. Stop all metadata
// writers before calling. Open remains fail-closed for old schema versions.
// The destination must be a new file in a private directory; a SQLite snapshot
// is created, integrity/history checked, fsynced and hashed before migration.
// A failed migration retains the verified backup and rolls back schema changes.
func UpgradeWithBackup(ctx context.Context, path, backup string) (string, error) {
	source, e := os.Lstat(path)
	if e != nil || !source.Mode().IsRegular() || source.Mode().Perm()&0077 != 0 {
		return "", ErrInvalidInput
	}
	if filepath.Clean(path) == filepath.Clean(backup) {
		return "", ErrInvalidInput
	}
	dir, e := os.Lstat(filepath.Dir(backup))
	if e != nil || !dir.IsDir() || dir.Mode()&os.ModeSymlink != 0 || dir.Mode().Perm()&0077 != 0 {
		return "", ErrInvalidInput
	}
	if _, e = os.Lstat(backup); !os.IsNotExist(e) {
		return "", ErrInvalidInput
	}
	db, e := openDatabase(ctx, path)
	if e != nil {
		return "", e
	}
	s := &Store{db: db}
	defer s.Close()
	list, e := loadMigrations()
	if e != nil {
		return "", e
	}
	if e = s.migrate(ctx, list); !errors.Is(e, ErrUpgradeRequired) {
		if e == nil {
			return "", ErrInvalidInput
		}
		return "", e
	}
	if e = s.CheckIntegrity(ctx); e != nil {
		return "", e
	}
	// VACUUM INTO creates a consistent standalone snapshot, including WAL data.
	if _, e = db.ExecContext(ctx, "VACUUM INTO ?", backup); e != nil {
		return "", databaseError(ctx, e)
	}
	if e = os.Chmod(backup, 0600); e != nil {
		return "", ErrDatabase
	}
	copyDB, e := openDatabase(ctx, backup)
	if e != nil {
		return "", e
	}
	copyStore := &Store{db: copyDB}
	e = copyStore.CheckIntegrity(ctx)
	if e == nil {
		e = copyStore.migrate(ctx, list)
		if errors.Is(e, ErrUpgradeRequired) {
			e = nil
		} else if e == nil {
			e = ErrIntegrity
		}
	}
	_ = copyStore.Close()
	if e != nil {
		return "", e
	}
	f, e := os.OpenFile(backup, os.O_RDWR, 0)
	if e != nil {
		return "", ErrDatabase
	}
	defer f.Close()
	if e = f.Sync(); e != nil {
		return "", ErrDatabase
	}
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", ErrDatabase
	}
	parent, e := os.Open(filepath.Dir(backup))
	if e != nil {
		return "", ErrDatabase
	}
	e = parent.Sync()
	_ = parent.Close()
	if e != nil {
		return "", ErrDatabase
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if e = s.migrateMode(ctx, list, true); e != nil {
		return sum, e
	}
	return sum, s.CheckIntegrity(ctx)
}
