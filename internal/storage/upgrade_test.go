package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestCloneSchemaUpgradeRequiresVerifiedBackup(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "old.db")
	db, e := openDatabase(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	s := &Store{db: db}
	list, _ := loadMigrations()
	if e = s.migrate(ctx, list[:1]); e != nil {
		t.Fatal(e)
	}
	seed(t, s)
	submit(t, s)
	_ = s.Close()
	if _, e = Open(ctx, path); !errors.Is(e, ErrUpgradeRequired) {
		t.Fatal("automatic upgrade", e)
	}
	backup := filepath.Join(dir, "verified-backup.db")
	sum, e := UpgradeWithBackup(ctx, path, backup)
	if e != nil || len(sum) != 64 {
		t.Fatal(sum, e)
	}
	s, e = Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if scalar(t, s, "SELECT count(*) FROM deployments") != 1 || scalar(t, s, "PRAGMA user_version") != 2 {
		t.Fatal("upgrade lost data")
	}
	if _, e = Open(ctx, backup); !errors.Is(e, ErrUpgradeRequired) {
		t.Fatal("backup changed", e)
	}
	if _, e = UpgradeWithBackup(ctx, path, backup); e == nil {
		t.Fatal("backup overwrite")
	}
}
