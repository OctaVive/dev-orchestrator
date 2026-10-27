//go:build linux

package provisioner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOwnedFileIdentityAcrossDeviceRenumbering(t *testing.T) {
	uuid := "675dde3db1884deaa4068e8d084e2ac2"
	for _, tc := range []struct {
		name                   string
		dev, ino               uint64
		uuid                   string
		currentDev, currentIno uint64
		currentUUID            string
		want                   bool
	}{
		{"stable filesystem moved", 2049, 42, uuid, 65025, 42, uuid, true},
		{"different filesystem same inode", 2049, 42, uuid, 65025, 42, strings.Repeat("a", 32), false},
		{"different inode same filesystem", 2049, 42, uuid, 65025, 43, uuid, false},
		{"zero inode", 2049, 0, uuid, 65025, 0, uuid, false},
		{"legacy unchanged", 2049, 42, "", 2049, 42, uuid, true},
		{"legacy cannot infer migration", 2049, 42, "", 65025, 42, uuid, false},
		{"new identity never falls back to device", 2049, 42, uuid, 2049, 42, "", false},
		{"malformed UUID", 2049, 42, "invalid", 2049, 42, "invalid", false},
		{"zero UUID", 2049, 42, strings.Repeat("0", 32), 2049, 42, strings.Repeat("0", 32), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameOwnedFile(tc.dev, tc.ino, tc.uuid, tc.currentDev, tc.currentIno, tc.currentUUID); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestFilesystemUUIDFromOpenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned")
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	uuid, e := fileFilesystemUUID(f)
	if e != nil {
		t.Fatal(e)
	}
	if uuid == "" {
		t.Skip("kernel lacks filesystem UUID ioctl; legacy device check retained")
	}
	i, e := f.Stat()
	if e != nil {
		t.Fatal(e)
	}
	st := i.Sys().(*syscall.Stat_t)
	if e = verifyOwnedFile(f, i, uint64(st.Dev)^1, st.Ino, uuid); e != nil {
		t.Fatal("same owned inode rejected after device renumbering", e)
	}
	if e = verifyOwnedFile(f, i, uint64(st.Dev), st.Ino, strings.Repeat("a", 32)); !errors.Is(e, ErrConflict) {
		t.Fatal("different filesystem accepted", e)
	}
	if e = verifyOwnedFile(f, i, uint64(st.Dev)^1, st.Ino, ""); !errors.Is(e, ErrConflict) {
		t.Fatal("legacy identity silently migrated", e)
	}
}

func TestMatrixHostV16FilesystemIdentity(t *testing.T) {
	b := matrixBackend(t, "idle")
	for _, which := range []string{"renumbered", "foreign-filesystem", "legacy-mismatch"} {
		t.Run(which, func(t *testing.T) {
			m := labMachine(t, b, time.Minute)
			labCreate(t, b, m)
			ctx := matrixContext(t, 20*time.Second)
			l, e := b.lock(ctx)
			if e != nil {
				t.Fatal(e)
			}
			s, e := b.read(m.Lease.JobID)
			if e != nil {
				unlock(l)
				t.Fatal(e)
			}
			if s.DiskFSUUID == "" || s.ReadyFSUUID == "" {
				unlock(l)
				t.Fatal("lab kernel did not capture disk/ready filesystem UUIDs")
			}
			original := s
			// Restore only this test record's original identity before registered cleanup.
			t.Cleanup(func() {
				lock, e := b.lock(context.Background())
				if e != nil {
					t.Error(e)
					return
				}
				defer unlock(lock)
				current, e := b.read(m.Lease.JobID)
				if e != nil {
					t.Error(e)
					return
				}
				current.DiskDev = original.DiskDev
				current.ReadyDev = original.ReadyDev
				current.DiskFSUUID = original.DiskFSUUID
				current.ReadyFSUUID = original.ReadyFSUUID
				if e = b.write(current); e != nil {
					t.Error(e)
				}
			})
			switch which {
			case "renumbered":
				s.DiskDev ^= 1
				s.ReadyDev ^= 1
			case "foreign-filesystem":
				s.DiskFSUUID = strings.Repeat("a", 32)
			case "legacy-mismatch":
				s.DiskFSUUID = ""
				s.DiskDev ^= 1
			}
			e = b.write(s)
			unlock(l)
			if e != nil {
				t.Fatal(e)
			}
			result, e := b.Cleanup(ctx, m)
			if which == "renumbered" {
				if e != nil || !result.VMAbsent || !result.ArtifactsAbsent || !result.StartFenced {
					t.Fatal("renumbered cleanup", result, e)
				}
				t.Log("disk and ready cleaned using filesystem UUID/inode despite changed device numbers")
			} else {
				if !errors.Is(e, ErrConflict) {
					t.Fatal("mismatched identity accepted", result, e)
				}
				if _, e = os.Stat(filepath.Join(b.c.Root, m.Lease.JobID+".raw")); e != nil {
					t.Fatal("mismatched disk not retained", e)
				}
				t.Log("mismatched identity retained the disk and fence")
			}
		})
	}
}

// This maintenance case is an explicit, exact-record enrollment for legacy
// journals which predate UUID capture. It never guesses a filesystem migration.
// Expected identity/content and a new root-owned backup directory are mandatory.
// The normal backend continues rejecting legacy device-number mismatches.
func TestLinuxMaintenanceRecoverLegacyFilesystem(t *testing.T) {
	job := os.Getenv("M04_RECOVER_JOB")
	if job == "" {
		t.Skip("exact legacy recovery not requested")
	}
	b := hostLab(t)
	if !identifier.MatchString(job) {
		t.Fatal("invalid recovery job")
	}
	oldDev, e := strconv.ParseUint(os.Getenv("M04_RECOVER_DEVICE"), 10, 64)
	if e != nil {
		t.Fatal(e)
	}
	ino, e := strconv.ParseUint(os.Getenv("M04_RECOVER_INODE"), 10, 64)
	if e != nil || ino == 0 {
		t.Fatal("expected inode required", e)
	}
	uuid := os.Getenv("M04_RECOVER_FS_UUID")
	hash := os.Getenv("M04_RECOVER_SHA256")
	hashBytes, hashErr := hex.DecodeString(hash)
	if !sameOwnedFile(oldDev, ino, uuid, oldDev, ino, uuid) || hashErr != nil || len(hashBytes) != 32 {
		t.Fatal("expected UUID/hash required")
	}
	backup := os.Getenv("M04_RECOVERY_BACKUP")
	if info, e := trustedPath(backup, true); e != nil || !info.IsDir() {
		t.Fatal("new private root-owned backup directory required", e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	l, e := b.lock(ctx)
	if e != nil {
		t.Fatal(e)
	}
	s, e := b.read(job)
	if e != nil {
		unlock(l)
		t.Fatal(e)
	}
	boot, e := bootID()
	if e != nil {
		unlock(l)
		t.Fatal(e)
	}
	if s.Machine.Lease.JobID != job || !validMachine(s.Machine, b.c) || !s.Fenced || s.BootID == boot || !time.Now().After(s.Machine.Lease.ExpiresAt) || s.DiskDev != oldDev || s.DiskIno != ino || s.DiskFSUUID != "" || s.ReadyIno != 0 {
		unlock(l)
		t.Fatal("legacy record does not match expired, fenced, prior-boot recovery expectations")
	}
	for _, name := range []string{unitName(job), expiryName(job) + ".timer", expiryName(job) + ".service"} {
		exists, active, e := b.namedUnit(ctx, s.Machine, name)
		if e != nil || active {
			unlock(l)
			t.Fatal("unit ownership/absence unconfirmed", name, exists, active, e)
		}
	}
	if e = confirmGuestGroupEmpty(job); e != nil {
		unlock(l)
		t.Fatal(e)
	}
	raw := filepath.Join(b.c.Root, job+".raw")
	info, e := trustedPath(raw, true)
	if e != nil {
		unlock(l)
		t.Fatal(e)
	}
	f, e := os.OpenFile(raw, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if e != nil {
		unlock(l)
		t.Fatal(e)
	}
	defer f.Close()
	before, e := f.Stat()
	if e != nil || !os.SameFile(info, before) {
		unlock(l)
		t.Fatal("file changed before verification", e)
	}
	st := before.Sys().(*syscall.Stat_t)
	currentUUID, e := fileFilesystemUUID(f)
	if e != nil || currentUUID != uuid || !before.Mode().IsRegular() || st.Uid != 0 || st.Nlink != 1 || st.Ino != ino || before.Size() != 10<<30 {
		unlock(l)
		t.Fatal("file does not match explicit recovery identity", e)
	}
	original, e := os.ReadFile(b.statePath(job))
	unlock(l)
	if e != nil {
		t.Fatal(e)
	}
	// Full content verification is maintenance evidence, outside the unchanged
	// 20-second production create/cleanup policy. No guest is running/admitted.
	h := sha256.New()
	if _, e = io.CopyBuffer(h, f, make([]byte, 1<<20)); e != nil {
		t.Fatal(e)
	}
	if hex.EncodeToString(h.Sum(nil)) != hash {
		t.Fatal("disk content differs from reviewed evidence")
	}
	after, e := f.Stat()
	if e != nil {
		t.Fatal(e)
	}
	a := after.Sys().(*syscall.Stat_t)
	if !os.SameFile(before, after) || a.Size != st.Size || a.Mtim != st.Mtim || a.Ctim != st.Ctim {
		t.Fatal("disk changed during content verification")
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel2()
	l, e = b.lock(ctx2)
	if e != nil {
		t.Fatal(e)
	}
	current, e := b.read(job)
	if e != nil || !sameMachine(current.Machine, s.Machine) || !current.Fenced || current.DiskDev != oldDev || current.DiskIno != ino || current.DiskFSUUID != "" {
		unlock(l)
		t.Fatal("record changed during verification", e)
	}
	pathInfo, e := os.Lstat(raw)
	if e != nil || !os.SameFile(after, pathInfo) {
		unlock(l)
		t.Fatal("path changed during verification", e)
	}
	// Durable backup and allowlisted audit precede the single enrollment write.
	writeBackup := func(name string, data []byte) error {
		f, e := os.OpenFile(filepath.Join(backup, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
		if e != nil {
			return e
		}
		_, e = f.Write(data)
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e != nil {
			return e
		}
		return closeErr
	}
	audit, e := json.MarshalIndent(struct {
		Job, FilesystemUUID, SHA256          string
		RecordedDevice, CurrentDevice, Inode uint64
		Boot                                 string
	}{job, uuid, hash, oldDev, uint64(st.Dev), ino, boot}, "", "  ")
	if e != nil {
		unlock(l)
		t.Fatal(e)
	}
	if e = writeBackup(job+".legacy.json", original); e == nil {
		e = writeBackup(job+".recovery.json", audit)
	}
	if e == nil {
		dir, err := os.Open(backup)
		if err != nil {
			e = err
		} else {
			e = dir.Sync()
			dir.Close()
		}
	}
	if e != nil {
		unlock(l)
		t.Fatal(e)
	}
	current.DiskFSUUID = uuid // Keep original DiskDev as historical audit metadata.
	e = b.write(current)
	unlock(l)
	if e != nil {
		t.Fatal(e)
	}
	cleanupCtx, stop := context.WithTimeout(context.Background(), 20*time.Second)
	defer stop()
	result, e := b.Cleanup(cleanupCtx, current.Machine)
	if e != nil || !result.VMAbsent || !result.ArtifactsAbsent || !result.StartFenced {
		t.Fatal("enrolled record cleanup unconfirmed", result, e)
	}
	final, e := b.read(job)
	if e != nil || !final.Fenced || final.DiskDev != oldDev || final.DiskFSUUID != uuid {
		t.Fatal("historical device/fence not preserved", e)
	}
	t.Log("exact legacy filesystem identity enrolled; normal backend cleanup confirmed; original proof/state and fence retained", job)
}
