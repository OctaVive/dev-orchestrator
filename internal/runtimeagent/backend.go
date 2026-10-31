package runtimeagent

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"strings"

	"dev-orchestrator/internal/contracts"
)

const backendMigration = `
CREATE TABLE backend_capacity (singleton INTEGER PRIMARY KEY CHECK(singleton=1), apps INTEGER NOT NULL, memory INTEGER NOT NULL, disk INTEGER NOT NULL);
CREATE TABLE backend_reservations (app TEXT PRIMARY KEY, socket TEXT NOT NULL UNIQUE, data_root TEXT NOT NULL UNIQUE, reservation BLOB NOT NULL, memory INTEGER NOT NULL, disk INTEGER NOT NULL);
CREATE TABLE backends (app TEXT PRIMARY KEY REFERENCES backend_reservations(app), socket TEXT NOT NULL UNIQUE, data_root TEXT NOT NULL UNIQUE, daemon TEXT NOT NULL UNIQUE, userns TEXT NOT NULL UNIQUE, binding BLOB NOT NULL, memory INTEGER NOT NULL, disk INTEGER NOT NULL);
PRAGMA user_version=2;
`

// BackendBinding is operator-owned state, never decoded from an execution command.
// Memory includes daemon overhead plus workload capacity. Disk includes a separate
// image/unpack allowance for this app; shared digest caches are not assumed.
// Reservations have no automatic release: uncertain cleanup retains all charges.
type BackendBinding struct {
	DaemonPID                                                              int
	DaemonStartTicks                                                       uint64
	BootID                                                                 string
	AppID, Socket, DataRoot, DaemonID, UserNamespace, InitialUserNamespace string
	UIDMapHash, GIDMapHash                                                 string
	DaemonMemory, WorkloadMemory, ImageDisk, WorkloadDisk                  int64
}
type BackendCapacity struct {
	Apps         int
	Memory, Disk int64
}

var userNamespace = regexp.MustCompile(`^user:\[[1-9][0-9]{0,19}\]$`)

// BackendReservation is persisted before the provisioner starts a daemon. A
// crash before binding still consumes capacity and retains exclusive paths.
type BackendReservation struct {
	AppID, Socket, DataRoot                               string
	DaemonMemory, WorkloadMemory, ImageDisk, WorkloadDisk int64
}

func (b BackendBinding) Reservation() BackendReservation {
	return BackendReservation{b.AppID, b.Socket, b.DataRoot, b.DaemonMemory, b.WorkloadMemory, b.ImageDisk, b.WorkloadDisk}
}
func (b BackendReservation) Valid() bool {
	pathOK := func(p string) bool {
		return len(p) <= 4096 && filepath.IsAbs(p) && filepath.Clean(p) == p && p != "/" && !strings.ContainsAny(p, "\x00\r\n")
	}
	return contracts.ValidJobID(b.AppID) && pathOK(b.Socket) && pathOK(b.DataRoot) && b.DaemonMemory > 0 && b.WorkloadMemory > 0 && b.ImageDisk > 0 && b.WorkloadDisk > 0 && b.DaemonMemory <= 1<<50 && b.WorkloadMemory <= 1<<50 && b.ImageDisk <= 1<<60 && b.WorkloadDisk <= 1<<60
}
func (b BackendBinding) Valid() bool {
	return b.Reservation().Valid() && b.DaemonPID > 1 && b.DaemonPID <= 1<<30 && b.DaemonStartTicks > 0 && contracts.ValidJobID(b.BootID) && len(b.DaemonID) > 0 && len(b.DaemonID) <= 128 && !strings.ContainsAny(b.DaemonID, "\x00\r\n") && userNamespace.MatchString(b.UserNamespace) && userNamespace.MatchString(b.InitialUserNamespace) && b.UserNamespace != b.InitialUserNamespace && contracts.ValidDigest(b.UIDMapHash) && contracts.ValidDigest(b.GIDMapHash)
}

// ConfigureBackends pins capacity durably. Changing it requires explicit operator
// reconciliation; reopening the process cannot shrink/reset existing reservations.
func (l *Ledger) ConfigureBackends(ctx context.Context, c BackendCapacity) error {
	if c.Apps < 1 || c.Apps > 1024 || c.Memory < 1 || c.Memory > 1<<60 || c.Disk < 1 || c.Disk > 1<<62 {
		return ErrDenied
	}
	return l.transaction(ctx, func(tx *sql.Tx) error {
		var old BackendCapacity
		err := tx.QueryRowContext(ctx, "SELECT apps,memory,disk FROM backend_capacity WHERE singleton=1").Scan(&old.Apps, &old.Memory, &old.Disk)
		if err == nil {
			if old != c {
				return ErrConflict
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return ErrLedger
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO backend_capacity VALUES(1,?,?,?)", c.Apps, c.Memory, c.Disk); err != nil {
			return ErrLedger
		}
		return nil
	})
}

// ReserveBackend must commit before daemon provisioning. It never starts a process.
func (l *Ledger) ReserveBackend(ctx context.Context, b BackendReservation) error {
	if !b.Valid() {
		return ErrDenied
	}
	raw, _ := json.Marshal(b)
	return l.transaction(ctx, func(tx *sql.Tx) error {
		var prior []byte
		err := tx.QueryRowContext(ctx, "SELECT reservation FROM backend_reservations WHERE app=?", b.AppID).Scan(&prior)
		if err == nil {
			if string(prior) != string(raw) {
				return ErrConflict
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return ErrLedger
		}
		var c BackendCapacity
		if tx.QueryRowContext(ctx, "SELECT apps,memory,disk FROM backend_capacity WHERE singleton=1").Scan(&c.Apps, &c.Memory, &c.Disk) != nil {
			return ErrUnsupported
		}
		var n int
		var mem, disk int64
		if tx.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(memory),0),coalesce(sum(disk),0) FROM backend_reservations").Scan(&n, &mem, &disk) != nil {
			return ErrLedger
		}
		m, d := b.DaemonMemory+b.WorkloadMemory, b.ImageDisk+b.WorkloadDisk
		if n >= c.Apps || m > c.Memory-mem || d > c.Disk-disk {
			return ErrUnsupported
		}
		// Reject nested roots and sockets inside another app's data tree as well as
		// exact collisions. These paths come exclusively from trusted provisioning.
		rows, err := tx.QueryContext(ctx, "SELECT socket,data_root FROM backend_reservations")
		if err != nil {
			return ErrLedger
		}
		overlap := func(a, b string) bool { return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/") }
		for rows.Next() {
			var s, r string
			if rows.Scan(&s, &r) != nil {
				rows.Close()
				return ErrLedger
			}
			if overlap(b.DataRoot, r) || overlap(b.Socket, r) || overlap(s, b.DataRoot) {
				rows.Close()
				return ErrConflict
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return ErrLedger
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO backend_reservations VALUES(?,?,?,?,?,?)", b.AppID, b.Socket, b.DataRoot, raw, m, d); err != nil {
			return ErrConflict
		}
		return nil
	})
}

// BindBackend records independently measured identity after provisioning. No
// assignment may be rebound across a daemon restart without reconciliation.
func (l *Ledger) BindBackend(ctx context.Context, b BackendBinding) error {
	if !b.Valid() {
		return ErrDenied
	}
	raw, _ := json.Marshal(b)
	reservation, _ := json.Marshal(b.Reservation())
	return l.transaction(ctx, func(tx *sql.Tx) error {
		var r []byte
		if tx.QueryRowContext(ctx, "SELECT reservation FROM backend_reservations WHERE app=?", b.AppID).Scan(&r) != nil || string(r) != string(reservation) {
			return ErrConflict
		}
		var prior []byte
		err := tx.QueryRowContext(ctx, "SELECT binding FROM backends WHERE app=?", b.AppID).Scan(&prior)
		if err == nil {
			if string(prior) != string(raw) {
				return ErrConflict
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return ErrLedger
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO backends VALUES(?,?,?,?,?,?,?,?)", b.AppID, b.Socket, b.DataRoot, b.DaemonID, b.UserNamespace, raw, b.DaemonMemory+b.WorkloadMemory, b.ImageDisk+b.WorkloadDisk); err != nil {
			return ErrConflict
		}
		return nil
	})
}
func (l *Ledger) Backend(ctx context.Context, app string) (BackendBinding, error) {
	var b BackendBinding
	var raw []byte
	if !contracts.ValidJobID(app) {
		return b, ErrDenied
	}
	if l.db.QueryRowContext(ctx, "SELECT binding FROM backends WHERE app=?", app).Scan(&raw) != nil || json.Unmarshal(raw, &b) != nil || !b.Valid() || b.AppID != app {
		return BackendBinding{}, ErrDenied
	}
	return b, nil
}

// Hash binds the entire trusted assignment, including mappings and reservations.
func (b BackendBinding) Hash() string { raw, _ := json.Marshal(b); return contracts.Digest(raw) }

// Identity prevents attaching a factory to a ledger for another worker lease.
func (l *Ledger) Identity(worker, incarnation string) bool {
	return validIdentity(worker, incarnation) && l.worker == worker && l.incarnation == incarnation
}

// PinRuntimeProfile prevents a process restart from silently changing operator
// slot/tool limits beneath durable reservations. Reconciliation must be explicit.
func (l *Ledger) PinRuntimeProfile(ctx context.Context, hash string) error {
	if !contracts.ValidDigest(hash) {
		return ErrDenied
	}
	return l.transaction(ctx, func(tx *sql.Tx) error {
		var prior string
		err := tx.QueryRowContext(ctx, "SELECT hash FROM runtime_profile WHERE singleton=1").Scan(&prior)
		if err == nil {
			if prior != hash {
				return ErrConflict
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return ErrLedger
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO runtime_profile VALUES(1,?)", hash); err != nil {
			return ErrLedger
		}
		return nil
	})
}
