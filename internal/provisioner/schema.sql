-- Independent HOST ledger. This is NOT a management metadata migration.
CREATE TABLE ledger_meta (
    id INTEGER PRIMARY KEY CHECK (id=1),
    checksum TEXT NOT NULL CHECK (length(checksum)=64)
) STRICT;
CREATE TABLE guard (
    id INTEGER PRIMARY KEY CHECK (id=1),
    heartbeat_at INTEGER NOT NULL CHECK (heartbeat_at>=0)
) STRICT;
INSERT INTO guard VALUES (1,0);
CREATE TABLE leases (
    job_id TEXT PRIMARY KEY NOT NULL,
    command_id TEXT NOT NULL UNIQUE,
    controller_id TEXT NOT NULL,
    app_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    template_id TEXT NOT NULL,
    template_digest TEXT NOT NULL,
    profile_id TEXT NOT NULL CHECK (profile_id='build-small-v1'),
    fingerprint TEXT NOT NULL CHECK (length(fingerprint)=64),
    nonce_hash TEXT NOT NULL UNIQUE CHECK (length(nonce_hash)=64),
    ownership_proof TEXT NOT NULL CHECK (length(ownership_proof)=64),
    state TEXT NOT NULL CHECK (state IN ('RESERVED','STARTING','ACTIVE','CLEANUP_PENDING','CLEANUP_FAILED','CLEANED')),
    version INTEGER NOT NULL CHECK (version>0),
    reason TEXT NOT NULL CHECK (reason IN ('requested','starting','started','released','expired','create_failed','start_timeout','clock_invalid','controls_lost','cleanup_failed','retry','cleaned')),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at>created_at),
    slot INTEGER NOT NULL DEFAULT 1 CHECK (slot=1)
) STRICT;
CREATE UNIQUE INDEX one_build_slot ON leases(slot) WHERE state!='CLEANED';
CREATE INDEX leases_expiry ON leases(expires_at) WHERE state!='CLEANED';
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL REFERENCES leases(job_id) ON DELETE RESTRICT,
    version INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('RESERVED','STARTING','ACTIVE','CLEANUP_PENDING','CLEANUP_FAILED','CLEANED')),
    reason TEXT NOT NULL CHECK (reason IN ('requested','starting','started','released','expired','create_failed','start_timeout','clock_invalid','controls_lost','cleanup_failed','retry','cleaned')),
    created_at INTEGER NOT NULL,
    UNIQUE(job_id,version)
) STRICT;
CREATE TRIGGER immutable_lease BEFORE UPDATE OF job_id,command_id,controller_id,app_id,deployment_id,template_id,template_digest,profile_id,fingerprint,nonce_hash,ownership_proof,created_at,expires_at,slot ON leases BEGIN
    SELECT RAISE(ABORT,'lease identity and deadline are immutable');
END;
CREATE TRIGGER no_lease_delete BEFORE DELETE ON leases BEGIN
    SELECT RAISE(ABORT,'lease tombstones cannot be reused');
END;
CREATE TRIGGER no_event_update BEFORE UPDATE ON events BEGIN
    SELECT RAISE(ABORT,'events are append-only');
END;
CREATE TRIGGER no_event_delete BEFORE DELETE ON events BEGIN
    SELECT RAISE(ABORT,'events are append-only');
END;
