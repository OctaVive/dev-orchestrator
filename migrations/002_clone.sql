-- Clone events use their own transactional queue because the original
-- deployment event contract permits only state-transition event names.
CREATE TABLE clone_attempts (
    job_id TEXT PRIMARY KEY NOT NULL,
    deployment_id TEXT NOT NULL REFERENCES deployments(id) ON DELETE RESTRICT,
    attempt INTEGER NOT NULL CHECK(attempt > 0),
    generation INTEGER NOT NULL CHECK(generation > 0),
    expected_version INTEGER NOT NULL CHECK(expected_version > 0),
    lease_id TEXT NOT NULL UNIQUE,
    policy_hash TEXT NOT NULL CHECK(length(policy_hash)=64 AND policy_hash NOT GLOB '*[^0-9a-f]*'),
    template_digest TEXT NOT NULL,
    job_hash TEXT NOT NULL CHECK(length(job_hash)=64),
    expires_at INTEGER NOT NULL,
    commit_sha TEXT CHECK(commit_sha IS NULL OR (length(commit_sha)=40 AND commit_sha NOT GLOB '*[^0-9a-f]*')),
    outcome TEXT NOT NULL CHECK(outcome IN ('pending','resolved','success','error','denied','limit','timeout','cancelled')),
    result_json TEXT CHECK(result_json IS NULL OR (length(result_json)<=4096 AND json_valid(result_json))),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(deployment_id,attempt)
) STRICT;
CREATE TABLE clone_events (
    id TEXT PRIMARY KEY NOT NULL,
    job_id TEXT NOT NULL REFERENCES clone_attempts(job_id) ON DELETE RESTRICT,
    event_type TEXT NOT NULL CHECK(event_type IN ('clone.resolved','clone.success','clone.error','clone.denied','clone.limit','clone.timeout','clone.cancelled')),
    payload TEXT NOT NULL CHECK(length(payload)<=4096 AND json_valid(payload)),
    created_at INTEGER NOT NULL,
    UNIQUE(job_id,event_type)
) STRICT;
CREATE TABLE clone_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE REFERENCES clone_events(id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL,
    delivered_at INTEGER CHECK(delivered_at IS NULL OR delivered_at >= created_at)
) STRICT;
CREATE TRIGGER clone_events_no_update BEFORE UPDATE ON clone_events BEGIN
    SELECT RAISE(ABORT,'clone events are append-only');
END;
CREATE TRIGGER clone_events_no_delete BEFORE DELETE ON clone_events BEGIN
    SELECT RAISE(ABORT,'clone events are append-only');
END;
CREATE TRIGGER clone_binding_immutable BEFORE UPDATE OF job_id,deployment_id,attempt,generation,lease_id,policy_hash,template_digest,job_hash,expires_at,created_at ON clone_attempts BEGIN
    SELECT RAISE(ABORT,'clone binding is immutable');
END;
CREATE TRIGGER clone_sha_immutable BEFORE UPDATE OF commit_sha ON clone_attempts WHEN OLD.commit_sha IS NOT NULL AND NEW.commit_sha IS NOT OLD.commit_sha BEGIN
    SELECT RAISE(ABORT,'clone SHA is immutable');
END;
CREATE TRIGGER deployment_sha_immutable BEFORE UPDATE OF commit_sha ON deployments WHEN OLD.commit_sha IS NOT NULL AND NEW.commit_sha IS NOT OLD.commit_sha BEGIN
    SELECT RAISE(ABORT,'deployment SHA is immutable');
END;
CREATE TRIGGER clone_outbox_payload_immutable BEFORE UPDATE OF id,event_id,created_at ON clone_outbox BEGIN
    SELECT RAISE(ABORT,'clone outbox identity is immutable');
END;
