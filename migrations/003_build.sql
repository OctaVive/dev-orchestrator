-- M07 admission is distinct from deployment approval.
CREATE TABLE build_attempts (
 job_id TEXT PRIMARY KEY NOT NULL REFERENCES clone_attempts(job_id) ON DELETE RESTRICT,
 deployment_id TEXT NOT NULL REFERENCES deployments(id) ON DELETE RESTRICT,
 attempt INTEGER NOT NULL CHECK(attempt>0),
 generation INTEGER NOT NULL CHECK(generation>0),
 job_hash TEXT NOT NULL CHECK(length(job_hash)=71),
 job_json TEXT NOT NULL CHECK(length(job_json)<=32768 AND json_valid(job_json)),
 expires_at INTEGER NOT NULL,
 expected_version INTEGER NOT NULL CHECK(expected_version>0),
 stage TEXT NOT NULL CHECK(stage IN ('building','scanning','admitted','denied','limit','timeout','cancelled','error')),
 object_id TEXT,
 archive_digest TEXT,
 archive_bytes INTEGER CHECK(archive_bytes IS NULL OR archive_bytes>0),
 result_json TEXT CHECK(result_json IS NULL OR (length(result_json)<=8192 AND json_valid(result_json))),
 created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL,
 UNIQUE(deployment_id,attempt)
) STRICT;
CREATE TABLE build_events (
 id TEXT PRIMARY KEY NOT NULL,
 job_id TEXT NOT NULL REFERENCES build_attempts(job_id) ON DELETE RESTRICT,
 event_type TEXT NOT NULL CHECK(event_type IN ('build.started','build.exported','scan.admitted','scan.denied','scan.limit','scan.timeout','scan.cancelled','scan.error')),
 payload TEXT NOT NULL CHECK(length(payload)<=8192 AND json_valid(payload)),
 created_at INTEGER NOT NULL,
 UNIQUE(job_id,event_type)
) STRICT;
CREATE TABLE build_outbox (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 event_id TEXT NOT NULL UNIQUE REFERENCES build_events(id) ON DELETE RESTRICT,
 created_at INTEGER NOT NULL,
 delivered_at INTEGER CHECK(delivered_at IS NULL OR delivered_at>=created_at)
) STRICT;
CREATE TRIGGER build_events_no_update BEFORE UPDATE ON build_events BEGIN SELECT RAISE(ABORT,'build events are append-only'); END;
CREATE TRIGGER build_events_no_delete BEFORE DELETE ON build_events BEGIN SELECT RAISE(ABORT,'build events are append-only'); END;
CREATE TRIGGER build_binding_immutable BEFORE UPDATE OF job_id,deployment_id,attempt,generation,job_hash,job_json,expires_at,created_at ON build_attempts BEGIN SELECT RAISE(ABORT,'build binding is immutable'); END;
CREATE TRIGGER build_result_immutable BEFORE UPDATE ON build_attempts WHEN OLD.result_json IS NOT NULL BEGIN SELECT RAISE(ABORT,'build result is immutable'); END;
CREATE TRIGGER build_outbox_immutable BEFORE UPDATE OF id,event_id,created_at ON build_outbox BEGIN SELECT RAISE(ABORT,'build outbox is immutable'); END;
CREATE TRIGGER deployment_digest_immutable BEFORE UPDATE OF image_digest ON deployments WHEN OLD.image_digest IS NOT NULL AND NEW.image_digest IS NOT OLD.image_digest BEGIN SELECT RAISE(ABORT,'deployment digest is immutable'); END;
