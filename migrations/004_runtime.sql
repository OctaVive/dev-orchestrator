-- Runtime authorization is distinct from immutable image admission and M12's
-- approval decision. Only trusted controller/operator methods issue these rows.
CREATE TABLE runtime_workers (
 worker TEXT PRIMARY KEY NOT NULL,
 incarnation TEXT NOT NULL,
 lease_until INTEGER NOT NULL,
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN(0,1)),
 inventory_key BLOB NOT NULL CHECK(length(inventory_key)=32)
) STRICT;
CREATE TABLE runtime_certificates (
 fingerprint TEXT PRIMARY KEY NOT NULL CHECK(length(fingerprint)=64),
 worker TEXT NOT NULL REFERENCES runtime_workers(worker),
 incarnation TEXT NOT NULL,
 valid_until INTEGER NOT NULL,
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN(0,1))
) STRICT;
CREATE TABLE runtime_scan_policy (singleton INTEGER PRIMARY KEY CHECK(singleton=1), policy_hash TEXT NOT NULL, database_created_at INTEGER NOT NULL) STRICT;
CREATE TABLE runtime_images (
 admission TEXT PRIMARY KEY NOT NULL,
 image TEXT NOT NULL,
 job_id TEXT NOT NULL REFERENCES build_attempts(job_id),
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN(0,1)),
 UNIQUE(admission,image)
) STRICT;
CREATE TABLE runtime_approvals (
 app TEXT NOT NULL,
 generation INTEGER NOT NULL CHECK(generation>0),
 worker TEXT NOT NULL REFERENCES runtime_workers(worker),
 incarnation TEXT NOT NULL,
 deployment TEXT NOT NULL REFERENCES deployments(id),
 spec_hash TEXT NOT NULL,
 policy_hash TEXT NOT NULL,
 spec_json TEXT NOT NULL CHECK(length(spec_json)<=65536 AND json_valid(spec_json)),
 expires_at INTEGER NOT NULL,
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN(0,1)),
 PRIMARY KEY(app,generation)
) STRICT;
CREATE TABLE runtime_fences (
 app TEXT PRIMARY KEY NOT NULL,
 generation INTEGER NOT NULL CHECK(generation>0)
) STRICT;
CREATE TABLE runtime_backends (
 worker TEXT NOT NULL REFERENCES runtime_workers(worker),
 incarnation TEXT NOT NULL,
 app TEXT NOT NULL,
 backend_hash TEXT NOT NULL,
 PRIMARY KEY(worker,incarnation,app)
) STRICT;
CREATE TABLE runtime_queue (
 command TEXT PRIMARY KEY NOT NULL,
 worker TEXT NOT NULL REFERENCES runtime_workers(worker),
 incarnation TEXT NOT NULL,
 request_hash TEXT NOT NULL,
 command_json TEXT NOT NULL CHECK(length(command_json)<=65536 AND json_valid(command_json)),
 expires_at INTEGER NOT NULL,
 created_at INTEGER NOT NULL,
 result_json TEXT CHECK(result_json IS NULL OR (length(result_json)<=65536 AND json_valid(result_json)))
) STRICT;
CREATE INDEX runtime_pending ON runtime_queue(worker,incarnation,created_at) WHERE result_json IS NULL;
CREATE TRIGGER runtime_worker_identity BEFORE UPDATE OF worker,incarnation,inventory_key ON runtime_workers BEGIN SELECT RAISE(ABORT,'runtime identity immutable'); END;
CREATE TRIGGER runtime_worker_revoked BEFORE UPDATE ON runtime_workers WHEN OLD.revoked=1 BEGIN SELECT RAISE(ABORT,'runtime revocation permanent'); END;
CREATE TRIGGER runtime_certificate_binding BEFORE UPDATE OF fingerprint,worker,incarnation,valid_until ON runtime_certificates BEGIN SELECT RAISE(ABORT,'runtime certificate binding immutable'); END;
CREATE TRIGGER runtime_certificate_revoked BEFORE UPDATE ON runtime_certificates WHEN OLD.revoked=1 BEGIN SELECT RAISE(ABORT,'runtime certificate revocation permanent'); END;
CREATE TRIGGER runtime_image_binding BEFORE UPDATE OF admission,image,job_id ON runtime_images BEGIN SELECT RAISE(ABORT,'runtime image immutable'); END;
CREATE TRIGGER runtime_image_revoked BEFORE UPDATE ON runtime_images WHEN OLD.revoked=1 BEGIN SELECT RAISE(ABORT,'runtime image revocation permanent'); END;
CREATE TRIGGER runtime_approval_binding BEFORE UPDATE OF app,generation,worker,incarnation,deployment,spec_hash,policy_hash,spec_json,expires_at ON runtime_approvals BEGIN SELECT RAISE(ABORT,'runtime approval immutable'); END;
CREATE TRIGGER runtime_approval_revoked BEFORE UPDATE ON runtime_approvals WHEN OLD.revoked=1 BEGIN SELECT RAISE(ABORT,'runtime approval revocation permanent'); END;
CREATE TRIGGER runtime_generation_monotonic BEFORE UPDATE ON runtime_fences WHEN NEW.generation<=OLD.generation BEGIN SELECT RAISE(ABORT,'runtime generation monotonic'); END;
CREATE TRIGGER runtime_backend_immutable BEFORE UPDATE ON runtime_backends BEGIN SELECT RAISE(ABORT,'runtime backend immutable'); END;
CREATE TRIGGER runtime_queue_immutable BEFORE UPDATE OF command,worker,incarnation,request_hash,command_json,expires_at,created_at ON runtime_queue BEGIN SELECT RAISE(ABORT,'runtime command immutable'); END;
CREATE TRIGGER runtime_result_immutable BEFORE UPDATE ON runtime_queue WHEN OLD.result_json IS NOT NULL BEGIN SELECT RAISE(ABORT,'runtime result immutable'); END;

CREATE UNIQUE INDEX runtime_one_create_per_generation ON runtime_queue(json_extract(command_json,'$.app_id'),json_extract(command_json,'$.generation')) WHERE json_extract(command_json,'$.operation')='create';
