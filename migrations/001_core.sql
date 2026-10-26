-- P1-M02: management metadata only. Never mount this DB into workloads.
CREATE TABLE users (
    id TEXT PRIMARY KEY NOT NULL,
    username TEXT NOT NULL UNIQUE CHECK (length(username) BETWEEN 1 AND 128 AND username = lower(username)),
    password_hash TEXT NOT NULL CHECK (length(password_hash) BETWEEN 1 AND 1024),
    disabled_at INTEGER,
    auth_epoch INTEGER NOT NULL DEFAULT 1 CHECK (auth_epoch > 0),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE roles (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE CHECK (name IN ('admin', 'user'))
) STRICT;
INSERT INTO roles (id, name) VALUES ('admin', 'admin'), ('user', 'user');

CREATE TABLE user_roles (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    PRIMARY KEY (user_id, role_id)
) STRICT;
CREATE INDEX user_roles_role ON user_roles(role_id);

CREATE TABLE sessions (
    id TEXT PRIMARY KEY NOT NULL,
    token_hash TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64 AND token_hash NOT GLOB '*[^0-9a-f]*'),
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    kind TEXT NOT NULL CHECK (kind IN ('portal', 'pending_mfa')),
    mfa_level INTEGER NOT NULL DEFAULT 0 CHECK (mfa_level IN (0, 1)),
    auth_epoch INTEGER NOT NULL CHECK (auth_epoch > 0),
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    idle_expires_at INTEGER NOT NULL,
    absolute_expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    CHECK (created_at <= last_seen_at AND last_seen_at <= idle_expires_at AND idle_expires_at <= absolute_expires_at)
) STRICT;
CREATE INDEX sessions_user ON sessions(user_id);
CREATE INDEX sessions_expiry ON sessions(absolute_expires_at);

CREATE TABLE application_categories (
    id TEXT PRIMARY KEY NOT NULL,
    label TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 128),
    sort_order INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE applications (
    id TEXT PRIMARY KEY NOT NULL,
    slug TEXT NOT NULL UNIQUE CHECK (length(slug) BETWEEN 1 AND 63 AND slug = lower(slug)),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 128),
    category_id TEXT REFERENCES application_categories(id) ON DELETE RESTRICT,
    owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    state TEXT NOT NULL DEFAULT 'enabled' CHECK (state IN ('enabled', 'disabled', 'deleted')),
    active_deployment_id TEXT,
    deployment_generation INTEGER NOT NULL DEFAULT 0 CHECK (deployment_generation BETWEEN 0 AND 9007199254740991),
    acl_epoch INTEGER NOT NULL DEFAULT 1 CHECK (acl_epoch > 0),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (active_deployment_id, id) REFERENCES deployments(id, app_id) ON DELETE RESTRICT
) STRICT;
CREATE INDEX applications_owner ON applications(owner_id);
CREATE INDEX applications_category ON applications(category_id);

CREATE TABLE application_permissions (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE RESTRICT,
    permission TEXT NOT NULL CHECK (permission = 'access'),
    granted_by TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, application_id)
) STRICT;
CREATE INDEX application_permissions_app ON application_permissions(application_id);

CREATE TABLE git_repositories (
    id TEXT PRIMARY KEY NOT NULL,
    canonical_url TEXT NOT NULL CHECK (length(canonical_url) BETWEEN 12 AND 2048),
    allowed_origin TEXT NOT NULL CHECK (length(allowed_origin) BETWEEN 1 AND 253),
    owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL
) STRICT;
CREATE INDEX git_repositories_owner ON git_repositories(owner_id);

CREATE TABLE git_branches (
    id TEXT PRIMARY KEY NOT NULL,
    repository_id TEXT NOT NULL REFERENCES git_repositories(id) ON DELETE RESTRICT,
    ref_name TEXT NOT NULL CHECK (length(ref_name) BETWEEN 1 AND 255),
    last_observed_sha TEXT CHECK (last_observed_sha IS NULL OR ((length(last_observed_sha) = 40 OR length(last_observed_sha) = 64) AND last_observed_sha NOT GLOB '*[^0-9a-f]*')),
    checked_at INTEGER,
    UNIQUE (repository_id, ref_name)
) STRICT;

CREATE TABLE deployments (
    id TEXT PRIMARY KEY NOT NULL,
    app_id TEXT NOT NULL REFERENCES applications(id) ON DELETE RESTRICT,
    branch_id TEXT NOT NULL REFERENCES git_branches(id) ON DELETE RESTRICT,
    submitted_by TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK (state IN ('SUBMITTED', 'VALIDATING', 'CLONING', 'BUILDING', 'SCANNING', 'APPROVED', 'DEPLOYING', 'HEALTH_CHECK', 'RUNNING', 'FAILED', 'CANCELLED', 'ROLLED_BACK')),
    generation INTEGER NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    attempt INTEGER NOT NULL DEFAULT 1 CHECK (attempt > 0),
    previous_id TEXT,
    idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 16 AND 128),
    request_hash TEXT NOT NULL CHECK (length(request_hash) = 64 AND request_hash NOT GLOB '*[^0-9a-f]*'),
    commit_sha TEXT CHECK (commit_sha IS NULL OR ((length(commit_sha) = 40 OR length(commit_sha) = 64) AND commit_sha NOT GLOB '*[^0-9a-f]*')),
    image_digest TEXT CHECK (image_digest IS NULL OR (length(image_digest) = 71 AND substr(image_digest, 1, 7) = 'sha256:' AND substr(image_digest, 8) NOT GLOB '*[^0-9a-f]*')),
    spec_json TEXT CHECK (spec_json IS NULL OR (length(spec_json) <= 131072 AND json_valid(spec_json))),
    spec_hash TEXT,
    policy_version TEXT,
    failure_code TEXT,
    deadline_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (id, app_id),
    UNIQUE (app_id, generation),
    UNIQUE (app_id, idempotency_key),
    FOREIGN KEY (previous_id, app_id) REFERENCES deployments(id, app_id) ON DELETE RESTRICT
) STRICT;
CREATE INDEX deployments_app_time ON deployments(app_id, created_at);
CREATE INDEX deployments_state_deadline ON deployments(state, deadline_at);
-- One unfinished rollout per application; an existing RUNNING app may be updated.
CREATE UNIQUE INDEX deployments_inflight_app ON deployments(app_id)
    WHERE state NOT IN ('RUNNING', 'FAILED', 'CANCELLED', 'ROLLED_BACK');

CREATE TABLE deployment_events (
    id TEXT PRIMARY KEY NOT NULL,
    deployment_id TEXT NOT NULL,
    app_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    generation INTEGER NOT NULL CHECK (generation > 0),
    attempt INTEGER NOT NULL CHECK (attempt > 0),
    event_type TEXT NOT NULL,
    from_state TEXT CHECK (from_state IS NULL OR from_state IN ('SUBMITTED', 'VALIDATING', 'CLONING', 'BUILDING', 'SCANNING', 'APPROVED', 'DEPLOYING', 'HEALTH_CHECK', 'RUNNING', 'FAILED', 'CANCELLED', 'ROLLED_BACK')),
    to_state TEXT NOT NULL CHECK (to_state IN ('SUBMITTED', 'VALIDATING', 'CLONING', 'BUILDING', 'SCANNING', 'APPROVED', 'DEPLOYING', 'HEALTH_CHECK', 'RUNNING', 'FAILED', 'CANCELLED', 'ROLLED_BACK')),
    reason_code TEXT NOT NULL CHECK (reason_code IN ('requested', 'validated', 'started', 'completed', 'policy_denied', 'timeout', 'error', 'cancelled', 'rollback_verified')),
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('user', 'controller', 'worker')),
    actor_id TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (deployment_id, sequence),
    CHECK (event_type = 'deployment.' || lower(to_state)),
    CHECK ((sequence = 1) = (from_state IS NULL)),
    CHECK (sequence != 1 OR to_state = 'SUBMITTED'),
    FOREIGN KEY (deployment_id, app_id) REFERENCES deployments(id, app_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE audit_events (
    id TEXT PRIMARY KEY NOT NULL,
    deployment_event_id TEXT UNIQUE REFERENCES deployment_events(id) ON DELETE RESTRICT,
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('user', 'controller', 'worker', 'operator', 'anonymous')),
    actor_id TEXT,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL CHECK (target_type IN ('deployment', 'user', 'session', 'application', 'infrastructure')),
    target_id TEXT,
    correlation_id TEXT NOT NULL,
    sanitized_metadata TEXT NOT NULL CHECK (length(sanitized_metadata) <= 4096 AND json_valid(sanitized_metadata)),
    created_at INTEGER NOT NULL,
    CHECK ((actor_kind = 'anonymous') = (actor_id IS NULL))
) STRICT;
CREATE INDEX audit_events_time ON audit_events(created_at);
CREATE INDEX audit_events_actor ON audit_events(actor_kind, actor_id, created_at);
CREATE INDEX audit_events_target ON audit_events(target_id, created_at);

CREATE TABLE outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE REFERENCES deployment_events(id) ON DELETE RESTRICT,
    event_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL REFERENCES deployments(id) ON DELETE RESTRICT,
    payload TEXT NOT NULL CHECK (length(payload) <= 4096 AND json_valid(payload)),
    created_at INTEGER NOT NULL,
    delivered_at INTEGER CHECK (delivered_at IS NULL OR delivered_at >= created_at)
) STRICT;
CREATE INDEX outbox_pending ON outbox(id) WHERE delivered_at IS NULL;

CREATE TRIGGER deployment_events_no_update BEFORE UPDATE ON deployment_events BEGIN
    SELECT RAISE(ABORT, 'deployment events are append-only');
END;
CREATE TRIGGER deployment_events_no_delete BEFORE DELETE ON deployment_events BEGIN
    SELECT RAISE(ABORT, 'deployment events are append-only');
END;
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;
CREATE TRIGGER outbox_payload_immutable BEFORE UPDATE OF id, event_id, event_type, aggregate_id, payload, created_at ON outbox BEGIN
    SELECT RAISE(ABORT, 'outbox payload is immutable');
END;
