# PH1 metadata storage (P1-M02)

## Implemented boundary

`internal/storage` owns a local SQLite metadata file via pinned pure-Go `modernc.org/sqlite`; no CGO/server dependency. `migrations/001_core.sql` and its embedded resource define the initial schema. This is persistence, **not session authentication or deployment execution**. Methods require already-authorized service calls; no HTTP or public SQL/transaction handle is exposed.

Initial tables: users, roles, user-role links, sessions, application categories, applications, per-app grants, Git repositories/branches, deployments, immutable deployment events, general audit events, outbox and migration history. Later phases/tasks add runtime containers, volumes, secret references, logs, worker leases and MFA-specific storage with reviewed migrations. Role seed values are `admin` and `user`; no default user/password/session is created.

## Open / permissions / connections

- `Open(ctx, path)` accepts only an operator-controlled filename. SQLite `file:` URIs, memory mode and UNC paths are rejected; filename characters are URL-encoded rather than interpreted as DSN options.
- Parent directory must already exist and be service-owned/private. Unix parent must have no group/other permission bits and not be a direct symlink. New DB files are 0600; existing nonregular/symlink or publicly accessible files are rejected. Ancestor ownership/mount type and Windows ACL protection are operator responsibilities; application input must never choose this path.
- No network filesystems, shared app mounts or multi-controller support. Same-host secondary handles are tested for SQLite locking, not a claim of HA.
- One pooled connection per store serializes reads/writes initially. Foreign keys ON, WAL, synchronous FULL, busy timeout 5 s and trusted_schema OFF are applied to **every physical connection**. This favors small, short metadata transactions; no build/network I/O belongs inside a transaction.
- `CheckIntegrity` runs SQLite `quick_check` and `foreign_key_check`. Open also checks these after migration. Neither test is proof of backup validity, encryption or resistance to a host attacker.

## Migration startup lock / compatibility

`BEGIN IMMEDIATE` holds SQLite's cross-process writer lock during the complete history/version check and initial DDL. Each embedded `NNN_name.sql` has a SHA-256 checksum; filenames/versions must be contiguous from 001. `schema_migrations` stores version/name/checksum/time, and `PRAGMA user_version` must agree with its contiguous history.

Unknown future versions, changed checksums/names, missing records and inconsistent user_version cause startup refusal, without resetting or overwriting data. DDL, history writes and user_version changes are committed together; a failed migration rolls all of them back. Process death releases the SQLite lock; there is no stale PID lock file to delete.

SQL checkout line endings are pinned to LF in `.gitattributes` so the same migration has the same checksum on Windows and Linux.

**Only initial empty-database bootstrap is automatic.** A known older, nonempty migration history with pending migrations returns `ErrUpgradeRequired`. An explicit verified-backup upgrade workflow must be implemented before existing databases can be upgraded. This task does not copy live WAL files, implement backup encryption or restore, or claim to meet PH5 recovery gates. Never delete migration records/checksums to bypass refusal or edit an already-released migration.

## Deployment writes

`Create` receives IDs, an idempotency key and a deterministic hash of the complete approved intent. The caller owns validation, admin/CSRF/ownership enforcement and canonical request hashing. Raw repository content, runtime env and secrets are not stored through this API.

One write transaction:

1. Reuse same app/key only when hash, submitting user and branch match; return the original attempt without duplicate events.
2. Require enabled application and reserve its next generation (bounded to 2^53−1).
3. Insert `SUBMITTED` deployment at version 1. A partial unique index rejects a second unfinished rollout for the same app. Existing RUNNING/history records do not block updates.
4. Insert sequence-1 event, matching audit entry and pending outbox message.
5. Commit; any error rolls back the entire operation, including generation reservation.

`Advance` validates the domain transition topology and closed reason vocabulary, then compares expected state, version and deployment generation under a writer transaction. It increments version and inserts matching event/audit/outbox rows before commit. Version is the event sequence. Terminal attempts are not reset for retry. `rollback_verified` is required for a ROLLED_BACK edge, but the **controller must actually verify rollback health**; a reason code is not evidence.

This adapter does not decide latest-app rollout ownership, worker identity, image approval, health, route generation, deadline enforcement or cancellation compensation. Those remain M09/M12 responsibilities. A newer rollout must not be allowed to publish stale results just because its DB write passed.

## Events, audit and outbox

Typed payload contains event/deployment/app/actor/correlation IDs, type, from/to states, sequence, generation, attempt, closed reason and UTC time. There is no arbitrary metadata map, URL, command, env or build output. Driver failures return safe sentinel errors rather than raw SQL values. Deployment/audit history is append-only by triggers; a host/database owner can still tamper and external audit remains future work.

`Events` returns bounded sequence pages; `PendingOutbox` returns bounded insertion-ordered pages for one dispatcher. The same event ID links event/audit/outbox. Delivery is **at least once**, never exactly once. Consumers deduplicate by event ID, perform durable handling, then `MarkDelivered`; acknowledgments are idempotent. A crash after send but before ack causes redelivery. Dispatch, retention and multi-consumer leases are not implemented yet.

After a commit I/O error the outcome can be uncertain: reread by idempotency key or deployment version before deciding to retry. Do not replay external actions blindly. Cancelled/panicking transactions attempt rollback with an independent bounded context; connections with failed cleanup are discarded.

## Tests / remaining assurances

Tests cover bootstrap/reopen, per-connection PRAGMAs, FKs, strict types/enum constraints, same-app active pointer, immutable history, idempotency/generation reservation, CAS across separate handles, cancelled/panicking transactions, injected outbox failure, failed DDL rollback, concurrent startup and checksum/version refusal. Fixed test-binary subprocesses exit abruptly before and after a transition commit to exercise WAL recovery of all four records.

These are actual SQLite tests on the development host, not fake storage. Abrupt process exit does **not** simulate sudden power loss, broken disks, Linux filesystem permission/locking behavior or host compromise. Linux execution/permissions tests, application-consistent backup/restore, DB encryption/key management, full auth endpoints and deploy/cancel/route races are still pending.
