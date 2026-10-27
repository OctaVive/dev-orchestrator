# P1-M02 - Initial SQLite migrations, version lock and state/outbox transaction adapter

Status: **Implemented/tested**.

## Requirement and acceptance contract

- Scope: Initial SQLite migrations, version lock and state/outbox transaction adapter.
- Prerequisites: [P1-M01](../P1M01/README.md).
- Acceptance gate: FK/integrity and crash-atomic transition tests pass.
- Source: [PH1 minimal plan](../../../plans/PH1/minimal.md).
- Requirements: [project requirements](../../requirements.md), [requirement-to-milestone map](../../requirement-milestones.md) and [evidence checklist](../../requirement-evidence.md).
- Security coverage: SEC-17.

## Documents

- [sqlite storage](sqlite-storage.md)

## Implementation history and validation

## P1-M02 — SQLite metadata and atomic state/outbox storage

Status: implemented and validation passing; ready for review. See [storage contract](sqlite-storage.md) for APIs and explicit limitations.

### Deliverables

- `migrations/{embed.go,001_core.sql}`: strict initial metadata tables, ownership/FK/enum constraints, uniqueness/indexes, immutable deployment/audit history and seeded role names (no default accounts).
- `internal/storage/{store,migrate}.go`: private file setup, per-connection WAL/FK/FULL-sync/busy PRAGMAs, bounded initial-WAL race retry, BEGIN IMMEDIATE startup lock, checksums/contiguous versions/user_version checks and integrity verification.
- `internal/storage/{deployments,events}.go`: idempotent submit, transactional generation reservation, state/version/generation CAS, typed sanitized events/audit, ordered at-least-once outbox and idempotent acknowledgments.
- `internal/storage/{store,crash}_test.go`: actual SQLite tests, trigger-injected failures, concurrent handles/bootstrap and abrupt test-process exit before/after commit.
- Pinned pure-Go SQLite driver `modernc.org/sqlite v1.61.0`, no system SQLite/CGO installation.

### Security scope

Storage is callable only by future trusted services; it does not authenticate/authorize callers or prove health/approval. Raw repository requests/env/secrets are not accepted as event metadata. No runtime, VM, proxy or network configuration has changed. Existing-data upgrades are deliberately refused until a verified-backup upgrade workflow exists; only fresh DB bootstrap is automatic. Backups, encryption, retention and future schema tables are not claimed complete.

Tests detected a concurrent first-open WAL race. Initialization now retries only transient SQLite BUSY/LOCKED errors within a 5-second bound; concurrent bootstrap/CAS tests passed 20 repeated runs after the fix. This is not a multi-controller support claim.

### Validation

Executed with the existing portable Go 1.27.3 toolchain on Windows:

| Check | Result |
|---|---|
| `go test -count=1 -cover ./...` | PASS: storage 84.5%, contracts 89.9%, domain 100% |
| Startup/CAS tests, `-count=20` | PASS after bounded WAL initialization retry fix |
| Abrupt subprocess before transition commit | PASS: prior state/event/audit/outbox all preserved |
| Abrupt subprocess after transition commit | PASS: new state/event/audit/outbox all recovered |
| Trigger-injected outbox insert failure | PASS: state/generation/event/audit changes all rolled back |
| Migration history/checksum/version/failed-DDL tests | PASS; unknown versions and unbacked existing-data upgrades refused |
| `go vet ./...` | PASS |
| `go mod verify` | PASS |
| `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...` | PASS, compilation only |
| Local Markdown links | PASS, zero broken links |

No Linux runtime, actual power-loss/disk-failure test or race-detector run is claimed. No C compiler was found on this host for Go's Windows race-detector support. Unit tests exercise actual SQLite concurrency, but are not a substitute for a future Linux `go test -race ./...` run and filesystem-specific recovery/permissions checks.

