# PH1 implementation progress

## P1-M01 — contract and test foundation

Status: foundation implemented and unit/contract checks passing; ready for review. This increment deliberately implements no listener, deployment runner or infrastructure changes. The existing 39 architecture/plan documents are preserved, with their index updated for implementation status.

### Deliverables

- `go.mod`, `go.sum`: Go module and pinned JSON Schema validation dependency.
- `api/{common,deployment,agent}.schema.json`: version 1, unknown fields denied on structured objects. Environment dictionaries intentionally permit bounded user keys.
- `api/openapi.yaml`: initial submit/status HTTP design contract; no handler implementation implied.
- `internal/domain`: state topology and default-deny principal permission helpers.
- `internal/contracts`: body/depth/UTF-8/duplicate/trailing checks, compiled local schemas, typed request decoding, lexical Git/path validation, worker/expiry/generation checks.
- `tests/fixtures`: accepted contract data, mutation tests and future Compose/network/execution fixture inventory.
- [Capability and requirement evidence checklist](ph1-capability-checklist.md).

### Contract decisions / limitations

- IDs are lowercase canonical UUIDs; commands use safe integer generations ≤2^53−1. Agent leases may be at most 5 minutes, deployment bodies at most 64 KiB, commands 128 KiB, JSON nesting 32.
- Numeric tokens must be decimal integers fitting signed 64-bit range; exponent/fraction/oversized encodings are rejected before schema arithmetic. Future command signing/replay rules are specified in `api/README.md`, but cryptographic enforcement remains unimplemented.
- `restricted-v1` hard controls are backend-owned, not caller-disableable flags. No raw Compose, Docker options, host paths or proxy directives exist in command contracts.
- Managed mount targets initially limited to `/data` and named descendants. This is an intentionally small first contract; broader approved app directories require policy/schema review. Duplicate/overlapping mounts are rejected.
- Runtime env is bounded data; orchestrator/Docker/BuildKit control prefixes are reserved. Real secret reference materialization is M10, not an invitation to put management credentials in env.
- URL checks are lexical only, never DNS resolution or egress enforcement. DNS rebinding and allowed public-host exfiltration remain unresolved until worker network controls exist.
- `DecodeAgentCommand` accepts structurally valid signature bytes, **not a verified signature**. The fixture signature is dummy data. No function executes these commands. Signature verification, durable replay storage, app/volume ownership, registry policy and measured engine enforcement are M09/M10 duties.
- Principal helpers assume an already verified server-side session and current exact-app grant. They are not login middleware or an ACL cache.
- State helper validates legal edges only, not transaction durability or rollback health evidence.

### Validation

Executed on the Windows development host using Go 1.27.3 from a portable, SHA-256-verified official archive under the approved temporary directory (no system PATH change):

| Check | Result |
|---|---|
| `go test -count=1 -cover ./...` | PASS: contracts 89.9%, domain 100%; API resource package has no executable logic |
| `go vet ./...` | PASS |
| `go mod verify` | PASS, pinned schema validator v6.0.3 and x/text v0.43.0 |
| `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...` | PASS: cross-compilation only, not Linux execution |
| Markdown local link check | PASS, zero broken links |
| Deployment decoder fuzz, 10 s / 2 workers | PASS, 16,335 executions |
| Agent decoder fuzz, 10 s / 2 workers | PASS, 2,418 executions |

No Linux VM/security release gate can be proven by these Windows unit/contract checks. OpenAPI is an initial design contract, not implemented or end-to-end validated HTTP behavior. Fuzz runs are bounded smoke tests, not proof of parser correctness or complete denial-of-service resistance.

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

## P1-M03 — secure setup, authentication and role-gated API

Status: implemented and validation passing; ready for review. [Authentication API/runbook](auth-core.md) describes operator setup and limitations. No production listener is left running by implementation.

### Deliverables

- `internal/auth`: current-profile Argon2id passwords, strong new-password policy/offline common list, dummy verification, two-slot KDF admission, bounded account/IP/global limiters, opaque sessions, setup expiry and session-bound CSRF.
- `internal/storage/auth.go`: atomic first admin + durable setup marker, password/epoch recheck at session issuance, hashed token storage, previous-session rotation, idle/absolute expiry/current roles on every lookup, atomic logout/audit and sanitized failure audit.
- `internal/httpapi`: separate portal/operator handlers, exact TLS Host/Origin checks, signed pre-login/setup nonces, strict credentials decoding, Secure/HttpOnly/host-only cookies, no-store JSON and backend role gates.
- `cmd/api`: explicit TLS/configuration entrypoint, distinct literal-loopback operator listener, protected bounded token/private-key file loading and graceful shutdown.
- `api/login.schema.json`, updated OpenAPI: actual auth/setup/status routes, no role/session mass assignment. Deployment routes remain explicitly unimplemented.
- Tests: real Argon2id/SQLite, one-time setup races/replay/expiry, mutation/CSRF/header/cookie confusion, role changes, outage/rotation/revocation, limiter bounds, actual local TLS 1.3 browser-like flow/TLS 1.2 rejection and CLI startup/shutdown smoke.

No migration-001 edits or existing-data upgrades were needed. There is no GUI, user/ACL management UI, MFA, application proxy, worker authority or actual deployment submission. Public setup is not a route gated merely by a forwarded loopback address: the portal listener never registers it, and the separate operator listener must never be published/proxied.

### Validation

Executed with portable Go 1.27.3 on Windows:

| Check | Result |
|---|---|
| `go test -count=1 -cover ./...` | PASS: CLI 70.5%, auth 84.6%, HTTP API 86.7%, storage 83.0%, contracts 89.9%, domain 100% |
| Actual temporary TLS authentication workflow | PASS: nonce, login, secure-cookie session, logout, old session denied; TLS 1.2 handshake rejected |
| CLI TLS startup/graceful shutdown | PASS with temporary self-signed test certificate and explicitly trusted test root; no insecure verification bypass |
| Bootstrap/audit atomicity, CSRF/fixation/header/role/outage/expiry tests | PASS |
| `go vet ./...` | PASS |
| `go mod verify` | PASS, including pinned x/crypto v0.58.0 |
| `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...` | PASS, compilation only |
| Local Markdown links | PASS, zero broken links |

No Linux runtime/permission/race-detector result, comprehensive breached-password screening, complete DoS resistance, penetration test or full secure-MVP release gate is claimed. The small offline password list, per-process rate limiting and shared proxy-IP limitation are explicit in the runbook. All production deployment execution remains unavailable.

Credentials decoder fuzz smoke: PASS, 22,042 executions with a 10-second budget and two workers. This is bounded regression evidence, not proof of complete parser/DoS correctness.

## P1-M04 — provisioner lease/mTLS core (PARTIAL)

Historical foundation status (superseded by the Linux implementation increment below): core implemented; real Linux backend and guest-create/destroy/expiry acceptance not completed at this point. No VM, service installation, image download, hypervisor command or network change was performed.

### Deliverables

- `api/build-lease.schema.json`, `api/provisioner.openapi.yaml`: bounded controller-only protocol; fixed template/profile IDs, immutable ≤30-minute deadline, no XML/path/network/shell/credential input.
- `internal/provisioner`: separate host-private SQLite namespace/schema/checksum, one-slot reservation, immutable identity/deadline/tombstones, command/nonce replay prevention, transactional versioned lifecycle events and ownership proof kept off the wire.
- Cleanup/expiry/restart reconciliation and independent guard loop; capacity retained on failure or partial cleanup. A fresh guard heartbeat and every backend enforcement control are required before admission.
- `internal/provisionerrpc`: real TLS 1.3 mutual auth, explicit client CA, pinned short-lived controller leaf, exact URI SAN and per-request expiry checks; no portal cookie/Origin/identity-header fallback.
- `cmd/provisioner`: loopback-only contract prototype. **Only UnconfiguredBackend is linked**, no simulator/unsafe fallback flag. Capabilities report false; create returns 503; unsupported guard does not claim readiness.
- Tests: actual SQLite and local mTLS; test-only simulated VM state for idempotency, quota specification, expiry, cleanup failures, cancellation/late-start fencing, foreign resource protection and interrupted-startup reconciliation. The simulator is not linked into production.

### Acceptance still blocked

The driver does not implement KVM/libvirt, pinned image measurement, host quotas, broker/disconnected networking, a host-monotonic hard kill or real late-start fencing. No mock result proves those controls. Real build execution is deliberately unavailable, and P1-M04 must not be marked complete based on these tests.

### Verification of the implemented core

Executed with portable Go 1.27.3 on Windows:

| Check | Result |
|---|---|
| Full uncached test suite with coverage | PASS: provisioner core 77.6%, provisioner mTLS 70.6%, prototype command 47.6%, contracts 90.4%; previous auth/storage/API regression tests also pass |
| Late-start/cancellation/concurrent-create model tests, `-count=20` | PASS; these use test-only simulated VM maps, not real guests |
| Real local mTLS tests | PASS: missing/untrusted/expired clients rejected, pinned worker URI denied, unpinned controller denied, reused connection expiry rechecked; shipped backend create remains 503 |
| Build-lease decoder fuzz, 10 s / two workers | PASS, 279,950 executions; bounded smoke evidence only |
| `go vet ./...` | PASS |
| `go mod verify` | PASS; no new dependencies introduced |
| Linux amd64 CGO-disabled cross-compilation | PASS, not Linux runtime execution |
| Local Markdown links | PASS, zero broken links |

No actual KVM, host firewall/quota, independent kernel timer, Linux permissions or race-detector result is claimed. No VM image, production credential, service installation or host network setting was created/changed.

## P1-M04 — Linux execution increment

Status: **Linux backend code implemented; mandatory real-host acceptance NOT RUN / NOT PASSED.**

- Explicit `linux-kvm` backend, fail-closed on non-Linux/unsupported/unconfigured hosts; default disabled, no simulator/TCG/container fallback.
- Direct QEMU under systemd instead of libvirt: fixed non-root QEMU command, no NIC/control socket/host mount, inherited raw-disk FD set and seccomp sandbox.
- Pinned credential-free operator-supplied raw boot image (<=1 GiB), copied and measured into a preallocated 10 GiB private disk, file-size bound and total 1000 IOPS throttle; systemd CPU/RAM/swap/tasks envelope.
- Durable root-private ownership/boot-time journals, immutable boot-ID/deadline, system-wide flock/start fencing, PID-1 absolute BOOTTIME alarm expiry plus timerfd supervisor and unit runtime cap.
- Ownership description, file inode/device/link and empty-cgroup checks before confirmed cleanup; foreign/unknown files quarantine capacity; fences retained permanently.
- Host example configuration and reviewed service assets/runbook in `infra/builder/`; no install/enable/image download performed by development work.
- Opt-in real-host tests for VM lifecycle, kernel envelope, independent expiry with SIGSTOPed supervisor and foreign-disk preservation. Ordinary tests explicitly skip privileged host cases.
- **Mandatory acceptance:** [Linux checklist](../testing/P1-M04-linux-checklist.md) + [real-host procedure](../testing/P1-M04-real-host.md) + [signed report](../testing/P1-M04-acceptance-report.md). Every required real workload/fault case must actually pass before M04 PASS. Model tests and cross-compilation are not substitutes.

The Windows suite passes and Linux provisioner tests cross-compile. Linux/KVM runtime, race detector, boot-image review and real enforcement evidence remain pending. M05–M14 remain unimplemented.

Verification for this increment: full uncached `go test -p 1 -count=1 ./...`, Windows and Linux-targeted `go vet ./...`, `go mod verify`, Linux amd64 production build/test-binary cross-compilation, Bash fixture syntax and documentation links passed. The initial full-suite invocation hit its 120-second tool timeout; a complete rerun with a 300-second tool budget passed without changing test/policy deadlines. No privileged Linux fixture build or host acceptance test was executed.

### Next work: finish P1-M04 on an approved Linux lab

Resolve Q01/Q05 (Linux host, virtualization, resources and quota/network mechanisms), then implement/review the fixed Linux backend and independent host deadline/fence. Record actual guest create/destroy, resource exhaustion, controller/provisioner/guard loss and expired-lease inventory evidence before linking it into the executable. Start with no-NIC test guests; M05 must separately prove controlled egress before M06/M07 real repository cloning/building. P1-M08 policy work remains independently implementable without enabling execution.
