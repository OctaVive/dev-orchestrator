# P1-M03 - Bootstrap admin, Argon2id, sessions, CSRF and role middleware

Status: **Implemented/tested**.

## Requirement and acceptance contract

- Scope: Bootstrap admin, Argon2id, sessions, CSRF and role middleware.
- Prerequisites: [P1-M02](../P1M02/README.md).
- Acceptance gate: SEC-01/02, setup replay/session fixation/rate-limit tests pass.
- Source: [PH1 minimal plan](../../../plans/PH1/minimal.md).
- Requirements: [project requirements](../../requirements.md), [requirement-to-milestone map](../../requirement-milestones.md) and [evidence checklist](../../requirement-evidence.md).
- Security coverage: SEC-01, SEC-02, SEC-10, SEC-12.

## Documents

- [auth core](auth-core.md)
- [api design](../../specifications/api-design.md)

## Implementation history and validation

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

