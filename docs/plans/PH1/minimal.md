# PH1 — Minimal secure core

## Objective and scope

Ship an admin-only GUI that builds approved public HTTPS Git repositories and deploys Dockerfile/basic Compose apps behind an authenticated gateway. Includes secure login, sidebar, branch selection, bounded logs/status, managed persistence and SQLite. No public apps, arbitrary Git credentials or forced embedding.

Architecture: management VM + disposable KVM builder + separate rootless runtime VM; Go/React/SQLite/NGINX. Baseline controls in all architecture documents are mandatory. Dependencies: Q01/Q05 resolved for integration, operator-approved lab and schemas in implementation specs. No preceding product phase.

## Proposed files/components

`api/*.yaml`, `api/*.schema.json`, `internal/{auth,acl,jobs,policy,storage,gitfetch,proxy}`, `cmd/*`, `migrations/001_*`, `web/src/{auth,layout,apps,deployments}`, `infra/{builder,runtime}`, `tests/{contract,security,integration}`. Create only within implementation-approved scope.

## Tasks and gates

| ID | Task / output | Depends | Complexity | Acceptance gate |
|---|---|---|---|---|
| P1-M01 | Scaffold domain/protocol contracts and fixture inventory; document capability checklist | None | M | Schemas reject unknown fields; security requirements mapped to tests |
| P1-M02 | Initial SQLite migrations, version lock and state/outbox transaction adapter | M01 | M | FK/integrity and crash-atomic transition tests pass |
| P1-M03 | Bootstrap admin, Argon2id, sessions, CSRF and role middleware | M02 | L | SEC-01/02, setup replay/session fixation/rate-limit tests pass |
| P1-M04 | Fixed VM template/provisioner contract and hard-expiry lifecycle | M01 | L | Guest create/destroy/expired lease proven; no arbitrary XML/path input |
| P1-M05 | External build egress broker and firewall template | M04 | L | IPv4/IPv6 internal, metadata and direct internet denied in guest |
| P1-M06 | Clone runner with HTTPS/ref/context limits and malicious Git fixtures | M05 | M | Rebinding/helper/submodule/redirect corpus denied, SHA recorded |
| P1-M07 | Rootless BuildKit export and isolated ingest/scanner adapter | M06 | L | Digest matches, budgets kill guest, hostile archives quarantined |
| P1-M08 | Strict Compose/Dockerfile normalization and agent policy contract | M01 | L | SEC-06; one Dockerfile and two-service subset fixtures accepted |
| P1-M09 | Runtime capability probe and typed agent create/inspect/stop | M08 | L | SEC-05/08/16; real engine constraints verified, no host ports |
| P1-M10 | Managed volume ownership/quota and secret-reference adapter | M09 | M | SEC-09; wrong-app mounts and unbounded storage rejected |
| P1-M11 | HTTP auth gateway, private relay path and atomic exact-host route activation | M03,M09 | L | SEC-03/04/13; forged headers and auth outage denied |
| P1-M12 | Job controller main state machine, cancellation and orphan reconciliation | M02,M07,M10,M11 | L | All transitions/timeouts auditable; SEC-11/17 pass |
| P1-M13 | Login/sidebar/admin deploy wizard, timeline and text-only bounded logs | M03,M12 | L | End-to-end submit/health/access/stop; non-admin direct API denied |
| P1-M14 | Secure-core acceptance harness and operator setup/backup smoke runbook | M13 | M | All PH1 release gates recorded with versions and no blockers |

Parallelism: M02/M04/M08 after M01; M03 alongside M05/M06; M09 and M07 after own dependencies; M10/M11 independently. UI layout/mock forms may proceed after M01 but no completion before M12. Runtime/build integration remains sequential through release gate.

## Security and testing

mTLS roles and command expiry in M04/M09; no service tokens in untrusted builds. Baseline vulnerability gate blocks known exploited/fixable critical images; fail closed on missing scan. Test secret fixture redaction and escaped log output. Full role deny tests even though user UI is deferred. Use [test strategy](../../implementation/testing-strategy.md), not fake-network tests alone.

## Risks / complexity / definition of done

High complexity, roughly 7–12 engineer-weeks before review/contingency. Rootless connectivity and externally enforceable quotas are highest uncertainty. Private Git and sensitive build secrets remain unsupported. Password-only admin login is not equivalent to MFA: advance P3 tasks if required. Done only after real isolated build → immutable scan → private runtime → authorized route succeeds and malicious/cancelled jobs leave no unauthorized resources; limitations and restore basics documented.
