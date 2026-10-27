# Test strategy and release evidence

## Layers

1. Unit/property/fuzz: URLs, refs, normalized paths, YAML limits, policy compilation, mount resolution, cookie handling, proxy rendering and state transitions. Deny unknown fields and parser differential cases.
2. Contract: OpenAPI permissions; agent spec versions, signatures/generation/idempotency; schema migrations and audit event payload redaction.
3. Linux VM integration: actual KVM guest creation/kill, rootless cgroups, network rules, managed volume quotas, immutable digest export/import and rollback. Mocks cannot prove isolation.
4. Browser: Chromium, Firefox and WebKit representative supported versions; cross-site cookies blocked/enabled, iframe CSP/XFO/sandbox, origin separation, login and ACL revocation, WS/SSE.
5. Security/chaos: malicious repos/Compose, connection-time rebinding, redirect chains, packet captures from guest, process/disk/log bombs, controller/agent/proxy crashes, stolen/replayed job token and certificate expiry.

## Acceptance suite IDs

| ID | Required assertion |
|---|---|
| SEC-01 | Anonymous management calls denied; setup unavailable after first admin |
| SEC-02 | User deployment/config/secret/ACL endpoints denied even with forged role fields |
| SEC-03 | Host port scan finds no application ports; stopped gateway gives no app path |
| SEC-04 | Direct app URL/WS requires valid session and current ACL |
| SEC-05 | API/UI process mounts/permissions contain no Docker or libvirt socket |
| SEC-06 | Compose forbidden-field and alias/duplicate-key corpus rejected by controller and agent |
| SEC-07 | Git/dep requests cannot reach IPv4/IPv6 host, management, metadata or rebinding target |
| SEC-08 | CPU/RAM/PID/disk/log/time exhaustion bounded; management remains operable |
| SEC-09 | App cannot read metadata DB, other app volume or deployment credentials |
| SEC-10 | Known test secret never appears in stored/displayed logs, audit, argv or URLs |
| SEC-11 | Failed/cancelled/crashed build has no VM/disk/token after cleanup SLA or a visible blocking incident |
| SEC-12 | New HTTP denied ≤5 s and existing WS/SSE closed ≤10 s after revoke commit |
| SEC-13 | Proxy bad generation never exposes candidate; previous verified route survives |
| SEC-14 | Backup restoration preserves ownership/integrity and starts with private routes |
| SEC-15 | Malicious iframe cannot read portal cookies/DOM, navigate top or forge postMessage |
| SEC-16 | Expired/replayed/wrong-worker commands cause no runtime changes |
| SEC-17 | Concurrent deploy/cancel/rollback produces one active app generation |
| SEC-18 | TOTP replay/recovery double-use rejected; enrollment/reset fully audited |

SEC-10 is a known-fixture test, not proof that malicious encoding can always be redacted. SEC-07 needs external firewall/broker evidence, not merely application validation. SEC-12 tests auth-service failure and dropped invalidation events, not only happy path.

## Release process

PH1 requires SEC-01–11, 13, 16–17 and baseline direct-request ACL tests; PH2 adds full embedded browser/stream behavior; PH3 requires SEC-12/18 complete user flows. Any stream feature introduced earlier inherits SEC-12 immediately. PH4 adds update/data rollback drills; PH5 adds external penetration review and complete restore exercise. Baseline scan and resource controls exist PH1 even if PH5 improves them.

Store evidence with commit, template/engine/kernel versions, policy hash and pass/fail; no sensitive captures in public CI. Security failures block release, not warning-only. Run hostile execution only in approved isolated lab guests, not developer host or shared CI runner. Dependency/SAST/SBOM scans complement, not replace, behavioral isolation tests.
