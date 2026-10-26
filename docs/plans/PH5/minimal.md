# PH5 — Minimal security assurance and recovery

## Objective / scope / architecture

Review and strengthen the already enforced security architecture; PH5 is not permission to defer isolation/auth until now. Establish repeatable security regression, vulnerability response, secret rotation, backup restore and penetration-test plan on existing separated VMs.

Dependencies: P4-M06, operator backup/key/retention decisions. Files: `tests/security`, `internal/{registry,secrets,audit}`, `tools/{diagnostics,restore}`, `infra/*` templates, threat model/runbooks. Optional PH1 recommended backups are not assumed: this track implements their required secure equivalent if absent.

| ID | Task/output | Depends | Size | Acceptance |
|---|---|---|---|---|
| P5-M01 | Threat-model refresh and requirement-to-evidence inventory | P4-M06 | M | Every hard requirement mapped; unsupported patterns and owners explicit |
| P5-M02 | Scanner DB freshness, severity policy and remediation tracking | M01 | M | Stale/missing scan blocks new deploy; existing-risk alert recorded without arbitrary shutdown |
| P5-M03 | Runtime/build tool template patch and secret/key rotation procedures | M01 | M | Compromised worker rebuilt; identities and app secrets rotated without leaking |
| P5-M04 | Encrypted metadata/key/app-volume backup implementation and restore drill | M01 | L | SEC-14, app-consistent restore and private-route bootstrap demonstrated |
| P5-M05 | Full adversarial regression automation and scoped penetration-test rules | M02,M03,M04 | L | SEC-01–18, no victim traffic or shared-runner hostile execution |
| P5-M06 | Remediation review, incident exercise and release risk signoff | M05 | M | Critical blockers fixed; residual risks have owner and no false guarantee |

Parallel M02/M03/M04 after M01; M05/M06 sequential. Do not rerun previously completed tasks unnecessarily: verify equivalent artifact and test evidence before marking imported capability done.

Security/testing: actual Linux guest networking, resource bombs, parser corpus, auth outage, TOTP recovery, webhook tests if feature enabled, route rollback, DB corruption and key loss. Missing optional feature tests are marked unsupported, not silently passed. Baseline scans/log redaction remain required before this phase.

Complexity high, ~4–7 weeks. Risks: untested backup assumptions, scanner false confidence, manual operational drift. Acceptance/done: complete restore within agreed measured objectives, current security regression evidence and no unresolved hard gate. Single-host/shared-runtime residuals remain; disclose them rather than claiming hostile multi-tenancy safety.
