# PH4 — Minimal Git updates and rollback

## Objective / scope / architecture

Add explicit branch checks, commit comparison, rebuild/redeploy, deployment history and verified rollback. Builds always use fresh isolated guests and immutable approval tuples. User-triggered refresh is admin-only; no webhook or automatic updates initially.

Dependencies: P3-M07, PH1 state machine and retained registry digests. Files: `internal/{gitfetch,jobs,runtime,proxy}`, `web/src/deployments/{history,update,rollback}`, migrations for branch observation/history, `tests/integration/updates`.

| ID | Task/output | Depends | Size | Acceptance |
|---|---|---|---|---|
| P4-M01 | Bounded isolated branch observation and commit comparison | P3-M07 | M | Moving/ref-deleted/force-pushed branch recorded; no code runs in management |
| P4-M02 | New deployment intent from selected immutable SHA and prior spec | M01 | M | No mutable tag/ref used by runtime; policy re-evaluated even on redeploy |
| P4-M03 | Per-app generation lock, private candidate and health-gated cutover | M02 | L | Concurrent update/cancel leaves exactly one active generation |
| P4-M04 | Retained approved digest/spec rollback and compatibility preflight | M03 | M | Incompatible data migration refuses automatic rollback |
| P4-M05 | History/update/rollback UI with explicit data-risk confirmation | M04 | M | Admin sees SHA/digest/policy/result; user cannot trigger operations |
| P4-M06 | Fault matrix for image pull/health/route switch/controller restart | M05 | M | Previous healthy route preserved; failure never reported as verified rollback |

Parallel: history read-only UI scaffold after M01 while M02 progresses; M03–M04 are sequential integration. App-data preflight contract can be drafted independently after M01, finalized at M04.

Security: Git egress identical to PH1; approval binds current policy and image digests, not old blanket approval. No automatic migration command with controller credentials. Backup required for declared incompatible app changes; no transparent data rewind. Artifact retention protects currently active, candidate and rollback references.

Testing/acceptance: SEC-11/13/16/17, force push during build, digest unavailable, old vulnerable image blocked by current policy, stop during health check, cancelled job result arriving late. All actions auditable; routes stay private throughout.

Complexity high, ~3–5 weeks. Risks: application-specific data migrations, storage races, retained artifacts consuming disk. Definition of done: repeatable update and verified code rollback with no data rollback promise, immutable history and operator-visible refusal when safe rollback cannot be established.
