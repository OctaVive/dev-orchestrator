# PH3 — Recommended identity operations

## Objective / scope / architecture

Add safer account/session operations and measured authorization caching to full MFA/ACL. Complete PH3 minimal first. Keep centralized server-side sessions, app-specific gateway sessions and default-deny policy. No external identity provider or role explosion.

Dependencies: P3-M07, operator recovery/key policy. Files: `internal/{auth,acl,audit,secrets}`, `web/src/admin/{sessions,audit}`, `tests/security/{session-races,key-rotation}`, migrations for key/epoch metadata.

| ID | Task/output | Depends | Size | Acceptance |
|---|---|---|---|---|
| P3-R01 | Session inventory, per-session/all-session revoke and recent-auth UX | P3-M07 | M | Stolen/old session invalid after revoke/privilege change |
| P3-R02 | Epoch-aware ≤5 s cache with push invalidation and strict lease expiry | P3-M07 | M | Delayed stale fill cannot restore revoked permission |
| P3-R03 | TOTP encryption-key rotation and isolated recovery drill | P3-M07 | M | Old/new key transition restores safely; no plaintext export |
| P3-R04 | Filtered audit browser and sensitive-action alerts | R01 | M | Admin-only access, sanitized payloads and alert for MFA/ACL changes |
| P3-R05 | Concurrency/property tests and operator lockout exercise | R02,R03,R04 | M | No last-admin accidental removal, lost-key recovery documented and audited |

Parallel R01/R02/R03, R04 after R01. R05 integrates all. If cache complexity is not justified, keep no positive cache and document R02 as replaced by equivalent epoch/latency proof; no indefinite cache is permitted.

Security/testing: same CSRF/Origin validation on all admin actions, strong reauthentication for reset/role changes, exact session/app binding, no token list disclosure. Test dropped invalidations, partitioned auth DB, concurrent session rotation, recovery consumption races and clock drift.

Complexity medium, ~2–4 additional weeks. Risks: cache correctness, service outages denying users and operator recovery privileges. Acceptance/done: lease bounds measured under fault injection, key rotation restores successfully, audit exposes no credentials and operator can revoke a compromised account promptly.
