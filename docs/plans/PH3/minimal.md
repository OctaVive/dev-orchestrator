# PH3 — Minimal full TOTP and application ACL

## Objective / scope / architecture

Expand PH1 authentication into complete MFA, recovery, user management and per-app assignments. Security did not begin here: existing sessions, backend role checks, private ingress and deny-by-default ACL persist. Central Go auth service/SQLite is authoritative; relay maintains revocation leases.

Dependencies: P2-M06; if day-one MFA required, pull M01–M04 and their PH1 dependencies into PH1 before release. Files: `internal/{auth,acl,secrets,audit}`, `migrations/*_mfa_acl`, `web/src/{auth,admin/users,admin/permissions}`, `tests/security/{mfa,acl}`.

| ID | Task/output | Depends | Size | Acceptance |
|---|---|---|---|---|
| P3-M01 | AEAD key-version adapter and TOTP credential/recovery schema | P1-M03 | M | Ciphertext context/key tests; no plaintext secret in DB/logs |
| P3-M02 | TOTP pending-login/enrollment/confirmation and replay guard | M01 | M | Wrong/reused/skewed code denied; pending session cannot deploy/open app |
| P3-M03 | Hashed one-use recovery codes and guarded reset flow | M02 | M | Parallel consumption yields one winner, reset revokes all sessions |
| P3-M04 | MFA UI and mandatory-admin enrollment policy | M03 | M | End-to-end enrollment/login/recovery with no bypass path |
| P3-M05 | Admin/User CRUD and transactional per-app grants with ACL epochs | P2-M06 | M | User cannot self-elevate, categories never imply access |
| P3-M06 | Grant management UI, session disable/revoke and durable invalidation | M05,M04 | M | Hidden app IDs denied directly, disabled users denied everywhere |
| P3-M07 | Full role/MFA/revocation audit and timed request/WS/SSE regression | M06 | M | SEC-12/18; HTTP ≤5 s, streams ≤10 s after commit including partitions |

Parallel: M01–M04 MFA chain and M05 ACL backend after its dependencies; M06 integrates. MFA tasks moved earlier do not require embedding code, but full stream gate does.

Security/tests: recent-auth requirement on sensitive changes, CSRF, encrypted TOTP, transactional recovery and replay counters, generic rate-limited errors, no email-only MFA bypass. Test last-admin protection, simultaneous ACL edits and stale cache fill. Admin all-app policy is explicit; disabled admin receives no access.

Complexity medium/high, ~3–5 weeks. Risks: key loss, clock skew, account lockout and recovery abuse. Acceptance/done: all listed gates, MFA onboarding/recovery runbook, no user permissions by default and revoked access promptly denied. Already delivered app data cannot be recalled.
