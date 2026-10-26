# PH3 — Hardened authentication and authorization

## Objective / scope / architecture

Raise key protection and privileged-change accountability on PH3 minimal/recommended. Keep TOTP as specified; do not claim TOTP is phishing-resistant. Optional later WebAuthn requires separate product decision, not substitution without approval.

Dependencies: P3-R05, operator-approved TPM/external key service and audit sink if selected. Files: `internal/{secrets,auth,acl,audit}`, `policy/identity`, `tests/security/auth-review`, operator recovery and key custody docs.

| ID | Task/output | Depends | Size | Acceptance |
|---|---|---|---|---|
| P3-H01 | Hardware/external wrapping-key adapter with fail-closed startup | P3-R05 | M | DB backup alone cannot decrypt TOTP; key outage does not skip MFA |
| P3-H02 | Dual approval for exceptional MFA reset/role escalation when two admins exist | P3-R05 | M | Requester cannot approve own action; expiry/replay audited |
| P3-H03 | Independent auth/ACL penetration review and fuzz campaign | H01,H02 | L | No critical/high session, recovery or IDOR findings remain |
| P3-H04 | Offline recovery/custody exercise with audit verification | H03 | M | Recovery is possible without unlogged permanent bypass; identities/sessions rotated |

Parallel H01/H02; H03 then H04. For a single-admin deployment dual approval is unavailable: disclose weaker assurance and use explicit offline recovery custody; do not fabricate independent approvers.

Controls/tests: key authorization separated from SQLite access, replay/rate limits, offline break-glass event trail, malicious admin grant attempts bounded by policy. Review tests include MFA fatigue/recovery social engineering and identity-header trust, not just TOTP math.

Complexity high, ~2–5 additional weeks plus key-service setup. Risks: key-service availability, dual-approval deadlock and residual TOTP phishing. Acceptance/done: external review and recovery exercise complete, no hidden bypass, key custody/revocation responsibilities assigned, all prior ACL timing bounds preserved.
