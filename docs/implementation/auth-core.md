# PH1 password authentication and API (P1-M03)

## What runs now

`cmd/api` is a TLS-only JSON API, not the GUI, application gateway or deployment engine. It never opens a Docker/libvirt socket or invokes repository code. Existing metadata migration 001 is unchanged; the tables prepared in M02 hold identities, sessions and general audit events.

| Listener | Endpoint | Access |
|---|---|---|
| Portal | GET `/api/v1/auth/csrf` | Signed five-minute pre-login challenge, no session needed |
| Portal | POST `/api/v1/auth/login` | JSON credentials + exact Origin + pre-login cookie/CSRF |
| Portal | GET `/api/v1/auth/session` | Active server-side session; current identity/role/CSRF |
| Portal | POST `/api/v1/auth/logout` | Active session + Origin/CSRF; atomic revoke/audit |
| Portal | GET `/api/v1/admin/status` | Admin only; reports deployment execution **false** |
| Portal | `/api/v1/setup` and descendants | Always 404, regardless of setup configuration |
| Operator | GET `/api/v1/setup/csrf` | Loopback peer, live setup configuration, separate cookie |
| Operator | POST `/api/v1/setup` | Loopback + Origin/CSRF + expiring operator bearer token |

Other management paths require authentication and admin role, then return 404. No placeholder job can execute or enqueue a deployment. Unknown paths outside the management namespace return 404. Never treat a hidden URL as an authorization control.

## Operator bootstrap / running the API

No process was left running by implementation. Tests start only temporary loopback TLS servers. To run manually:

1. Prepare an operator-owned private metadata directory (Unix 0700; Windows restrictive ACL). Do not use a shared mount. Back up existing metadata before any future upgrade; M02 upgrade refusal still applies.
2. Supply a trusted TLS certificate/private key for the portal hostname **and** the operator setup hostname, or terminate the two listeners through separately designed trusted TLS arrangements. The current binary uses one certificate pair for both. Private key input must be a bounded regular file, not a symlink, with no Unix group/other access (Windows ACLs are an operator duty). No HTTP/insecure-cookie fallback exists; do not disable certificate verification.
3. Generate 32 random bytes with an operator-controlled CSPRNG and encode as exactly 64 lowercase hex characters in a private regular token file (Unix 0600/0400; Windows ACL checked by operator). Do not print it, place it in process arguments/URLs, check it into source, or send it to the public listener.
4. Start with `go run ./cmd/api` and explicitly provide `-tls-cert`, `-tls-key`, `-public-origin`, and `-db`. Default portal bind is `127.0.0.1:8443`. `-public-origin` is the exact browser origin, with no trailing slash/path/query; preserve its Host when proxying.
5. On a fresh DB also supply `-setup-token-file` and `-setup-expires-at` (RFC3339, future but no more than 15 minutes from startup). Setup bind defaults to **separate** `127.0.0.1:9443`, origin `https://localhost:9443`. Only literal loopback binds and localhost/loopback setup origins are allowed.
6. Use an operator-only HTTPS client to fetch the setup CSRF endpoint, keep its cookie, then POST JSON `{username,password}` with its CSRF header and bearer token loaded from the protected file. Acquire passwords interactively rather than via CLI arguments. There is no setup GUI yet.
7. Once created, setup returns 404 permanently (a durable audit marker survives removal of users). Login is a separate step using the portal challenge and login endpoint. Remove the now-useless operator token file through your normal authorized secret-file procedure.
8. Restart after setup without bootstrap flags. Missing bootstrap configuration on a fresh DB causes refusal; no default password/user is installed. Losing all admin credentials has no hidden reset endpoint; audited recovery is future work.

**Never publish or proxy the operator listener.** Loopback source checks alone are insufficient behind a local reverse proxy; separation of listeners is intentional. If remote operation is necessary, use an operator-authenticated tunnel whose TLS hostname/origin is configured correctly, without exposing the port to regular users.

The portal handler requires actual TLS, including on a future edge-to-API connection. `X-Forwarded-Proto`, `X-Forwarded-For`, `Forwarded` and identity headers are not trusted. TLS minimum is 1.3. Header/body/read/write timeouts are configured; auth bodies are bounded to 8 KiB. A production gateway and its service authentication remain M11.

## Passwords / admission

- Argon2id v19, 64 MiB, 3 iterations, parallelism 1, 16-byte random salt, 32-byte key. Encoded PHC string is stored, never plaintext. Only this explicit profile is currently accepted; malicious DB parameter strings cannot request huge allocations. Future profile migration needs reviewed verification/rehash logic.
- New passwords: ≥15 Unicode code points, ≤1024 UTF-8 bytes, valid UTF-8, no NUL, nonblank, no silent trimming/truncation. A small shipped offline common-password list is enforced. This is **not a comprehensive breached-password database** or a guarantee of strength. Unicode normalization is not silently performed.
- Usernames are lowercase ASCII identifiers, case-normalized consistently before account limits/lookups. No client role/user ID fields are accepted.
- Missing users and malformed hashes do one normal dummy KDF. Wrong/disabled/missing accounts return the same generic failure; do not claim mathematically constant network timing.
- At most two KDF operations per service process; excess work gets 503 instead of an unbounded queue. KDF work already started is not interruptible, but its resource profile is bounded.
- Login limits count attempts (including successful ones): 5/account, 20/source IP and 100/global per five-minute fixed window. Separate setup limiter uses the same bounds. Entries are capped at 4096, live entries are never evicted for attacker churn, and expiry restores access—no permanent attacker-triggered account lockout.
- Limits are in-memory and reset on restart; no multi-instance/distributed limit guarantee. Account lockout for the short window is a residual availability risk. Invalid/throttled requests are not each written to audit (avoid log flooding); admitted credential failures are audited without submitted username/IP/secret. Deployment-time gateway limits/telemetry remain future work.
- Source IP comes solely from the TCP peer, not forwarded headers. Behind a proxy all clients currently share its IP bucket; trusted client-IP propagation requires the M11 authenticated proxy design, not a casual forwarded-header opt-in.

## Sessions / CSRF / permissions

Successful login always creates a random 256-bit token; only its SHA-256 hash is stored. The presented previous session is revoked in the same transaction as new session creation and login audit. Failed login/audit writes do not revoke the prior session. Other independent browser sessions are not globally revoked on login.

Cookie `__Host-portal_session`: Secure, HttpOnly, Path=/, no Domain, SameSite=Lax; browser max-age 12 hours. Backend enforces 30-minute sliding idle and 12-hour absolute expiry, revocation, account disabled state, auth_epoch and current DB role **on every request**. Pending-MFA sessions cannot authenticate. No positive permission cache, localStorage bearer token or client role header is used. Auth DB outage returns 503, not stale authorization.

All mutations require exact configured Origin and a session-bound CSRF header; duplicate cookie/Origin/CSRF values are rejected. Pre-login/setup use distinct HttpOnly Strict cookies containing expiring, server-MACed nonces; the JSON CSRF value alone cannot mint a valid cookie. Pre-login keys are ephemeral across API restart. Session CSRF derives via domain-separated HMAC from the HttpOnly raw token, so it remains session-bound without storing another bearer credential. Platform tokens are never URL parameters.

Responses are no-store, JSON/nosniff, with restrictive CSP and referrer policy. Browser-origin/Host/Sec-Fetch checks fail closed; CORS is not enabled. Passwords, session/setup tokens and auth request bodies are not logged or placed in audit. Audit records cover successful setup/login/logout and admitted failed login/setup-token attempts with server-generated correlation IDs.

Users may inspect their own session and log out. Admin status and all other management namespace operations require backend admin permission. Current roles are read from DB, never cached from the browser; removing admin takes effect on the next request. This does not implement per-application gateway access, TOTP, user/ACL administration, reauthentication UX or global session management UI.

## Evidence and remaining gates

Tests use real Argon2id/SQLite, not weak test hash parameters. They cover first-admin races/permanent marker, audit rollback on setup/session/revoke failure, server-side hashing, rotation/fixation, idle/absolute expiry, account epoch/disable/role changes, generic errors, bounded limiter/KDF admission, JSON ambiguity, cookie/Origin/CSRF confusion, auth outage and a real local TLS 1.3 challenge→login→session→logout flow (TLS 1.2 denied).

This is not a production secure MVP yet: no UI, full MFA, application gateway, VM/build/runtime isolation, real deployment endpoints, secret manager or tested auth backup/recovery. If day-one production MFA is required, password-only PH1 remains blocked until PH3 tasks are pulled forward. Windows tests/cross-compilation do not establish Linux process isolation, filesystem guarantees, benchmark SLOs or complete penetration-test assurance.
