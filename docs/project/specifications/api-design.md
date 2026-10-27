# Management and agent APIs

JSON over TLS, `/api/v1`, OpenAPI contract first; deny unknown fields on security-sensitive writes, bounded payloads, typed IDs. All non-bootstrap endpoints require a session/service identity and a route-specific permission. Session auth uses CSRF on mutations. Errors return code, safe message, field errors and correlation ID, not stack traces. Generic 404 for unauthorized app IDs. No API endpoint accepting engine commands, host paths or proxy config.

| Endpoint group | Operations | Permission |
|---|---|---|
| `/setup` | POST create first admin with operator token | Bootstrap channel only, single-use |
| `/auth/login`, `/auth/mfa`, `/auth/logout` | POST, rate-limited state machine | Login or pending/full session as appropriate |
| `/auth/sessions`, `/auth/totp`, `/auth/recovery` | List/revoke/enroll/confirm | Own identity + recent auth |
| `/apps` | GET filtered catalog; POST create | User catalog; admin create |
| `/apps/{id}` | GET/PATCH/DELETE | Authorized metadata; admin mutate |
| `/apps/{id}/launch` | POST one-use handoff | Current app access |
| `/apps/{id}/deployments` | GET history / POST submit | Admin |
| `/deployments/{id}` | GET status; POST cancel/rollback | Admin |
| `/deployments/{id}/logs` | GET bounded pages or authenticated SSE | Admin |
| `/repositories`, `/repositories/{id}/branches` | Create config / controlled asynchronous enumeration | Admin |
| `/apps/{id}/volumes`, `/secrets` | Managed references and lifecycle | Admin + recent auth |
| `/apps/{id}/permissions`, `/users`, `/categories` | CRUD under role policy | Admin |
| `/apps/{id}/stop`, `/disable`, `/redeploy` | POST lifecycle operations | Admin |
| `/internal/authz` | HTTP auth_request decision, no public routing | Gateway service identity |
| `/internal/handoff/redeem` | Atomic audience/nonce-bound redemption | Gateway identity |
| `/internal/workers/poll`, `/result`, `/heartbeat` | Leased typed commands/results | Worker-specific mTLS |
| `/internal/jobs/{id}/artifact` | Size-limited one-job export | Job token plus constrained network |

Deployment submission fields: repository ID/HTTPS URL, validated branch, app ID, Dockerfile/Compose path, type, requested runtime env/secret refs, volume IDs and bounded resource settings. Domain is a separate validated route ownership operation. Never accept final image digest from a browser as trusted build result.

Idempotency-Key on submit/lifecycle writes; persisted request hash prevents same key/different body. If-Match application version for config/ACL mutations; 409 on stale generation. 202 returns job ID. Pagination cursor and maximum sizes; status SSE includes resumable event IDs, revocation lease and rate limits. Logs must not interpret HTML or terminal escapes.

Agent command envelope: version, command ID, app/deployment/worker IDs, monotonic generation, expires_at, nonce, policy hash, typed desired spec, signature. Agent result includes observed IDs/digests, sanitized bounded logs and error code. A result is evidence, not authority to change another app. Server checks certificate role, ownership and expected state on every update.

No public webhook in PH1. PH4 webhook requires HMAC/signature, replay window/delivery ID, body limit, repo mapping and rate limits; payload cannot choose arbitrary URL, ref, secret or worker.
