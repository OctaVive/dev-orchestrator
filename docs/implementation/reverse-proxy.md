# Reverse proxy implementation contract

Choose NGINX; pin supported version/modules including auth_request. Separate public edge and private runtime relay. No Docker socket/discovery. Fixed templates consume validated route structures: canonical host, app/deployment IDs, backend handle, approved port and generation, TLS reference and iframe compatibility profile.

HTTP request flow: TLS SNI/Host validation → normalized exact route lookup → auth_request to private auth service with gateway-generated app identity → relay's approved backend → workload. Never proxy unknown hosts/paths to a default application. Login/handoff routes are narrowly exempted and never forward to workloads. Internal auth locations are not client-accessible. Auth service errors/timeouts produce deny/503, not success.

NGINX auth_request is sufficient for per-request HTTP authorization but not revoking established upgraded or streaming connections. Relay terminates WebSockets and tracks SSE/long responses with user/session/app context. Every connection has an expiring authorization lease; push events accelerate close, periodic refresh bounds delay. Missing refresh closes connection. Unauthorized upgrade cannot reach backend before allow result.

Configuration transaction: render to generation directory → syntax/semantic checks → atomic activation pointer → NGINX reload → positive/negative smoke probes → DB active-generation commit. If controller dies between reload and DB write, recover from generation marker and probes. Preserve last known-good config; remove a revoked app route immediately or replace with deny even if ordinary app config generation fails.

Certificate management is separate from user strings. Validate domain ownership and supported SAN scope before issuance. Rate-limit issuance; no wildcard arbitrary admin URL. Local development uses generated development CA under explicit trust, never production keys. Protect private keys with gateway-only permissions. Rotation doesn't grant unauthenticated app access.

Cookie handling: reserve platform cookie names; filter upstream attempts to overwrite them; do not forward platform session cookies to apps. Host-only cookies don't eliminate malicious sibling-domain attacks unless origin/domain design is correct. Reject response/request header injection. Validate redirect helper targets against explicit origins, without rewriting app login/header policies silently.

Test config injection names, unknown Host/SNI, forged forwarding headers, duplicate Host, path normalization mismatch, wrong app route mapping, stale generation and reload failure. Test auth failure before/after WS upgrade and under partition. Verify no public host port reaches apps even with gateway stopped.
