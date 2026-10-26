# PH2 — Minimal embedded applications and routing

## Objective / scope / architecture

Add isolated-origin iframe views retaining portal sidebar, automatic route lifecycle, optional DNS setup and authorized WebSockets. No path-based arbitrary-app embedding. Inherits PH1 baseline: routes already private/validated; this phase improves automation and browser integration.

Dependencies: P1-M14, Q03/Q08; PH1 recommended private-Git support not required. Files: `internal/{proxy,auth,acl}`, `cmd/ingress-relay`, `web/src/apps/{frame,launch,compatibility}`, `tests/browser`, gateway templates and handoff schema migration.

| ID | Task/output | Depends | Size | Acceptance |
|---|---|---|---|---|
| P2-M01 | App-origin inventory, exact host ownership and local hosts/CA setup contract | P1-M14 | M | Unknown/duplicate/unowned domains rejected; no wildcard fallthrough |
| P2-M02 | Audience/nonce-bound one-use handoff and app gateway sessions | M01 | L | Token replay/login CSRF/open redirect denied; platform cookie stripped upstream |
| P2-M03 | Frame shell with CSP, sandbox and explicit protected-tab fallback | M02 | M | Sidebar persists; malicious frame cannot read portal or top-navigate |
| P2-M04 | Authenticated WS relay with periodic lease and connection registry | M02 | L | Unauthorized upgrade denied; revoke/auth outage closes ≤10 s |
| P2-M05 | Automated versioned route create/disable/rollback and probe reports | M01 | M | Bad reload preserves previous private route; stale generation cannot activate |
| P2-M06 | Browser compatibility harness for XFO/CSP/cookies/storage/redirects | M03,M04,M05 | M | Blocked frames/cookies show safe fallback without stripping headers |

Parallel: M03/M04 after M02, M05 after M01. M06 integrates. Small frontend prototypes can use fixed fixture origins; real app publication waits for M02.

Security: distinct origins, host-only cookies, platform auth on every request, no token URLs, deny unknown postMessage, default-deny frame permissions. Test SEC-03/04/12/13/15, browser engine matrix and same-site/cross-site cookie profiles. Revocation is tested with service partitions even before PH3 user UI exists, using backend fixture grants.

Acceptance / done: authorized app embeds in supported browser; blocked app has protected new-tab or rejection; direct URL still checks ACL; WS/SSE cannot remain authorized indefinitely after revoke; app cannot reach management. No claim that users cannot open protected URLs directly.

Complexity high, ~4–7 weeks. Risks: third-party cookie restrictions, app frame policies, rootless relay networking. Unsupported apps are a product compatibility outcome, never a reason to weaken gateway/auth headers.
