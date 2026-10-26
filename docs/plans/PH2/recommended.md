# PH2 — Recommended embedded applications

## Objective / scope / architecture

Build on PH2 minimal with reliable compatibility onboarding, managed domains/TLS and complete streaming revocation. Isolated app origins remain default; no automatic same-origin path fallback. Dependencies: P2-M06 and operator-owned domains/certificate policy Q11.

Files: `internal/{proxy,acl}`, `web/src/apps/compatibility`, `infra/gateway`, `tests/{browser,security/streams}`, route/domain migrations and operator TLS docs.

| ID | Task/output | Depends | Size | Acceptance |
|---|---|---|---|---|
| P2-R01 | Header/URL/browser preflight report and admin compatibility approval | P2-M06 | M | XFO/CSP conflicts reported without modification; static checks not claimed sufficient |
| P2-R02 | Domain ownership and certificate lifecycle adapter | P2-M06 | M | Unowned SAN rejected, renewal failure alerts without public bypass |
| P2-R03 | SSE/download revocation and bounded in-flight response handling | P2-M04 | M | All tracked streams close ≤10 s under dropped invalidation events |
| P2-R04 | Exact-origin postMessage API for harmless resize/status only | R01 | S | Wrong origin/source/schema rejected, no session/privileged method exposed |
| P2-R05 | Full browser compatibility and route/certificate failure matrix | R02,R03,R04 | M | Supported browser list and per-app fallback evidence published |

Parallel R01/R02/R03; R04 after R01, R05 last. Use shared origin/session contracts, no ad hoc frontend token exchange.

Controls: origin ownership, protected handoff cookies, reserved platform cookie names, exact postMessage destinations, atomic route config and no insecure TLS fallback. Test cookie tossing on sibling domains, service-worker persistence on retired app origins, certificate rotation, blocked third-party cookies and slow streaming revocation.

Complexity medium/high, ~2–4 additional weeks. Risks: CA rate limits, browser policy changes, upstream application login integrations. Acceptance: each app has explicit supported embedding profile and secure fallback, all streams obey lease, TLS failures deny traffic. Done: R01–R05 and all minimal gates pass, operator can diagnose incompatibility without weakening app headers.
