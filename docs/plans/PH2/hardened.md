# PH2 — Hardened browser and routing isolation

## Objective / scope / architecture

Complete PH2 minimal/recommended, then reduce gateway blast radius and continuously test browser boundaries. Requires separate portal/app registrable domains, dedicated edge identity/network, and optional dedicated gateway VM. No reviewed same-origin mode is included.

Dependencies: P2-R05, second domain and lab browser matrix. Files: `infra/gateway`, `policy/egress`, `internal/proxy`, `tests/security/{browser-origin,gateway}`, CSP reporting/monitoring docs.

| ID | Task/output | Depends | Size | Acceptance |
|---|---|---|---|---|
| P2-H01 | Separate edge VM/service identity and minimal management auth channel | P2-R05 | M | Edge compromise simulation cannot deploy or read DB; only auth API reachable |
| P2-H02 | Cookie/domain adversarial suite with malicious app and nested frames | P2-R05 | M | Parent-domain, storage, sandbox and navigation attacks blocked or documented unsupported |
| P2-H03 | Bounded privacy-safe CSP violation collection and origin retirement process | H02 | M | No secret URL/body capture; retired origin cannot be reassigned silently |
| P2-H04 | Chaos routing/auth test campaign and independent browser review | H01,H03 | M | Edge/auth/relay partitions fail closed, revocation SLA and previous config recovery proven |

Parallel H01/H02; H03 after H02; H04 final. Actual VM/network deployment requires explicit operator approval.

Security: separated registrable domains and host-only cookies; no generic relay tunnel; route source authorization; bounded CSP data; explicit app-frame capabilities. Test direct unauthenticated ingress, misleading Host/SNI, session cookie injection, controller/relay restart during switching and auth-service expiry on live WS/SSE.

Complexity high, ~2–4 additional weeks. Risks: gateway becomes an internet-facing high-value service, browser behavior evolves, allowed frame can still phish users visually. Acceptance: independent review has no unresolved high-risk origin/cookie findings; supported browser constraints are published. Done: all previous gates plus H01–H04 evidence, incident procedure for a malicious embedded app exercised.
