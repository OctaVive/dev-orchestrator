# Portal frontend

React/TypeScript with a small maintained router and query client, no runtime dependency on frontend framework for authorization. Pages: bootstrap; login/pending MFA; sidebar/catalog; iframe shell; admin apps/deployment wizard; deployment timeline and logs; later users/ACL/MFA/settings. Category ordering is presentation only, never inherited permission.

Wizard: Git URL/branch (asynchronous controlled enumeration), display name/category, Dockerfile/Compose selection and path, declared port/health probe, permitted runtime variables/secret references, managed volumes, optional domain, policy preview, confirmation. Distinguish runtime env from build args; build secrets are unsupported. Show policy rejections by field with remediation, not a bypass toggle.

Status consumes persisted state events, not guessed progress percentages. Show immutable SHA/digests, approval/policy version, current vs candidate generation and rollback/data warnings. Cancellation is pending until server confirms resource cleanup. Log viewer treats all output as text, strips terminal controls, bounds memory and never renders repository HTML. Sensitive values are write-only inputs; clear after submission and do not retain in browser storage/analytics.

Sidebar fetches only authorized apps; route guards improve UX but direct API requests remain backend-checked. App frame state: checking → launching → embedded, protected-tab fallback, denied, unsupported or unavailable. Loading/health failures never substitute a raw backend address. Exact source/origin checks for optional postMessage.

Accessibility: keyboard navigation, focus transfer between sidebar/frame, live status announcements without reading secrets, accessible login/recovery. Auth expiry clears local query data and closes frame/streams. Session logout is server-side; opening another browser tab cannot resurrect revoked gateway access.

Browser tests: unauthenticated redirect, non-admin hidden controls plus direct API denial, malicious app frame cannot read portal, denied top-navigation, blocked third-party cookies yields explicit fallback, CSP/XFO conflict remains intact, unauthorized WS denial, no credentials in URLs/localStorage.
