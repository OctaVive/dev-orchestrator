# Security exception policy

An exception is an explicit bounded risk decision, not a generic admin override. Required fields: immutable ID, app/service/worker scope, control ID, requested alternative, business need, attack impact, compensating controls, approving admin with recent authentication, security reviewer where distinct, policy/spec hash, expiry, review date, test evidence and audit correlation. No secret values in record.

Allowed candidates: higher bounded resource limits; explicitly approved public egress hostname; app-specific sandbox capability; additional managed writable directory; a separately reviewed filesystem profile. Gateway shows active exceptions and deployment approval binds their versions. Agent checks scope/expiry and never trusts a browser-provided approval flag.

Non-waivable here: UI/API socket access, privileged DinD, host sockets/binds/devices/namespaces, management-network reachability, anonymous/public application bypass, unisolated arbitrary builds, arbitrary agent shell, disabling TLS/auth, long-lived secrets in builds. Such needs are unsupported deployment patterns requiring a new architecture, not an exception row.

Expiry prevents new deployments; for running apps, disable the exceptional capability or quarantine route/workload per reviewed expiry plan, with warnings before expiry. Never silently leave an expired broad egress rule active. Revocation increments policy generation and reconciles runtime/network state; denial is immediate where possible, otherwise terminate affected workload.

Audit exceptions at least monthly and on policy upgrade. No standing global wildcard exceptions. A failed exception test blocks release. Security owner must explicitly accept residual risk; acceptance does not convert an unprovable property into a guarantee.
