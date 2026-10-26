# PH4 — Recommended Git update operations

## Objective / scope / architecture

Add safe update notifications, signed webhook triggers and deployment scheduling/backpressure to PH4 minimal. No arbitrary webhook-supplied URLs or commands. Same ephemeral builder and restricted runtime architecture.

Dependencies: P4-M06, operator chooses Git provider and webhook secret policy. Files: `internal/{api/webhooks,gitfetch,jobs,audit}`, `web/src/deployments`, webhook delivery migration, `tests/security/webhooks`, update runbooks.

| ID | Task/output | Depends | Size | Acceptance |
|---|---|---|---|---|
| P4-R01 | Scheduled branch observation and explicit update notifications | P4-M06 | M | Polls bounded/deduplicated; default does not deploy automatically |
| P4-R02 | Provider-specific signed webhook verification and replay store | P4-M06 | M | Bad signature/stale/duplicate/oversized payload denied before job creation |
| P4-R03 | Repo/ref mapping, queued trigger coalescing and admin opt-in policy | R01,R02 | M | Payload cannot select new repository, worker, secret or arbitrary ref |
| P4-R04 | Pre-update app-consistent backup hook contract and restore preview | P4-M04 | M | Hook executes only in app security domain, no management shell; failed backup blocks unsafe update |
| P4-R05 | Delivery/update observability and webhook/rollback incident drill | R03,R04 | M | Flood bounded, results auditable, revoked webhook stops new jobs |

Parallel R01/R02/R04, R03 then R05. PH1 recommended credential broker is an extra dependency only if enabling private repositories; public repo workflows need no private tokens.

Security/testing: HMAC/signature constant-time verification over exact bytes, secret rotation overlap, public ingress rate/body limits, no unsafe branch pattern expansion. Backup hooks are optional constrained application actions, not arbitrary host commands. Test replay under DB restart, burst webhooks, force pushes, old digest scan failure and storage fill.

Complexity medium/high, ~2–4 additional weeks. Risks: provider signature differences, webhook-driven build DoS and app-specific backup semantics. Acceptance/done: authenticated webhook produces at most one authorized bounded intent, notifications do not auto-deploy by surprise, backups/rollback warning are accurate, all previous isolation gates remain green.
