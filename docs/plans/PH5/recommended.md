# PH5 — Recommended continuous hardening

## Objective / scope / architecture

Add continuous risk monitoring, off-host audit/backup and independent review to PH5 minimal. Maintain small self-hosted platform, no Kubernetes/HA requirement. Dedicated hosts are preferred when budget permits but remain a separately approved infrastructure change.

Dependencies: P5-M06, external encrypted storage/audit destination, security reviewer. Files: `internal/{audit,registry,policy}`, `tools/diagnostics`, `tests/security/chaos`, backup/audit adapters and security operations docs.

| ID | Task/output | Depends | Size | Acceptance |
|---|---|---|---|---|
| P5-R01 | Periodic running-image rescans and risk inventory | P5-M06 | M | All active digests checked, stale DB alerts, no tag identity confusion |
| P5-R02 | Off-host encrypted backup and append-only audit export | P5-M06 | M | Source-host loss restore demonstrated; export gaps detectable |
| P5-R03 | Independent platform penetration test and prioritized fixes | P5-M06 | L | Auth/agent/build/iframe/network boundaries reviewed, critical/high fixes verified |
| P5-R04 | Scheduled chaos and restore drills with capacity/lease telemetry | R01,R02 | M | Auth partitions deny traffic, cleanup stays bounded, measured recovery report |
| P5-R05 | Release security checklist and operator incident training | R03,R04 | M | Operator executes compromise containment without public bypass or shared-volume corruption |

Parallel R01/R02/R03; R04 after R01/R02; R05 final. Independent review scope must include privileged provisioner and egress broker, not just web endpoints.

Controls/testing: external audit integrity, strict destination credentials, periodic identity/secret expiry, scanner provenance, overload/backpressure alerts, restore verification. Test stolen backup, lost wrapping key, audit destination outage and partial worker compromise. Off-host storage credentials never reach build guests/apps.

Complexity high, ~3–6 additional weeks plus external scheduling. Risks: review scope gaps, off-host credential custody, alert fatigue. Acceptance/done: independent findings resolved or explicitly scoped below hard-gate severity, recovery and containment rehearsed, monitoring actionable, all prior tests preserved.
