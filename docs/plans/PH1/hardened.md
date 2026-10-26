# PH1 — Hardened secure core

## Objective / scope / architecture

Raise PH1 isolation assurance without expanding application privileges. Complete PH1 minimal and recommended first. Move builders to a separate physical host where available; retain management/runtime boundary and strict typed agents. Dedicated hardware is the hardened target, not a secure-minimal prerequisite.

Files/components: `infra/{builder,management,runtime}`, `policy/{seccomp,egress}`, `internal/{audit,registry}`, `tests/security/isolation`, template build/verification documentation. Dependencies: P1-R06, dedicated host budget, external audit destination approved.

| ID | Task/output | Depends | Size | Acceptance |
|---|---|---|---|---|
| P1-H01 | Reproducible signed VM template manifest and verification path | P1-R06 | M | Modified/obsolete template refused, version in provenance |
| P1-H02 | Dedicated builder-host provisioning with isolated host-control network | H01 | L | Full guest compromise simulation cannot reach management/host control |
| P1-H03 | Syscall/MAC profile regression harness and host reserve stress test | H01 | M | Required profiles active, management survives budget exhaustion |
| P1-H04 | Append-only external audit export with durable outbox retry | P1-R06 | M | Local outage queues bounded evidence; tamper/gap alert demonstrated |
| P1-H05 | Independent adversarial review of provisioner/ingest/agent boundary | H02,H03,H04 | L | Critical findings fixed; shared-runtime guest-kernel residual documented |

Parallel: H01/H04; H02/H03 after H01; H05 last. Dedicated hardware work is operator-approved, never performed implicitly by a coding task.

Security: separate service CAs/identities, no guest-reachable provisioner, template signature verification, external lifecycle enforcement and audit. Tests: SEC-07–11/16 under simulated compromised guest, boot template alteration, audit outage and host resource stress. Acceptance: all previous gates plus no unresolved critical/high boundary findings and a rebuild/rotation drill.

Complexity high, ~3–6 additional weeks plus procurement. Risks: hypervisor vulnerabilities, new networking mistakes and signed-but-vulnerable templates. Definition of done: independent evidence of separated physical builder operation and documented emergency disable/rebuild path. Still not a claim of perfect isolation or safe arbitrary runtime tenancy.
