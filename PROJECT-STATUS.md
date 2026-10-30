# Master project status

Last reviewed: 2026-10-30.

This is the consolidated overview of PH1–PH5: scope, implementation progress, remaining work and supporting documentation. Status is based on the recorded [implementation progress](docs/project/progress.md), [PH1 milestones](docs/project/PH1/README.md) and phase plans; PH1M05, PH1M06, PH1M07 and PH1M08 software and real-host validation are recorded in their linked evidence reports.

## Phase overview

| Phase | Scope | Status | Implementation progress | Recorded implemented milestones |
|---|---|---|---|---|
| [PH1](#ph1--secure-core) | Secure deployment platform foundation | In progress; validation gaps remain | **57.1%** | 8 / 14* |
| [PH2](#ph2--embedded-applications-and-routing) | Embedded applications and automated routing | Planned | **0%** | 0 / 6 |
| [PH3](#ph3--mfa-users-and-application-permissions) | MFA, user administration and application permissions | Planned | **0%** | 0 / 7 |
| [PH4](#ph4--git-updates-and-rollback) | Git updates, deployment history and safe rollback | Planned | **0%** | 0 / 6 |
| [PH5](#ph5--security-assurance-and-recovery) | Security regression, operational recovery and release review | Planned | **0%** | 0 / 6 |
| **Overall** | **Minimal baseline across all five phases** | **In progress** | **20.5%** | **8 / 39*** |

### How percentages are calculated

- Implementation progress = milestones recorded as implemented / total milestones in the phase's **minimal** plan × 100, rounded to one decimal place. Milestones have equal weight; these figures are not estimates of effort or time remaining.
- *P1-M04 counts as implemented with qualified validation: V01–V13 and V16 passed; **V14 and V15 are SKIP, not passes**. Only seven PH1 milestones have unqualified implemented/tested status. No arbitrary partial credit is assigned to skipped checks.
- P1-M05 counts as implemented/tested after controlled isolated-KVM N01–N13 acceptance; its lab evidence does not enable production or waive later build gates.
- P1-M06 counts as implemented/tested after all 83 required cases passed, including 51 actual Git cases and the controlled M05 regression; production rollout and later build/controller gates remain separate.
- P1-M07 counts as implemented/tested after all 146 required ledger cases passed, including the complete rootless build/isolated ingest pipeline and real budget-failure cases; admission remains separate from deployment approval.
- P1-M08 counts as implemented/tested after all 214 required ledger cases passed, including guest parsing/fuzzing, Dockerfile/two-service Compose normalization, independent agent policy and full M07 regression; runtime execution remains M09.
- Planned milestones receive no credit. Writing plans or creating milestone folders does not count as implementation.
- Recommended and hardened additions are outside these percentages and are not assessed here. Their scope is linked under each phase. The [master roadmap](docs/plans/master-roadmap.md) defines the cumulative tracks and prerequisites.
- Release readiness is separate: no phase is recorded as release complete. A phase reaches release completion only when all required acceptance gates and reviews are satisfied.

## PH1 — Secure core

Build the authenticated, isolated Git-to-container deployment foundation: persistent metadata, controlled builds, runtime policy, private application access and an operator interface.

| Milestone | Deliverable | Recorded status |
|---|---|---|
| [P1-M01](docs/project/PH1/P1M01/README.md) | Domain/protocol contracts, fixtures and capability checklist | Implemented/tested |
| [P1-M02](docs/project/PH1/P1M02/README.md) | SQLite migrations and transactional state/outbox persistence | Implemented/tested |
| [P1-M03](docs/project/PH1/P1M03/README.md) | Admin bootstrap, password/session authentication, CSRF and roles | Implemented/tested |
| [P1-M04](docs/project/PH1/P1M04/README.md) | KVM provisioner and expiring build-guest lifecycle | Implemented/tested with V14 and V15 skipped |
| [P1-M05](docs/project/PH1/P1M05/README.md) | Controlled build egress and firewall policy | Implemented/tested; controlled isolated-KVM N01–N13 PASS |
| [P1-M06](docs/project/PH1/P1M06/README.md) | Restricted Git clone runner and malicious Git fixtures | Implemented/tested; isolated-KVM M06 acceptance PASS |
| [P1-M07](docs/project/PH1/P1M07/README.md) | Rootless BuildKit, isolated image ingest and scanning | Implemented/tested; isolated-KVM M07 acceptance PASS |
| [P1-M08](docs/project/PH1/P1M08/README.md) | Compose/Dockerfile normalization and agent policy | Implemented/tested; isolated-KVM M08 acceptance PASS |
| [P1-M09](docs/project/PH1/P1M09/README.md) | Runtime capability checks and agent create/inspect/stop | Planned |
| [P1-M10](docs/project/PH1/P1M10/README.md) | Managed storage ownership/quotas and secret references | Planned |
| [P1-M11](docs/project/PH1/P1M11/README.md) | Authenticated application gateway and atomic private routes | Planned |
| [P1-M12](docs/project/PH1/P1M12/README.md) | Deployment controller, cancellation and reconciliation | Planned |
| [P1-M13](docs/project/PH1/P1M13/README.md) | Login, sidebar, deployment wizard, timeline and bounded logs | Planned |
| [P1-M14](docs/project/PH1/P1M14/README.md) | Secure-core acceptance and operator setup/backup smoke checks | Planned |

**Next:** P1-M09 runtime capability checks and typed agent. [P1-M08 acceptance](docs/project/PH1/P1M08/testing/acceptance-report.md) records all 214 required ledger cases PASS; normalization does not authorize runtime execution. [P1-M07](docs/project/PH1/P1M07/testing/acceptance-report.md) passed all 146 required ledger cases; it produces admitted artifacts, not deployed applications. P1-M05 and [P1-M06](docs/project/PH1/P1M06/testing/acceptance-report.md) are accepted on their tested isolated VM/templates; later build and controller gates remain separate. Track P1-M04's skipped checks in the [acceptance report](docs/project/PH1/P1M04/testing/acceptance-report.md). There is no working end-to-end deployment platform yet.

**Release gate:** complete the secure-core acceptance harness, actual guest isolation evidence, default-deny authorization, private application routing, independent agent policy, cleanup and authenticated status checks. See the [requirement evidence](docs/project/requirement-evidence.md) for gaps and operator decisions.

Plans: [minimal](docs/plans/PH1/minimal.md), [recommended](docs/plans/PH1/recommended.md), [hardened](docs/plans/PH1/hardened.md).

## PH2 — Embedded applications and routing

Add isolated-origin application frames with the portal sidebar, protected-tab fallback, application sessions, authorized streams and automated route lifecycle.

**Status: planned, 0%.** Depends on P1-M14 and the DNS/origin decisions identified in the plan.

| Milestone | Deliverable | Status |
|---|---|---|
| P2-M01 | Application-origin inventory, host ownership and local CA setup | Planned |
| P2-M02 | One-use authentication handoff and application gateway sessions | Planned |
| P2-M03 | Frame shell, CSP/sandbox policy and protected-tab fallback | Planned |
| P2-M04 | Authorized WebSocket relay, revocation leases and connection registry | Planned |
| P2-M05 | Versioned route creation, disabling, rollback and probes | Planned |
| P2-M06 | Browser compatibility and isolation harness | Planned |

**Release gate:** verify browser origin isolation, direct-URL authorization, safe compatibility fallback and timely WS/SSE revocation.

Plans: [minimal](docs/plans/PH2/minimal.md), [recommended](docs/plans/PH2/recommended.md), [hardened](docs/plans/PH2/hardened.md).

## PH3 — MFA, users and application permissions

Extend authentication with TOTP, recovery codes, user administration and explicit per-application grants.

**Status: planned, 0%.** Normally depends on P2-M06. If day-one MFA is required, move P3-M01–M04 and their prerequisites into the PH1 release scope as specified by the roadmap.

| Milestone | Deliverable | Status |
|---|---|---|
| P3-M01 | Encryption adapter and TOTP/recovery storage | Planned |
| P3-M02 | TOTP enrollment, pending login, confirmation and replay protection | Planned |
| P3-M03 | One-use recovery codes and guarded reset | Planned |
| P3-M04 | MFA interface and mandatory admin enrollment | Planned |
| P3-M05 | User administration and transactional application grants | Planned |
| P3-M06 | Permission interface, session disabling and durable invalidation | Planned |
| P3-M07 | Role/MFA audit and timed HTTP/WS/SSE revocation regression | Planned |

**Release gate:** demonstrate MFA enrollment/login/recovery, no privilege escalation, default-deny grants and revocation within the plan's HTTP and stream limits.

Plans: [minimal](docs/plans/PH3/minimal.md), [recommended](docs/plans/PH3/recommended.md), [hardened](docs/plans/PH3/hardened.md).

## PH4 — Git updates and rollback

Add administrator-triggered branch checks, immutable rebuilds, health-gated updates, deployment history and rollback with data-compatibility checks.

**Status: planned, 0%.** Depends on P3-M07, the PH1 controller and retained image digests.

| Milestone | Deliverable | Status |
|---|---|---|
| P4-M01 | Isolated branch observation and commit comparison | Planned |
| P4-M02 | Deployment intent bound to an immutable commit and current policy | Planned |
| P4-M03 | Generation locking, private candidate and health-gated cutover | Planned |
| P4-M04 | Approved-digest rollback and data-compatibility preflight | Planned |
| P4-M05 | Deployment history, update and rollback interface | Planned |
| P4-M06 | Failure/race regression for updates and rollback | Planned |

**Release gate:** verify immutable updates, race-safe route switching, preserved healthy routes on failure and refusal of unsafe automatic rollback. Code rollback does not promise data rollback.

Plans: [minimal](docs/plans/PH4/minimal.md), [recommended](docs/plans/PH4/recommended.md), [hardened](docs/plans/PH4/hardened.md).

## PH5 — Security assurance and recovery

Establish repeatable adversarial regression, vulnerability response, rotation procedures, encrypted backups, restore drills and release risk review.

**Status: planned, 0%.** Depends on P4-M06 and operator backup, key and retention decisions. Earlier phases retain their own required security gates.

| Milestone | Deliverable | Status |
|---|---|---|
| P5-M01 | Updated threat model and requirement-to-evidence inventory | Planned |
| P5-M02 | Scanner freshness, severity policy and remediation tracking | Planned |
| P5-M03 | Build/runtime patching and secret/key rotation procedures | Planned |
| P5-M04 | Encrypted metadata/key/volume backups and restore drill | Planned |
| P5-M05 | Adversarial regression automation and scoped penetration-test rules | Planned |
| P5-M06 | Remediation review, incident exercise and release risk signoff | Planned |

**Release gate:** demonstrate recovery against agreed objectives, current security evidence and no unresolved critical blockers; document residual risks and owners.

Plans: [minimal](docs/plans/PH5/minimal.md), [recommended](docs/plans/PH5/recommended.md), [hardened](docs/plans/PH5/hardened.md).

## Maintaining this file

When implementation or acceptance evidence changes, update the affected milestone's source documentation, [progress record](docs/project/progress.md) and this overview together. Recalculate phase and overall percentages, preserve skipped/failed-check qualifications and update the review date. If the selected track or milestone scope changes, revise the denominator explicitly before comparing progress.
