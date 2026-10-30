# P1-M08 - Strict Compose/Dockerfile normalization and agent policy contract

Status: **Implemented/tested; isolated-KVM M08 acceptance PASS**.

## Requirement and acceptance contract

- Scope: Strict Compose/Dockerfile normalization and agent policy contract.
- Prerequisites: [P1-M01](../P1M01/README.md).
- Acceptance gate: SEC-06; one Dockerfile and two-service subset fixtures accepted.
- Source: [PH1 minimal plan](../../../plans/PH1/minimal.md).
- Requirements: [project requirements](../../requirements.md), [requirement-to-milestone map](../../requirement-milestones.md) and [evidence checklist](../../requirement-evidence.md).
- Security coverage: SEC-06.

## Documents

- [implementation plan](implementation-plan.md)
- [implementation evidence](implementation-evidence.md)
- [post-implementation test plan](test-plan.md)
- [acceptance report](testing/acceptance-report.md)
- [per-case acceptance ledger](testing/acceptance-results.json)
- [configuration policy and contract](../../specifications/configuration-policy.md)
- [deployment agent](../../specifications/deployment-agent.md)

All **214 required acceptance ledger cases PASS**, including actual guest parsing/fuzzing, both accepted runtime-spec fixtures, policy denial and the complete M07 pipeline regression. No required cases are failed, missing or skipped. Runtime execution/authorization remain M09; normalization does not approve or deploy. Shared contracts stay in `../../specifications/`.
