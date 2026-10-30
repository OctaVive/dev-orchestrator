# P1-M09 - Runtime capability probe and typed agent create/inspect/stop

Status: **In progress; NOT PASSED**.

## Requirement and acceptance contract

- Scope: Runtime capability probe and typed agent create/inspect/stop.
- Prerequisites: [P1-M08](../P1M08/README.md).
- Acceptance gate: SEC-05/08/16; real engine constraints verified, no host ports.
- Source: [PH1 minimal plan](../../../plans/PH1/minimal.md).
- Requirements: [project requirements](../../requirements.md), [requirement-to-milestone map](../../requirement-milestones.md) and [evidence checklist](../../requirement-evidence.md).
- Security coverage: SEC-03, SEC-05, SEC-08, SEC-16.

## Documents

- [Implementation plan](implementation-plan.md)
- [Implementation evidence](implementation-evidence.md)
- [Test plan](test-plan.md)
- [Acceptance report — INCOMPLETE](testing/acceptance-report.md)
- [Runtime execution contract](../../specifications/runtime-execution.md)
- [deployment agent](../../specifications/deployment-agent.md)

The current code increment has 137 passing named software cases across the changed runtime/artifact packages. Full runtime acceptance is incomplete: the required ledger has 1 FAIL and 9 NOT_RUN. Missing measured enforcement refuses deployment. No production runtime service is wired or enabled. Shared contracts stay in `../../specifications/`.
