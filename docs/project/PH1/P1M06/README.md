# P1-M06 - Clone runner with HTTPS/ref/context limits and malicious Git fixtures

Status: **Implemented/tested; isolated-KVM acceptance PASS** (2026-10-30).

## Requirement and acceptance contract

- Scope: Clone runner with HTTPS/ref/context limits and malicious Git fixtures.
- Prerequisites: [P1-M05](../P1M05/README.md).
- Acceptance gate: Rebinding/helper/submodule/redirect corpus denied, SHA recorded.
- Source: [PH1 minimal plan](../../../plans/PH1/minimal.md).
- Requirements: [project requirements](../../requirements.md), [requirement-to-milestone map](../../requirement-milestones.md) and [evidence checklist](../../requirement-evidence.md).
- Security coverage: SEC-07.

## Documents

- [acceptance report — all 83 required cases PASS](testing/acceptance-report.md)
- [machine-readable case ledger](testing/acceptance-results.json)
- [implementation plan](implementation-plan.md)
- [post-implementation test plan](test-plan.md)
- [implementation and validation evidence](implementation-evidence.md)
- [restricted clone-worker contract](../../specifications/clone-runner.md)
- [clone operator/lab runbook](../../../../infra/clone/README.md)
- [deployment agent](../../specifications/deployment-agent.md)

The runner, transport, persistence and isolated-lab harness are implemented. All
83 required cases passed, including 51 actual Git cases, independent expiry,
crash/foreign-resource/race checks, durable SHA handoff and the M05 regression.
Final inventory confirmed all 67 owned jobs cleaned up. Shared contracts stay
in `../../specifications/`. M04 V14/V15 remain historical SKIPs; production
rollout, private Git credentials, M07 builds and the M12 controller remain separate.
