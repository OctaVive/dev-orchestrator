# P1-M07 - Rootless BuildKit export and isolated ingest/scanner adapter

Status: **Implemented/tested; isolated-KVM acceptance PASS** on 2026-10-30. All 146 required ledger cases PASS.

## Requirement and acceptance contract

- Scope: Rootless BuildKit export and isolated ingest/scanner adapter.
- Prerequisites: [P1-M06](../P1M06/README.md).
- Acceptance gate: Digest matches, budgets kill guest, hostile archives quarantined.
- Source: [PH1 minimal plan](../../../plans/PH1/minimal.md).
- Requirements: [project requirements](../../requirements.md), [requirement-to-milestone map](../../requirement-milestones.md) and [evidence checklist](../../requirement-evidence.md).
- Security coverage: SEC-08, SEC-10.

## Documents

- [implementation plan](implementation-plan.md)
- [post-implementation test plan](test-plan.md)
- [implementation and validation evidence](implementation-evidence.md)
- [acceptance report](testing/acceptance-report.md)
- [per-case results](testing/acceptance-results.json)
- [shared build/ingest contract](../../specifications/build-ingest.md)
- [build runbook](../../../../infra/build/README.md)
- [ingest runbook](../../../../infra/ingest/README.md)

- [deployment agent](../../specifications/deployment-agent.md)

The complete software and isolated-KVM matrix passed with zero failed, missing or skipped required cases. Admission leaves deployment SCANNING; runtime deployment and approval remain later milestones. Historical M04 V14/V15 SKIPs remain unchanged.
