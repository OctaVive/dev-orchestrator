# P1-M05 - External build egress broker and firewall template

Status: **Implemented/tested; isolated-KVM acceptance PASS**.

## Requirement and acceptance contract

- Scope: External build egress broker and firewall template.
- Prerequisites: [P1-M04](../P1M04/README.md).
- Acceptance gate: IPv4/IPv6 internal, metadata and direct internet denied in guest.
- Source: [PH1 minimal plan](../../../plans/PH1/minimal.md).
- Requirements: [project requirements](../../requirements.md), [requirement-to-milestone map](../../requirement-milestones.md) and [evidence checklist](../../requirement-evidence.md).
- Security coverage: SEC-07.

## Documents

- [Implementation plan](implementation-plan.md)
- [Test plan](test-plan.md)
- [deployment agent](../../specifications/deployment-agent.md)

Implemented: inspecting HTTPS broker, pinned operator policy and build CA, conservative IPv4/IPv6 address validation, per-lease namespace/TAP filtering, QEMU descriptor inheritance, owned transient broker services, cancellation, independent expiry and crash reconciliation. No-NIC mode remains the default. Software checks and the controlled N01–N13 KVM acceptance suite passed, including simultaneous captures and zero forbidden canary arrivals.

- [Low-level implementation design](../../../../LLD-documents/PH1/p1-m05.md)
- [Implementation and validation evidence](implementation-evidence.md)
- [Acceptance report](testing/acceptance-report.md)
- [Real-host smoke/fault and acceptance procedure](testing/real-host.md)
- [Installation and rollback](../../../../infra/egress/README.md)

Shared contracts stay in `../../specifications/`.
