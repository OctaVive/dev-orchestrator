# P1-M04 - Fixed VM template/provisioner contract and hard-expiry lifecycle

Status: **Implemented/tested*; V14 and V15 SKIP**.

## Requirement and acceptance contract

- Scope: Fixed VM template/provisioner contract and hard-expiry lifecycle.
- Prerequisites: [P1-M01](../P1M01/README.md).
- Acceptance gate: Guest create/destroy/expired lease proven; no arbitrary XML/path input.
- Source: [PH1 minimal plan](../../../plans/PH1/minimal.md).
- Requirements: [project requirements](../../requirements.md), [requirement-to-milestone map](../../requirement-milestones.md) and [evidence checklist](../../requirement-evidence.md).
- Security coverage: SEC-08, SEC-10, SEC-11.

## Documents

- [build provisioner](build-provisioner.md)
- [acceptance report](testing/acceptance-report.md)
- [command debug plan](testing/command-debug-plan.md)
- [linux checklist](testing/linux-checklist.md)
- [real host](testing/real-host.md)
- [deployment agent](../../specifications/deployment-agent.md)

## Implementation history and validation

## P1-M04 — provisioner lease/mTLS core (historical increment)

Historical foundation status (superseded by the Linux implementation increment below): core implemented; real Linux backend and guest-create/destroy/expiry acceptance not completed at this point. No VM, service installation, image download, hypervisor command or network change was performed.

### Deliverables

- `api/build-lease.schema.json`, `api/provisioner.openapi.yaml`: bounded controller-only protocol; fixed template/profile IDs, immutable ≤30-minute deadline, no XML/path/network/shell/credential input.
- `internal/provisioner`: separate host-private SQLite namespace/schema/checksum, one-slot reservation, immutable identity/deadline/tombstones, command/nonce replay prevention, transactional versioned lifecycle events and ownership proof kept off the wire.
- Cleanup/expiry/restart reconciliation and independent guard loop; capacity retained on failure or partial cleanup. A fresh guard heartbeat and every backend enforcement control are required before admission.
- `internal/provisionerrpc`: real TLS 1.3 mutual auth, explicit client CA, pinned short-lived controller leaf, exact URI SAN and per-request expiry checks; no portal cookie/Origin/identity-header fallback.
- `cmd/provisioner`: loopback-only contract prototype. **Only UnconfiguredBackend is linked**, no simulator/unsafe fallback flag. Capabilities report false; create returns 503; unsupported guard does not claim readiness.
- Tests: actual SQLite and local mTLS; test-only simulated VM state for idempotency, quota specification, expiry, cleanup failures, cancellation/late-start fencing, foreign resource protection and interrupted-startup reconciliation. The simulator is not linked into production.

### Acceptance still blocked

The driver does not implement KVM/libvirt, pinned image measurement, host quotas, broker/disconnected networking, a host-monotonic hard kill or real late-start fencing. No mock result proves those controls. Real build execution is deliberately unavailable, and P1-M04 must not be marked complete based on these tests.

### Verification of the implemented core

Executed with portable Go 1.27.3 on Windows:

| Check | Result |
|---|---|
| Full uncached test suite with coverage | PASS: provisioner core 77.6%, provisioner mTLS 70.6%, prototype command 47.6%, contracts 90.4%; previous auth/storage/API regression tests also pass |
| Late-start/cancellation/concurrent-create model tests, `-count=20` | PASS; these use test-only simulated VM maps, not real guests |
| Real local mTLS tests | PASS: missing/untrusted/expired clients rejected, pinned worker URI denied, unpinned controller denied, reused connection expiry rechecked; shipped backend create remains 503 |
| Build-lease decoder fuzz, 10 s / two workers | PASS, 279,950 executions; bounded smoke evidence only |
| `go vet ./...` | PASS |
| `go mod verify` | PASS; no new dependencies introduced |
| Linux amd64 CGO-disabled cross-compilation | PASS, not Linux runtime execution |
| Local Markdown links | PASS, zero broken links |

No actual KVM, host firewall/quota, independent kernel timer, Linux permissions or race-detector result is claimed. No VM image, production credential, service installation or host network setting was created/changed.

## P1-M04 — Linux implementation and testing

Status: **Implemented/tested\*.**

\* V14 and V15 marked as SKIP. V01–V13 and V16 passed; neither skipped case is counted as passed. The separate qualified acceptance decision remains PASS* in the [acceptance record](testing/acceptance-report.md).

- Real QEMU/KVM/systemd backend with fixed pinned images, non-root guests, no NIC, resource limits and independent immutable expiry.
- Real lifecycle, boot, image tampering, CPU/memory/IO/PID limits, controller/API/guard loss, delayed-start fencing, crash recovery and foreign-resource checks executed successfully.
- Disk and ready-marker ownership uses stable filesystem UUID/inode identity; storage-controller changes no longer invalidate UUID-aware records. Legacy recovery preserved the original audit record and cleaned the historical disk.
- Final inventory verified: no owned guest, active timer, populated cgroup, guest disk/ready marker or active test lease remains.
- Software tests, vet, race detection and deployed-binary verification passed. Private logs, hashes and recovery evidence remain outside the repository.
- V14 time/ledger fault acceptance and V15 network/patch-posture acceptance remain SKIP at operator request; their findings and deferred work are retained.

See the [provisioner implementation](build-provisioner.md), [host procedure](testing/real-host.md), and [acceptance record](testing/acceptance-report.md) for details. The earlier core-increment sections document historical implementation stages rather than current M04 limitations.

### Next work: P1-M05 — controlled build egress

Implement and verify the external build egress broker and firewall isolation before M06 repository cloning and M07 builds. M05–M14 remain unimplemented. P1-M08 policy work can proceed independently after M01.
