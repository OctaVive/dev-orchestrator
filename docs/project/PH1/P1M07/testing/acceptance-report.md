# P1-M07 acceptance report

Result: **PASS** on 2026-10-30. All **146 required ledger cases PASS**, with zero
failed, missing or skipped required cases. See the
[post-implementation test plan](../test-plan.md) and
[per-case ledger](acceptance-results.json).

## Delivered and exercised

- Actual HTTPS Git clone, durable immutable SHA/context handoff and predeclared
  build authorization in the same fresh KVM VM.
- Rootless BuildKit with process sandboxing, fixed frontend/source policy,
  digest-pinned base pull through M05 and offline RUN. The controlled metadata
  request was unreachable; inherited ONBUILD remote ADD was denied with zero
  remote-target arrivals.
- Separate TLS artifact-service process, private Unix control socket, opaque
  quarantine bytes and exact archive/image digest distinction.
- Fresh separate no-network ingest VMs with read-only job/artifact/database
  devices; UID-separated validation/scanning and a root-frozen layout.
- Hostile OCI/layer/gzip/JSON corpus, safe internal links/whiteouts, actual Trivy
  clean/vulnerable images, strict unfixed HIGH/CRITICAL policy and exact expiring
  exceptions. The vulnerable fixture produced actual HIGH/CRITICAL counts.
- Actual build timeout, cancellation, controller loss, scanner expiry and log,
  disk, memory and PID exhaustion. Actual systemd CPU/memory/tasks/capabilities
  and fixed raw disk limits were checked. SQLite remained available under the
  controller-loss CPU case; recovery durably recorded the timeout.
- Atomic metadata/admission/outbox, stale-result fences, failure after expiry,
  crash recovery after export/promotion, service-loss denial and foreign-resource
  preservation. Admission left deployment SCANNING, never APPROVED.

## Execution evidence

| Check | Actual result |
|---|---|
| Fresh repository software suite | 387 test/subtest PASS results across 17 passing packages |
| `go vet ./...` | PASS |
| Targeted `-race` tests: artifacts/buildjob/storage/provisioner | PASS |
| Bounded contract fuzzing | PASS |
| Python and shell syntax checks | PASS |
| Independent ingest KVM cases | clean, vulnerable, malformed: all PASS; final host-binary rerun 137.16 s |
| Guest corpus, actual Trivy and coverage-guided OCI fuzz | All PASS in each ingest VM |
| Host identity regression | Fresh rootless VM PASS; QEMU UID/GID dropped and CapEff zero under the new supervisor profile |
| Complete pipeline KVM matrix | All 10 scenarios PASS; 252.04 seconds |
| Controlled registry | 30 actual requests |
| Packet capture | 1,807 packets captured; zero kernel drops |
| Protected/remote-source canaries | Zero forbidden arrivals |
| Source inventory | Unchanged from pre-build snapshot through final run |
| Cleanup | Owned VM disks absent; temporary trust restored; base firewall unchanged |

Ordinary software runs deliberately leave privileged entry points disabled.
Their actual M07 KVM cases above were separately executed and passed; those
software SKIPs are not used as acceptance evidence. M04 V14/V15 retain their
historical SKIP outcomes and are not reclassified.

Pinned runtime: Go 1.27.3, Debian kernel 6.12.113+deb13-amd64, QEMU 10.0.13,
BuildKit 0.34.1, Trivy 0.76.1. Exact source, binary, template and database hashes
are in [pipeline evidence](pipeline-evidence.json),
[software checks](software-checks.json) and
[evidence manifest](evidence-manifest.json). Bounded readable evidence:
[pipeline log](pipeline.log), [ingest log](ingest.log),
[cleanup record](cleanup.json), [host identity regression](host-identity.log) and
[final ingest identities](ingest-evidence.json).

Private full pipeline evidence:
`/var/lib/orchestrator-builder/m05-lab.4cac6wpp/m07.1793368911214050600/`.
The manifest records the separate private software evidence directory. Private
TLS keys, database image, raw VM images and packet captures are retained there;
they are not copied into the repository. No production service was enabled.

## Findings fixed before final acceptance

Development failures remain retained; they are not relabeled PASS. Rootless RUN
required switching the fixture off initramfs rootfs before runc pivot_root.
The large vulnerability DB moved to a separately pinned read-only disk. Trivy's
OCI input requires a validated layout directory. Job IDs became fresh per case.
Upload transport stopped sending a Connection header forbidden by the broker.

The controller-loss test found that an expired timer could not signal QEMU after
its UID drop: the supervisor lacked CAP_KILL. Both no-network and broker-network
supervisor capability profiles now include CAP_KILL. QEMU still drops to its
unprivileged account; no guest receives that host capability. The host timer is
armed before authorization delivery and the corrected independent deadline
passed with the build controller absent. A timer-rearm regression test also
passes. No sandbox or TLS validation was disabled to obtain acceptance.

## Scope and remaining work

Acceptance applies to the tested host/templates and conservative profile: one
linux/amd64 image, offline build steps, restricted Dockerfile inputs and bounded
OCI formats. Large or unsupported images fail closed. Existing metadata databases
require the verified-snapshot upgrade workflow before migration 003.

M08 normalization, M09 runtime delivery, M12 scheduling/approval/full reconciliation,
full referenced-artifact retention/GC and production patch/rollout compliance
remain separate gates. Scan admission does not prove image benignness or source
provenance from a compromised builder, and does not deploy an application.
