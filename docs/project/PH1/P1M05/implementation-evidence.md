# P1-M05 implementation and validation evidence

Status: **Implemented/tested; isolated-KVM acceptance PASS** on 2026-10-28.
See the [acceptance report](testing/acceptance-report.md) for N01–N13 and the
[LLD](../../../../LLD-documents/PH1/p1-m05.md) for implementation details.
M04 V14/V15 remain SKIP; this milestone does not pass those historical checks
or enable repository execution.

## Delivered implementation

- Versioned operator policy with exact host:443 admission, strict bounded JSON,
  policy/CA pins, special-purpose IPv4/IPv6 classification and infrastructure
  deny CIDRs. Empty allowlist defaults to deny.
- External inspecting HTTPS broker enforcing CONNECT/SNI/HTTP agreement,
  dedicated TCP DNS, validation of every answer and numeric-IP dialing,
  independently verified upstream TLS, no redirect/upgrade/arbitrary tunnel or
  authority-changing reuse, sanitized reason codes and bounded resources.
- Per-lease uplink-free namespace/TAP, MAC/IP/ARP/IPv6 filtering, atomic nftables
  installation before activation, and an already-open TAP passed to QEMU FD 5.
  QEMU retains its unprivileged identity and has no network setup capability.
- Owned transient broker service with an inherited namespace listener, root-only
  input capabilities and dedicated UID. No management paths, authority or keys
  are supplied to its child. Production has no test destination/TLS override.
- Versioned durable namespace identity, policy binding, late-start fence,
  cancellation, independent CLOCK_BOOTTIME expiry, cgroup confirmation and
  conservative crash/foreign-resource cleanup. Guard recovery does not require
  live policy/CA health; new admission does.
- Operator installation/rollback documentation, policy/firewall references,
  credential-free pinned guest probes, raw UDP/IPv6/RA/protocol probes and two
  opt-in lab harnesses. Controlled fixtures and capture code are test-only.

## Software validation

Executed with Go 1.27.3 on Linux:

| Check | Actual result |
|---|---|
| `umask 077; /usr/local/go/bin/go test -race ./...` | PASS |
| `/usr/local/go/bin/go vet ./...` | PASS |
| Broker/provisioner/fixture builds | PASS; installed binaries executed in KVM lab |
| Policy decode fuzz, 2 s / 2 workers | PASS; 41,981 executions |
| Authority fuzz, 2 s / 2 workers | PASS; 39,693 executions |
| Address classification fuzz, 2 s / 2 workers | PASS; 27,425 executions |
| Shell syntax and Python compilation | PASS |
| `git diff --check` | PASS |

The existing metadata tests require a private umask. The first earlier run
without it failed existing storage/lease permission checks; the corrected run
passed. Ordinary software runs intentionally SKIP opt-in infrastructure tests;
the separate installed root test binary executed the real-host cases below.
A sandbox-only device check hid `/dev/kvm` and `/dev/net/tun`; checking outside
the sandbox confirmed both devices and KVM API version 12. No emulator was used.

U01–U10 are covered by software and actual-host checks: malformed policy,
authority mutation, IPv4/IPv6 ranges, mixed/mapped/rebound DNS, peer/lease/SNI/
HTTP mismatch, TLS failure, redirects/upgrades/tunnels/reuse, expiry/revocation,
slow/oversized input, concurrency/rate/byte caps, sensitive diagnostic exclusion,
legacy/unknown manifests and foreign ownership. The slow-header guest probe
observed a bounded refusal after 5,000 ms (103 response bytes), not an open
connection. It correctly treats HTTP error responses as denial.

## Executed real KVM checks

The user explicitly authorized internal controlled fixtures in this isolated
VM. The final run used synthetic globally classified addresses assigned only
to loopback, a local authoritative TCP resolver, HTTPS servers with a separate
temporary upstream CA, and production broker binaries without bypass switches.
The build CA was separately pinned in the guest template. No synthetic address
was contacted through an external route.

Final private evidence directory:

`/var/lib/orchestrator-builder/m05-lab.4cac6wpp/controlled.1793215611889984415/`

| Installed real test | Final result | Duration |
|---|---|---|
| Network lifecycle, guest-root protocol/resource probes and captures | PASS | 61.12 s |
| Independent expiry with both supervisors SIGSTOPed and an active transfer | PASS | 22.10 s |
| Setup crash recovery at seven boundaries | PASS, all seven subcases | 19.04 s |
| Foreign namespace/firewall preservation | PASS | 0.17 s |
| Invalid/missing/stale policy admission and guard restart | PASS | 0.15 s |
| Creation/cancellation race and delayed-start fence | PASS | 2.87 s |
| Active-transfer cancellation | PASS | 14.86 s |

Captures contain 1,801 guest-boundary frames and 1,476 selected host frames,
including IPv6. Both capture sockets reported **zero packet loss**. Namespace
rules recorded 62 ingress drops. Host capture assertions found **zero escaped
guest frames** and **zero protected-destination frames**. The other-job TAP
capture contained zero frames. Controlled DNS/HTTPS logs contained 92 events
and **zero forbidden arrivals**. Capture, log and source hashes are recorded
in `final-inventory.json`; raw captures, private keys and ownership proofs stay
outside the repository.

The final inventory checked 55 lab jobs across all development runs: no owned
VM/broker active unit or populated cgroup, no working raw disk and no remaining
namespace. Temporary loopback aliases and fixture processes were removed;
temporary trust was removed and the host trust bundle matched its baseline.
The host firewall structure and original M04 backend configuration were unchanged.
Pristine images, binaries, private lab keys, reports and audit tombstones are
retained for review, not represented as active runtime resources.

## Reproduction and development history

- [Controlled internal acceptance procedure](testing/real-host.md).
- [Installation, fixture and rollback runbook](../../../../infra/egress/README.md).
- Initial public-origin smoke: `/var/lib/orchestrator-builder/m05-lab.64mh0p_x/run.log`.
- Full public-origin fault-suite rerun: `/var/lib/orchestrator-builder/m05-lab.4cac6wpp/retest.1793213828482539887.log` (PASS).
- First controlled capture run: `controlled.1793214689830319214/` (PASS).
- Expanded run: `controlled.1793215086094343461/` retained a failed slow-header
  assertion: the server returned a bounded denial, but the probe incorrectly
  required an empty response. This was a harness error, corrected before the
  final PASS. Earlier crash/canary harness error-variable and nft syntax fixes
  are likewise retained in `m05-lab.4cac6wpp/run.log`; no failed run is relabeled.

All private subdirectories above are under the same scoped lab directory.
Current source base is `3a8ad369707190c9ad89876bb25ab9cc0f31ab60` plus the
uncommitted implementation; exact source file hashes are retained with the
final binary hashes. Acceptance covers this isolated VM and tested template,
not arbitrary production hosts, host patch compliance, private Git credentials,
BuildKit, artifact ingestion or later platform release gates.
