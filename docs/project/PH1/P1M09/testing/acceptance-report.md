# P1-M09 acceptance report — INCOMPLETE / NOT PASSED

Date: 2026-10-30. **M09 is not complete and is not passed.** The implementation
increment has passing software checks, but the required complete runtime profile
has not passed and the real agent integration suite is unfinished. No production
runtime is enabled and no accepted runtime template is delivered.

## Executed evidence

- Full `go test -json ./...` with `umask 077`: command succeeded, 23 packages emitted
  PASS. Existing guest-only and optional historical tests retain their own SKIPs;
  these are not accepted as M09 runtime tests.
- The five changed runtime/artifact packages have **137 named software cases and
  subcases PASS**, listed in [software-cases.json](software-cases.json). These
  include existing artifact regressions, not 137 distinct real-runtime cases.
- Targeted race tests for all five packages: PASS. `go vet ./...`: PASS.
- Bounded normalized-command fuzzing: PASS (329 executions in the recorded run).
  Raw repository parsers were not run on management.
- Reporter unit test: PASS. The actual milestone reporter correctly returned
  **INCOMPLETE**, exit 1; [report.json](report.json) records the refusal reasons.

See the [test plan](../test-plan.md), [required runtime ledger](required-cases.json)
and [source/evidence manifest](evidence-manifest.json). The required ledger has
**1 FAIL and 9 NOT_RUN**, so none can be omitted or promoted to PASS.

## Real VM development observations

The fresh no-NIC KVM guest used Linux 6.12.113+deb13-amd64, QEMU 10.0.13, Debian
trixie, systemd 257.13 and pinned Docker/rootless extras 29.5.0. The legacy Debian
Docker 26.1.5 was also investigated in earlier development runs. Images were made
from a trusted never-executed root tree, booted with snapshot writes and externally
bounded. No workload disk was mounted on management.

Engine requests alone proved insufficient: Docker accepted the requested
AppArmor option but returned an empty applied profile. A minimal experimental
OCI wrapper could apply the preloaded profile and observe `tap-runtime (enforce)`,
CapEff=0, NoNewPrivs=1 and Seccomp=2. This was a narrow feasibility result from a
different prototype, not full-profile or M09 acceptance.

A stricter experiment attempting new UID maps failed with uid_map EPERM. The
current supplement preserves and validates engine-generated namespace mappings
instead, but its complete fixture still does not start. The recorded
[current feasibility log](runtime-feasibility.log) contains that failure. A later
[bounded diagnostic](runtime-diagnostic.json) identifies its first failed check:
the actual bundle has no user namespace entry and null UID/GID mappings, while
the supplement requires an explicit private user namespace. This is a mismatch
between the engine-generated configuration and the required profile. It must not
be described as successful isolation, or as proof that every possible rootless
stack is unsupported. The earlier uid_map EPERM was a separate experiment.

Private development artifacts, including earlier failed runs and template/tool
files, remain under `/var/lib/orchestrator-builder/m09-tools/`. The shipped
`tools.lock.json` pins development downloads only; it does not certify a release
stack. No external packet-capture, full resource-attack or management-identity
acceptance exists in this increment.

## Remaining implementation and acceptance work

1. Finish the actual restricted runtime profile and its measured capability,
   network, storage and capacity-enforcement adapter. Integrate the accepted MAC/
   namespace approach into engine configuration and observed-state verification.
2. Supply concrete durable approval/admission/lease adapters and connect private
   artifact retrieval to those records. The current code provides narrow trusted
   interfaces and bounded transport, not product scheduling or an approval service.
3. Wire the runtime-agent process/service, outbound polling/results, capability
   signing, recovery, drift/quarantine and independently confirmed cleanup. The
   current adapter refuses readiness when required enforcement is missing.
4. Complete the full R01–R10 runtime driver and execute every constituent test,
   including real approved OCI import, one/two-service candidates, IPv4/IPv6
   network attacks, resource exhaustion, restart/crash/revocation and actual
   management socket/credential isolation. Nonzero workload restart attempts
   currently refuse execution; durable retry dispatch remains unfinished.
5. Freeze final code/templates/policy, rerun all checks, hash the new evidence and
   require every runtime case PASS with a clean final inventory before accepting
   M09. The present source manifest and development logs cannot substitute.

M10 volume/secret materialization, M11 authenticated routing and M12 scheduling
remain separate milestones. This increment makes no PH1 release/security-gate
completion claim.

## Follow-up isolation feasibility

A [two-app kernel observation](isolation-direction.json) confirmed that the tested
shared engine gives the two apps the same user namespace and leaves both
unconfined. A separate rootless engine per app, with the minimal fixed MAC
prototype, produced distinct app user namespaces and `tap-runtime (enforce)` for
both in a NIC-less VM. This establishes a candidate design direction only. It
does not complete R01 or change any required runtime gate to PASS. The
[recovery sequence](../implementation-plan.md#recovery-sequence-after-the-incomplete-implementation-increment)
starts with app-scoped engine ownership and measured enforcement, then one
complete signed lifecycle before the remaining test suite.
