# P1-M04 acceptance record — NOT PASSED

Copy this file into the private evidence directory. Do not change status to PASS
until the complete Linux checklist and real-host procedure have been executed.
Cross-compilation, a skipped host test or simulated lifecycle test cannot pass it.

| Required evidence | Result / log / measured value |
|---|---|
| Tester, reviewer and UTC date | NOT RUN |
| Exact commit and source diff | NOT RUN |
| Debian, kernel, systemd, QEMU, CPU/hypervisor versions | NOT RUN |
| Nested KVM, cgroup v2, alarm timers, local ext4/XFS | NOT RUN |
| Approved image SHA-256 and credential-free image review | NOT RUN |
| S01–S05 and P01–P03 | NOT RUN |
| S06 fuzz smoke | NOT RUN |
| Real-host test binary SHA-256; no skipped host tests | NOT RUN |
| Real creation/release, kernel envelope, tombstone replay | NOT RUN |
| Frozen supervisor hard expiry, empty cgroup and observed lateness | NOT RUN |
| Foreign canary unchanged; slot held during cleanup failures | NOT RUN |
| V01–V16, each evidence path and measured result | NOT RUN |
| Source/kernel/hypervisor security review | NOT RUN |
| Baseline versus final exact owned-resource inventory | NOT RUN |
| Residual risks and operator/reviewer sign-off | NOT RUN |

**Decision: NOT PASSED.** Any mandatory FAIL, BLOCKED, SKIP or NOT RUN keeps
M04 unpassed. The release owner must review the evidence, not merely check that a
command ran. A changed implementation/image/policy invalidates relevant results;
repeat affected cases. This record is not permission to enable M05 egress/builds.
