# PH5 — Hardened long-term implementation

## Objective / scope / architecture

Migrate to separate physical management, builder and runtime hosts and support per-app/per-trust-group runtime VMs. Preserve lightweight controller and typed agents; do not evolve into Kubernetes. Recommended target for mutually distrusting or high-impact apps.

Dependencies: P5-R05, hardware budget, per-app isolation policy, backup/volume migration rehearsal. Files: `internal/{jobs,runtime,volumes,proxy}`, `infra/{runtime,builder,management}`, worker capability/migration schema, `tests/integration/migration`, long-term operations docs.

| ID | Task/output | Depends | Size | Acceptance |
|---|---|---|---|---|
| P5-H01 | Physical separation rollout and host identity/network policy | P5-R05 | L | Workload NICs cannot reach host control plane; independent resource failure tested |
| P5-H02 | Per-app runtime VM profile and placement capability model | H01 | L | Two hostile fixture apps no longer share guest kernel or volumes |
| P5-H03 | Quiesced volume export/restore and digest-preserving worker migration | H02 | L | No concurrent SQLite writers; checksums/ownership/health verified before route switch |
| P5-H04 | Compromised-worker quarantine, credential rotation and rebuild drill | H03 | M | External isolation works even if agent lies; unaffected app/management domains remain reachable |
| P5-H05 | Independent escape/segmentation review and final assurance statement | H04 | L | Explicit tested boundaries and residual hypervisor/operator risks published |

Sequential H01→H02→H03→H04→H05; migration fixtures/runbooks can be drafted after H01 in parallel with H02. Hardware operations require explicit authorization, not inferred from plan approval.

Security/testing: external hypervisor controls, per-app disk ownership/quotas, service/CA separation, no flat worker mesh, backup encryption, command replay protection and immutable image approval. Simulate malicious runtime agent reporting false health; external probes and route policy must limit trust. Test host shutdown, control-plane partitions and attempted cross-VM app access.

Complexity very high, ~6–12 additional weeks plus hardware/review. Risks: operational burden, VM proliferation, physical network configuration, data migration downtime and hypervisor exploits. Acceptance/done: application migration/restore/quarantine is tested, management can survive an isolated worker failure, no unsupported shared-kernel hostile-tenancy claim, documented residual CPU side channels and privileged-host compromise.
