# Weighted architecture comparison

Scale: 1 poor, 5 best. Higher consumption/complexity scores mean **lower** resource use/easier operation. Weights sum to 100. Scores are architectural judgments, not measurements. A–D are assessed without adding E; otherwise build-security differences would be hidden.

| Criterion | Weight | A privileged DinD | B host engine | C local rootless agent | D runtime VM | E ephemeral builders + D |
|---|---:|---:|---:|---:|---:|---:|
| Security | 20 | 1 | 2 | 3 | 4 | 5 |
| Ease of implementation | 8 | 4 | 5 | 3 | 3 | 2 |
| Runtime isolation | 15 | 1 | 1 | 2 | 4 | 4 |
| Resource consumption | 8 | 4 | 5 | 5 | 3 | 2 |
| Maintainability | 10 | 2 | 4 | 3 | 4 | 3 |
| Deployment complexity | 7 | 3 | 5 | 3 | 2 | 2 |
| Git build security | 15 | 1 | 1 | 2 | 2 | 5 |
| Application networking | 7 | 2 | 4 | 2 | 4 | 4 |
| Persistent storage | 5 | 2 | 4 | 3 | 4 | 4 |
| Future scalability | 5 | 2 | 2 | 3 | 4 | 5 |
| Weighted result / 5 | 100 | **1.89** | **2.83** | **2.79** | **3.40** | **3.84** |

Rootless DinD improves A's privilege posture, but not shared-kernel build isolation. Its exact score is implementation dependent and still fails mandatory gates. Weighted scores cannot override a failed security gate.

## Performance / operations

- B/C have fastest cold starts and smallest idle footprint; C can have user-space networking and filesystem overhead.
- D adds VM memory and I/O overhead, usually acceptable for a small platform. Runtime container starts remain fast.
- E adds guest startup, fresh build cache misses, artifact transfer and scanner cost. Budget approximately 10–120 seconds of infrastructure overhead as a hypothesis to measure, not an SLO. Concurrency one and controlled registry mirrors limit load.
- Cached artifacts are content-addressed, scoped and read-only across jobs; no guest or writable build cache is trusted after executing repository code.

## Recommendations

**PH1:** E with one disposable builder at a time, one restricted runtime VM (D), and a management VM on a single supported Linux hypervisor. Host resources and provisioning complexity are accepted to satisfy untrusted-build requirements now. If unavailable, offer documentation/demo only; do not label C plus local builds a secure MVP.

**Long term:** E with dedicated physical builder and runtime hosts, hardened hypervisor control, isolated registry/egress, per-app runtime VMs for hostile or mutually distrusting workloads, external audit/backup destination. No Kubernetes required.

**Why not privileged DinD:** E separates guest kernels and management credentials, provides an externally enforceable egress boundary, and destroys build state. DinD privilege largely undermines its outer container and does not create any of these guarantees.

## Migration

Persist worker IDs, deployment digests and volume ownership from PH1. Drain a worker; quiesce app writes; snapshot/export volumes and verify backup; restore to new worker; register new short-lived mTLS identity; deploy same immutable digest/spec; health check; atomically switch route generation. Keep old worker stopped and isolated until restore validation. Revoke old identity. Cross-host rollback requires compatible data state; never restore stale data automatically over writes. Platform API and application IDs remain stable.
