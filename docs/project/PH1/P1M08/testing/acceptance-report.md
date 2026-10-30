# P1-M08 acceptance report

Result: **PASS** on 2026-10-30. All **214 required ledger cases PASS**, with zero
failed, missing or skipped required cases. See the
[post-implementation test plan](../test-plan.md),
[per-case ledger](acceptance-results.json) and
[implementation evidence](../implementation-evidence.md).

## Delivered and exercised

- Actual HTTPS clone into a fresh pinned KVM guest, strict guest configuration
  normalization, independently validated durable plan/source identity, exact
  build authorization and guest reanalysis before execution.
- Actual rootless offline BuildKit builds, opaque TLS uploads, separate fresh
  no-network digest validation/scanning VMs and immutable image admissions.
- Accepted single-Dockerfile and two-service Compose fixtures, each producing a
  canonical spec that also passed the independent agent policy gate. The second
  fixture used the first independently scanned image as its external service and
  separately built/scanned its local service. No digest was accepted from syntax alone.
- Actual forbidden Compose fixture fetched/exported successfully and then denied
  by configuration policy, with durable denial and owned cleanup.
- All guest strict YAML/Dockerfile and embedded hostile fixtures, five-service
  limit, nested Compose context semantics, static/racing symlinks, parser budget/
  cancellation/diagnostic checks and two coverage-guided parser fuzzers PASS.
- Independent normalized controller/agent denials, canonical golden identity,
  image/source/ownership binding, runtime/build data separation, event redaction,
  protocol version/framing and transactional stale/cancelled/replayed fences PASS.
- Complete ten-scenario M07 pipeline regression PASS on the changed templates:
  success, build timeout, cancellation, controller loss, scanner expiry, log,
  disk, memory and PID exhaustion, and inherited remote source denial.

## Execution evidence

| Check | Actual outcome |
|---|---|
| C01 accepted inputs and real spec finalization | PASS |
| C02 strict YAML corpus and bounded fuzzing | PASS |
| C03 SEC-06 forbidden fields at guest/controller/agent boundaries | PASS |
| C04 Dockerfile, path, race and remote-source restrictions | PASS |
| C05 canonical identity and semantic/resource limits | PASS |
| C06 admission/source/ownership and runtime-input separation | PASS |
| C07 independent agent policy and normalized decoder fuzzing | PASS |
| C08 durable/versioned/framed handoff and lifecycle fences | PASS |
| C09 parser budgets and value-free diagnostics/events | PASS |
| C10 complete regression, unchanged source and cleanup | PASS |
| Fresh `go test -count=1 -json ./...` | 471 test/subtest PASS results; 19 passing packages |
| `go vet ./...` | PASS |
| Targeted race checks across seven packages | PASS |
| Agent normalized-input fuzzing, 5-second requested budget | PASS; 5,341 executions |
| Python AST and shell syntax checks | PASS |
| Real M07 pipeline matrix | All ten PASS; 255.88 seconds |
| Real M08 pipeline matrix | All three PASS; 176.71 seconds |
| Controlled registry requests | 36 actual requests |
| Forbidden controlled endpoint arrivals | 0 |
| Required guest skips / debug / partial selection | None |
| Trust restored / firewall restored / guest disks absent | All confirmed |

The generic host suite intentionally skips raw guest parsers and optional unrelated
host/runtime tests. Required M08 parser roots/subcases were then executed PASS in
actual guests; host skips were never credited as required acceptance. Historical
M04 V14/V15 SKIPs remain unchanged.

Packet capture recorded 2,374 packets with five kernel capture-buffer drops. Capture
is supporting evidence and does not establish complete packet visibility. The
zero-forbidden-arrivals assertion comes from the independent controlled endpoint
canaries, combined with actual broker/pull checks; it is not inferred from absent
packets in the capture. No release claim requires zero capture-buffer drops.

## Reproducibility and artifacts

Exact source/binary/template/database/version hashes are in
[pipeline evidence](pipeline-evidence.json),
[software check manifest](software-checks.json) and
[evidence manifest](evidence-manifest.json). Bounded readable evidence includes
[pipeline log](pipeline.log), [race log](race.log),
[agent fuzz log](agent-fuzz.log), [software summary](software-summary.json) and
[cleanup record](cleanup.json).

Go: 1.27.3; kernel: 6.12.113+deb13-amd64; QEMU: 10.0.13; BuildKit/parser:
v0.34.1; YAML parser: v3.0.5; Trivy: v0.76.1. Exact database byte identity and
UpdatedAt remain pinned in infra/build/tools.lock.json and the evidence manifest.

Private complete evidence:
`/var/lib/orchestrator-builder/m05-lab.4cac6wpp/m08.1793373175703252316/` and
`/tmp/m08-final-checks/`. The manifest identifies the working-tree source hashes;
HEAD alone does not identify the uncommitted implementation. All source hashes
were checked unchanged during the final run and independently rechecked before
recording PASS. Keys, database disks, raw guest images and packet capture remain
private; they were not copied into the repository. No production service was enabled.

The fail-closed reporter was also run against the earlier invalidated complete
run: it returned PENDING for changed source and the missing new nested-context
regression. That run was not promoted despite its earlier matrix passing. Failed
and invalidated development evidence remains separate from this accepted run.

## Scope and downstream gates

This acceptance covers the documented conservative grammar on the tested host:
maximum five services and one local build, pinned images, offline RUN, one private
app network, numeric non-root users and restricted-v1 policy. Unsupported syntax
and missing trusted adapters fail closed. Normalization/admission are not approval.

M09 must implement runtime signatures/replay authorization, capability probing,
actual rootless engine constraints/inspection and private image delivery. M10 owns
volume/secret materialization and quotas; M12 owns scheduling, approval and full
reconciliation. Runtime deployment and end-to-end PH1 release remain pending.
