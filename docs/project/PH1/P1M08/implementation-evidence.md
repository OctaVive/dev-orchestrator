# P1-M08 implementation evidence

Implementation and isolated-KVM acceptance **PASS**. All **214 required ledger cases PASS**; see the [acceptance report](testing/acceptance-report.md) and [per-case outcomes](testing/acceptance-results.json).

## Delivered

- Strict guest-only YAML AST and upstream Dockerfile parsing with pinned
  go.yaml.in/yaml/v3 v3.0.5 and BuildKit v0.34.1. A fixed parser child runs with
  5-second deadline, 128 MiB memory/no swap, one CPU, 32 PIDs and capped output.
- Explicit supported subset, immutable restricted-v1 controls, finite resource/
  lifecycle bounds, no implicit environment/files or unknown-option passthrough.
  Compose context paths resolve relative to the selected configuration directory.
- Version 2 clone/build configuration identity and version 2 runtime/agent spec.
  JSON decoders reject unknown/case-aliased/duplicate fields, malformed numeric
  encodings and oversize/trailing input. Legacy v1 remains shape-only/fixture-only.
- Atomic private clone-plan persistence, independently validated canonical plan
  hash and selected Dockerfile before build, stale/cancelled/replayed handoff
  fencing, and guest reanalysis immediately before rootless offline build.
- Isolated digest-verified image metadata in immutable artifact admission;
  controller finalization checks exact admissions, local-build source identities,
  numeric non-root users, managed mounts and trusted runtime/secret references.
  Runtime input never enters the guest build job.
- Independent agent-side normalized policy gate with its own trusted resolver;
  no raw Compose/Dockerfile, host paths, arbitrary Docker options or bypass flag.
  Signature/replay authorization and actual engine operations remain M09.
- Audit/event/outbox metadata strips repository/image env and argv values and
  retains identities/hashes. Private attempt records preserve evidence for M12
  approval. No automatic approval or deployment is added.
- Embedded accepted/hostile fixtures, isolated parser tests and fuzzers, normalized
  policy/protocol/storage tests, and a fail-closed acceptance report generator.

## Delivery details relative to the plan

Normalization is attached to terminal clone success after export and durable source
resolution, rather than introducing a second generic control channel. The accepted
source/context and normalized plan become durable together; build still requires
that durable success. Existing framed M06/M07 prefixes are retained with explicit
v2 body validation and a larger bounded result cap.

The encoded plan/spec/envelope cap is 64 KiB, tighter than the proposed 256 KiB.
The combined clone result cap is 69,632 bytes. CPU/memory/PID/storage/log aggregate
budgets are fixed in policy; app tmpfs maximum is 1280 MiB so five bounded services
can fit without reducing per-service defaults. Compose resource requests use the
standard deploy.resources.limits subset and health durations use whole-second
strings. Exact accepted syntax and defaults are in the
[shared contract](../../specifications/configuration-policy.md).

At most one local build is supported. External service digests require prior
independent admission; the lab first builds/scans one fixture and uses its exact
admitted digest as the second service's external image. Image-only plans can be
finalized through trusted resolvers but full orchestration is M12. Configured local
build paths remain predeclared in the sealed M07-compatible job; repository-selected
paths must match before authorization.

Existing JSON attempt records hold the new versioned evidence, so this milestone
requires no new SQLite migration or automatic upgrade. The runtime spec is returned
by finalization; M12 owns durable approval records binding its exact hash.

## Evidence and limits

Follow the [post-implementation test plan](test-plan.md) and
[lab runbook](../../../../infra/config/README.md). Raw parser/fuzzer tests are never
credited from host skips. The final ledger must include all required software
subcases, actual guest corpus/fuzzing, the complete M07 regression matrix and all
three M08 scenarios, source/template identities, packet evidence and cleanup.

Development failures were preserved separately: startup-window contention from
synchronous lab corpus execution, Dockerfile opcode spelling, and later grammar/
source-binding hardening. Corrections did not weaken TLS, rootless sandboxing,
external budgets, source policy or the startup limit. Source changes during a run
invalidate that run's acceptance and require a new frozen-source full execution.

M08 does not prove source provenance from a compromised builder or prove an image
benign. It does not create runtime containers, verify runtime signatures, schedule
jobs, materialize storage/secrets or activate routes. Existing M04 V14/V15 SKIPs
remain unchanged; downstream M09/M10/M12/M14 gates remain required.
