# P1-M09 implementation evidence — incomplete increment

Status: **In progress; NOT PASSED**. [Acceptance report](testing/acceptance-report.md)
and [test plan](test-plan.md) distinguish passing software from unfinished runtime
acceptance. [Source hashes](testing/evidence-manifest.json) identify this working
tree increment; HEAD alone does not identify the uncommitted implementation.

## Delivered code

- `internal/runtimeagent`: strict v3 operation envelope, domain-separated Ed25519
  signatures and inventory signing, independent policy/approval/lease checks,
  durable SQLite nonce/request/generation/ownership state, exclusive process lock,
  bounded status/logs and conservative uncertain-intent handling. Invalid inputs
  do not enter the fake engine in software tests; real-engine denials remain pending.
- `internal/runtimeengine`: bounded Unix-socket Engine API 1.47 adapter, fixed
  resource/security options, complete typed setting comparisons, private candidate
  creation/start/inspection, owned stop/remove, bounded Docker log-frame decoding
  and immutable archive spool/reverification before import. Missing enforcement
  refuses readiness. Actual engine compatibility and cleanup recovery remain pending.
- `internal/runtimerpc`: outbound mTLS polling/artifact fetch with chain/name/URI/
  SPKI checks, no proxy/redirect, certificate validity/revocation on reused
  responses, strict bounded command bodies and complete artifact digest checking.
- `internal/artifacts/runtime.go`: separate runtime download handler requiring
  current authorization for certificate fingerprint, worker/incarnation, app/
  deployment, generation, admission, image and policy/spec binding. No listing,
  arbitrary path, symlink following or upload-grant reuse. Concrete current-state
  authorization and listener wiring remain to be implemented.
- `api/runtime-v3.schema.json` and the [execution contract](../../specifications/runtime-execution.md):
  explicit new execution protocol; legacy envelopes remain non-executing.
- `internal/runtimeprofile` / `cmd/runtime-runc`: experimental fixed OCI MAC
  supplement requiring private user namespaces and non-host-root mappings. It is
  not selected by the engine adapter and has not passed the complete VM fixture.
- `infra/runtime`: credential-free feasibility probe/profile, development download
  pins, reporter and reporter unit test. This is not a finished acceptance harness
  or a production bootstrap/template builder.

## Scope limits

No automatic approval, scheduler, public route activation, volume/secret
materialization, generic shell/exec/engine forwarding API or production deployment
is introduced. The core can be exercised through its Go interfaces; it is not yet
a deployable agent service. Required measured helpers are absent, so the normal
Engine readiness path refuses deployment. The milestone stays incomplete until
its entire required runtime matrix passes.

## App-scoped backend recovery increment (2026-10-30)

Implemented the durable allocation/binding and dispatch portion of recovery step
1. `runtimeagent` ledger schema 2 migrates schema 1 without clearing execution
state. Operator capacity, exclusive socket/data-root reservations and app slot,
daemon/workload memory and duplicated image/workload disk charges survive process
restart. Reservation commits before provisioning; measured binding follows daemon
startup. Unbound charges survive a crash and cannot route commands. No automatic
rebind, daemon deletion or capacity release is available.

`runtimeengine.Factory` selects existing bound backends solely by worker,
incarnation and app. It constructs a separate guarded Unix client per operation;
all HTTP paths, including image imports and reused connections, check backend
identity before requests and after response headers. Unknown apps, mismatched
workers, changed daemon observations and foreign app capability reports refuse.
The factory does not implement daemon provisioning or start an engine itself.

The concrete Linux **backend identity observer** checks private path ownership,
fixed daemon socket/data-root arguments, socket peer PID/UID, process start ticks,
boot identity, actual namespace and actual UID/GID maps. It rejects initial user
namespace reuse, host-root/invalid/overlapping mappings and unmapped runtime UID
1000. This validates inherited rootless namespaces without relaxing the separate
experimental OCI hardener. App namespace and daemon uniqueness are ledger
constraints. Full workload enforcement remains a separate unimplemented adapter.

Capability inventory version 2 binds app and full backend hash, with a new signing
domain. Agent probes receive the authenticated app command. Controller verification
can require the independently enrolled app/hash through `VerifyFor`; old/unbound
reports cannot authorize readiness.

The [post-implementation plan](test-plan.md#post-implementation-plan-app-scoped-backend-recovery-increment)
and [increment checks](testing/backend-factory/checks.json) record regression
commands and results. Full tests pass (23 packages), all **159 named component
cases/subcases** across the five runtime/artifact packages pass, the same five
packages pass race checks, vet passes, bounded normalized-command fuzzing passes,
and reporter unit tests pass. These component results do not pass R01–R10.

The private NIC-less VM diagnostic runs the actual Go observer as UID/GID 1000
against two actual Docker 29.5.0 app daemons. See the
[observation record](testing/backend-factory/observation.json) for final-source
run status, hashes and serial evidence. It checks identities, durable reopen and
altered bindings only. It observes already-started daemons, not the production
reserve/provision/bind sequence. Superseded-source VM runs and failed development
regressions are retained and are not final-source acceptance evidence.

Still required: bounded daemon provisioning and restart/reconciliation; physically
enforced app/candidate/storage/cgroup totals; actual workload MAC/seccomp/cgroups;
network default deny and private relay; current approval/admission/lease adapters;
agent service/mTLS integration; drift/quarantine/crash recovery; and every real
R01–R10 constituent case. The existing applied-MAC check still fails closed on an
empty Docker AppArmor inspect field. No complete runtime profile is ready.

## Completion implementation in progress — 2026-10-30

The C01–C08 plan in implementation-plan.md is the current completion sequence.
The previous backend-only evidence remains historical. This increment adds:

- Fixed root-owned per-app enrollment and a boot/process/map-bound OCI hardener.
  A missing userns entry is accepted only after actual inherited app namespace
  verification. Independent kernel inspection requires enforced MAC/seccomp,
  zero capabilities, no-new-privileges, nonroot mapped IDs, private namespaces,
  cgroup limits, read-only root and bounded tmpfs. Engine-managed etc files are
  made read-only.
- A root oneshot provisioner for finite operator app slots. It reserves ledger
  capacity before disk/daemon effects, physically reserves hard-sized separate
  guest filesystems, installs fixed parent cgroups and no-uplink rootless units,
  binds actual daemon identities and publishes immutable enrollments. Failures
  retain charges; changed daemons are not silently rebound. A separate root-owned
  agent-ledger anchor prevents missing state from becoming a fresh enrollment.
- A bounded root measurement service and fixed capability-dropping network helper.
  Requests select exact enrolled app/container ownership; they cannot select PID,
  executable, host path or engine API. The service independently resolves running
  processes and app-parent cgroups. Health enters only a verified private network
  namespace. Relays use a separate UID, Unix sockets, exact tracked child ownership
  and finite lifetimes. Stop removes only the tracked socket inode/process.
- Concrete measured enforcement, immutable platform canary, aggregate candidate
  capacity, strict live inspection, unknown-container/network refusal and cleanup.
  Platform canaries are separate from user M07 admissions.
- Durable current management approval/admission/scan-policy/worker-lease/certificate
  adapters and mTLS handlers. Approvals bind source/context/plan/spec/policy and
  current deployment/app generation. Explicit trusted issuers remain required;
  there is no automatic approval endpoint. M10 volume/secret references deny.
- Agent/controller executables, outbound mTLS transport replacement, signed
  app/backend-bound inventory, durable result outbox and command queue, continuing
  authorization, reconciliation/quarantine and finite durable restart allowances.
  Service unit templates are under infra/runtime/services.

Executed development observations: host-6 completed with rc=0 in a fresh no-NIC
KVM guest. The actual provisioner ran twice idempotently; both real app engines
loaded the trusted pinned canary. Both independent backend/kernel measurements,
private health, relay fetch and relay removal succeeded. Distinct app namespaces,
MAC enforcement, seccomp, per-process and parent cgroups, hard disk reservations
and no-uplink networks were observed. This proves that narrow diagnostic only.
The newer containerd-image-store path and signed measured-canary probe remain
under development. Classic Docker rejects plain OCI archives produced by M07;
a successful trusted dual-index canary import does not resolve user-image delivery.

Component validation: full Go tests and vet passed with private umask and bounded
scratch; targeted race checks passed. New durable budget tests exercise concurrent
candidate accounting, reopen, exhausted restart budgets and stop fencing. These
are component tests, not real crash/revocation acceptance.

Still required: compatible exact M07 image import/identity, complete measured
canary success, actual separate agent/controller mTLS lifecycle, real restart and
crash/revocation/drift/ownership cases, hostile resource/network cases with positive
controls, management/API/UI separation observations, and a complete constituent
R01–R10 driver followed by final source freeze/report. No required runtime gate
is promoted to PASS by this implementation progress.
