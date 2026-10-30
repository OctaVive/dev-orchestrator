# P1-M09 implementation plan — runtime capability probe and typed agent

Status: **In progress; NOT PASSED**. This document records the intended delivery sequence and gates. See [implementation evidence](implementation-evidence.md), [test plan](test-plan.md) and [incomplete acceptance report](testing/acceptance-report.md) for the actual delivered scope and remaining work.

## Outcome and scope

Run an admitted, explicitly approved normalized application inside a dedicated runtime VM through a narrow rootless agent. Authenticate commands, reject replay durably, verify required runtime capabilities, create candidates privately, inspect actual enforcement, and stop/remove only owned resources. Acceptance: **SEC-05/08/16; real engine constraints verified and no host application ports**. Cover the M09 portion of SEC-03; authenticated public relay routing remains M11.

Authoritative inputs: [milestone contract](README.md), [runtime security policy](../../../architecture/docker-security.md), [agent lifecycle](../../specifications/deployment-agent.md), [configuration policy](../../specifications/configuration-policy.md), [testing strategy](../../specifications/testing-strategy.md), and [M08 acceptance](../P1M08/testing/acceptance-report.md).

M10 owns managed persistent volume quotas/ownership and secret materialization; M11 owns the authenticated gateway and production relay path; M12 owns scheduling, approval decisions and deployment orchestration. M09 defines and consumes narrow trusted interfaces for these concerns. Until M10 exists, reject nonempty volume/secret references before engine mutation. Acceptance uses stateless workloads and a private relay connectivity fixture. Do not add generic exec, Docker API forwarding, raw Compose parsing, automatic approval or public route activation.

## Existing foundation and proposed defaults

- `internal/contracts/configuration.go` and `api/agent-v2.schema.json` define the M08 spec/envelope. `internal/agentpolicy.Decode` checks strict shape, policy, worker, expiry, generation and spec hash, but explicitly does not verify signatures or mutate an engine.
- `internal/policy/profile.go` lists required controls. Booleans describe requirements; they are not evidence that the engine enforces them.
- Existing v2 envelopes have no operation discriminator or target for inspect/stop/remove. Define a new execution envelope version rather than assigning new meanings to M08 v2. Preserve runtime spec v2 unless its semantics actually change. Legacy decoders remain non-executing.
- M07/M08 supply immutable image admissions and metadata, not a runtime download/import path. `internal/artifacts` currently exposes upload/receipt/promotion operations, not authenticated runtime retrieval.
- Provisioner mTLS/lease/ledger patterns are useful precedents, but build VM commands, identities and replay state must not authorize runtime actions. Management deployment storage is not the agent's local durable execution ledger.
- Use rootless Docker in a dedicated Linux runtime VM under a dedicated Unix account. API/UI accounts cannot reach its socket or account data. Prefer a typed Engine API adapter over shelling out to Docker. Select and pin engine, API, SDK, kernel, seccomp/MAC policy and template versions during implementation after checking upstream documentation; this plan does not assert version compatibility.
- Use Ed25519 command signatures with operator-provisioned public keys and explicit key IDs. Keep signing keys in the controller trust boundary; runtime agents receive verification keys only. Use a separate capability-report signing identity.
- Fail closed when any required control is unavailable. Do not fall back to a rootful engine, unconfined profile, unbounded storage or permissive networking.

These defaults follow the existing architecture. No user choice blocks the plan; changing engine, hard-profile controls or milestone boundaries requires updating the shared contract and acceptance cases.

## Delivery sequence

### 1. Freeze execution, identity and ownership contracts

Add a shared runtime-agent specification supplement covering operations, signing bytes, trusted context, finite deadlines, durable state, capability inventory, closed failure codes and recovery. Update Go contracts, JSON schemas, API descriptions and golden fixtures together.

Define a strict versioned operation union: probe, prepare approved image, create candidate, inspect owned candidate, bounded logs, stop/drain and remove owned resources. Each operation has exact fields and bounded output; no arbitrary engine options, filesystem paths, registry URLs, network configuration or executable strings beyond workload argv already validated in the spec. Read operations are authenticated and bounded too.

Bind every effect-bearing field into domain-separated canonical signing bytes: envelope version/operation, command ID, worker identity and incarnation, app/deployment, generation, target identity, nonce, key ID, expiry, policy/spec hash and typed operation payload. Retain the existing spec canonicalization and 64 KiB envelope ceiling unless a documented contract revision is necessary. Signatures exclude only the signature field itself. Define integer, timestamp, default, collection ordering and omission rules with cross-process golden tests; reject ambiguous/unknown JSON before verification.

Separate app deployment generation from the sequencing of individual commands. The current `LastGeneration` check cannot by itself support create, inspect and stop for the same generation. Define per-app generation fencing, per-command identity/replay checks and a worker incarnation fence. Same-generation lifecycle operations require the exact owned target; new creates cannot revive a superseded generation. Cleanup of an older generation must be explicitly authorized without granting permission to create it again.

Define trusted approval lookup/revocation and artifact lookup interfaces. Approval binds app/deployment, source/context, each admission/digest, spec/policy hash, worker assignment and generation. A correctly signed command is insufficient without current approval. M09 supplies a concrete controlled adapter/acceptance issuer for exercising this boundary; M12 later owns product approval decisions. Guest/browser maps and envelope flags are never trusted approvals.

### 2. Implement command authorization and a crash-safe agent ledger

Add an agent-local SQLite ledger, separate from management metadata, with private account ownership, explicit migrations and durable transactions. Record worker incarnation, app generation fences, command/nonce uniqueness, complete request hash, operation intent, owned engine identities, state transitions and bounded outcomes. Retain replay tombstones through the command validity window plus defined clock-skew/recovery margin; generation/incarnation fences survive compaction and restart. Lost or rolled-back ledger state requires re-enrollment/reconciliation, not resetting counters and continuing.

Authorization order: bounded strict decode; trusted worker/key/time checks; signature verification; independent runtime policy and admission/approval checks where applicable; transactional replay/generation reservation and durable intent; engine operation. Reject invalid commands before engine mutation. Do not directly reuse the v2 decoder's global generation precheck as execution authorization.

Define at-most-one command admission and idempotent recovery, not an impossible atomic transaction across SQLite and Docker. An identical completed retry returns the recorded bounded outcome without repeating mutation; a conflicting command ID/hash or reused nonce under another command denies. Expired/revoked retries cannot resume side effects. Concurrent duplicates serialize. Use per-app mutation serialization and generation compare-and-swap so late completion cannot mark an older candidate current.

Recheck approval, worker lease, expiry, capability readiness and generation immediately before side effects and before reporting candidate success. Serialize locally observed revocation with command dispatch; define controller lease/revocation semantics rather than claiming instantaneous distributed atomicity. If approval cannot be checked, refuse new execution. During an in-flight action, cancellation/expiry/revocation triggers bounded compensation and an explicit incomplete/incident result when cleanup is uncertain.

Recovery reconciles reserved/prepared/created/started/verifying/stopping/removed/uncertain intents with engine inventory. Persist intent before calls so a crash after engine success can be recovered by ownership identity. Never claim success merely because an object with a matching name exists.

### 3. Build the runtime VM profile and measured capability probe

Add `infra/runtime/` template/bootstrap, operator configuration, service units and a reproducible isolated acceptance harness. Keep the agent and rootless socket inside the runtime VM. Agent processes receive no management DB credentials or controller signing keys. Fixed host networking/storage helpers, if required, have separate identities and narrow operator-owned interfaces; the agent does not acquire host root or arbitrary firewall/filesystem RPC.

Probe actual cgroup delegation and CPU/memory/swap/PID enforcement, rootless UID/GID mappings, namespace isolation, seccomp and enforced MAC, engine/API compatibility, read-only roots, bounded tmpfs/storage/logs, network default deny, and private relay connectivity. Use disposable owned canaries where inspection alone cannot establish support. Cleanup probe artifacts and fail readiness on uncertain cleanup.

Resolve the rootless storage/quota and network enforcement feasibility first. Ordinary bridge separation or Docker `internal` networking is not proof of denied host/cross-app access, and read-only roots do not bound engine image/cache/log storage. If the chosen stack cannot enforce the complete profile, record unsupported capability and stop admission; revise the implementation design before claiming acceptance.

Emit a bounded signed inventory bound to worker/incarnation, fresh challenge, timestamp/expiry, template/kernel/engine/API versions, policy hashes and measured results. Verification rejects stale, wrong-worker or altered reports. Invalidate readiness after daemon restart, relevant policy/configuration change or lease loss; re-probe before further mutations. A signed report identifies a worker assertion, not remote attestation of an uncompromised VM.

### 4. Deliver approved images without broad registry credentials

Extend the artifact service through a separate authenticated runtime retrieval interface. Authorize exact admission/digest, worker, app/deployment, approval/policy and short expiry; bound bytes, requests, concurrency and retry lifetime. Do not expose host artifact paths or build upload grants. Runtime credentials cannot list arbitrary artifacts, mutate admissions or reach management APIs.

Only the agent downloads from a fixed trusted service. Verify admission/revocation and digest/platform identity; use bounded immutable OCI content through the controlled runtime import path. Reuse admitted metadata, and verify loaded engine image identity/configuration before create. Any additional parsing of hostile image/archive data requires explicit isolation rather than moving M07's unsafe parsing boundary into management.

Reserve VM storage before download/import, account for unpacked layers/cache and concurrent candidates, enforce physical backing-store limits, and remove partial owned transfers. Refuse when capacity or cleanup is uncertain. App containers cannot inherit retrieval credentials or use the agent's artifact network path. Shared digest cache garbage collection requires durable references; never delete images used by another app or foreign engine objects.

### 5. Implement typed create and inspect against actual engine state

Proposed packages: `internal/runtimeagent` for authorization/lifecycle, `internal/runtimeengine` for typed engine adaptation, `internal/runtimerpc` for transport, and `cmd/runtime-agent` for process wiring. Keep policy validation in `internal/agentpolicy`/`internal/policy`; do not import raw repository parsers. Narrow interfaces permit unit testing but acceptance must exercise the real adapter.

Translate validated specs into a fixed engine configuration: numeric non-root UID/GID, no supplementary groups, drop ALL capabilities, no-new-privileges, read-only root, private namespaces, pinned enforced seccomp/MAC, bounded tmpfs and writable locations, CPU/RAM/swap/PIDs, finite restart/health limits, rotated byte-bounded logs, no published ports and no implicit image volumes. Deny missing M10 adapters before creating anything.

Create one platform-owned private app network, admitting only the intended app services and separate relay identity. Enforce default-deny outbound, host/management/metadata, IPv4/IPv6 and cross-app traffic outside workload control. Permit only required intra-app and fixture relay connections. No implicit default bridge, host networking or automatically published exposed ports. Inspect all attached networks and actual bindings.

Persist object identity with worker incarnation, app/deployment, generation, service, spec/policy hash and command ownership. Cross-check ledger, exact engine IDs and inspected settings; labels alone are insufficient authority to mutate/delete. Unexpected or foreign objects cause an incident, never automatic adoption/deletion.

Create containers stopped; inspect critical settings before start, then inspect live state and run bounded health checks in dependency order. Compare complete intended and observed constraints, including effective namespace/user mappings and external network controls. A successful create response is insufficient. Mismatch prevents candidate readiness and triggers owned cleanup. Health probes use the fixed private backend/path and finite budget; workload healthcheck argv runs only in its container. Never publish a route in M09.

### 6. Complete stop, logs, reconciliation and transport

Implement bounded structured status and logs without returning raw engine inspect/configuration, environment values or credentials. Cap line/byte/count/time limits, sanitize malformed UTF-8/control sequences and escape display output. Known secret fixtures must be absent from agent diagnostics/audit; workload stdout is untrusted and cannot be guaranteed secret-free by pattern redaction alone. No generic exec endpoint.

Stop blocks further starts for the fenced target, requests relay drain through a narrow adapter when present, applies a fixed grace period and force-kills remaining owned processes. Without M11, test private fixture disconnection and report route draining unavailable rather than asserting production drain. Remove only exact owned containers/networks; preserve incident records and capacity reservations until cleanup is confirmed. Daemon/agent restart cannot reset restart budgets or revive stopped/stale candidates.

Add mTLS controller polling and bounded heartbeat/results using distinct runtime identities/roles, pinned trust, certificate rotation/revocation checks and explicit deadlines/backpressure. No inbound unauthenticated engine/control listener. On controller loss, refuse new execution and expire pending operations; define existing workload/quarantine behavior with the external network controller and make inability to enforce quarantine visible. Do not invent volume failover or production route revocation before M10/M11.

Reconcile periodically for engine drift, daemon restart, unknown objects, orphan intents and worker lease expiry. Quarantine/stop drifted owned candidates; never delete foreign objects. Export only bounded closed reason codes, identities, hashes and resource summaries.

### 7. Record acceptance evidence and handoff

Add milestone `test-plan.md`, implementation evidence and `testing/acceptance-report.md`, plus fixture manifests and a machine-readable required-case ledger. Update shared contracts, milestone README and project evidence only to the demonstrated level. Keep milestone status Planned until implementation/testing evidence exists.

Record exact code commit, template/kernel/engine/SDK versions, cgroup/MAC/seccomp/network/storage configuration, policy/spec hashes, commands, external observations and final owned-resource inventory. Run hostile workloads only in approved disposable lab runtime VMs; management must remain observable during exhaustion. Missing lab capabilities or required SKIPs leave acceptance incomplete.

## Required verification matrix

| Gate | Required evidence |
|---|---|
| R01 — capability/readiness | Real supported profile ready; individually missing cgroups, mapping, MAC/seccomp, quota, network or relay controls refuse. Stale/tampered/wrong-worker reports and daemon restart invalidate readiness. |
| R02 — SEC-16 authorization | Alter every signed field; wrong key/worker/incarnation/app, stale generation, expired/future-invalid expiry, revoked approval, obsolete policy and legacy envelope cause zero engine mutations. Concurrent nonce/ID conflicts and ledger restart retain rejection. |
| R03 — idempotency/recovery | Same-command retries produce one effect. Crash at each ledger/engine boundary, lost responses, cancellation and controller loss recover or visibly block with reservations retained. Late old-generation completion cannot become ready. |
| R04 — image delivery | Only exact approved digest/platform imports. Wrong/revoked admission, cross-worker grant, redirect/untrusted destination, truncated/corrupt/oversized content, storage exhaustion and partial import deny with bounded cleanup. Credentials absent from app environment/mounts/logs. |
| R05 — actual hard profile | Real single-service and two-service candidates pass before/after-start inspection. Tampered adapter/engine settings, unmanaged volumes, supplementary groups, privilege/socket/namespace/network drift prevent readiness. |
| R06 — network/SEC-03 | External host port scans show no app bindings; IPv4/IPv6 host/management/metadata, outbound and cross-app attempts fail; intended intra-app/private fixture relay traffic succeeds. Removing fixture relay removes that ingress path. Full gateway/auth evidence deferred to M11. |
| R07 — SEC-05 | Actual API/UI identities cannot access Docker/libvirt sockets; process permissions, mounts, credentials and runtime VM separation inventoried. No app can access engine sockets or agent credentials. |
| R08 — SEC-08 | CPU/RAM/swap/PID/tmpfs/writable storage/image storage/log/time bombs stay bounded, management remains responsive and finite restart budgets survive restart. Concurrent app/candidate capacity reservations cannot overcommit. |
| R09 — ownership/lifecycle | Stop/force-kill/remove affect exact owned targets only. Forged labels/IDs, foreign objects, app mismatch, stale creates, network in use and daemon loss cause no foreign deletion. Cleanup uncertainty stays visible and blocks capacity reuse. |
| R10 — protocol/diagnostics/regression | mTLS role/revocation/rotation, malformed/oversized/flooded commands and logs, secret sentinels, deterministic signing vectors, schema compatibility and M08 normalized-policy regressions pass. M10/M11/M12 boundaries remain explicit. |

Software verification: `go test ./...`, `go vet ./...`, targeted race tests for ledger/app concurrency and transport, bounded strict-command fuzzing, golden signing/canonicalization tests, migration/restart tests and fault injection around engine calls. Real Linux VM tests establish enforcement; mocks establish orchestration behavior only.

## Completion and downstream contracts

Deliver the pinned runtime profile and capability inventory, strict signed execution protocol, durable replay/ownership ledger, controlled image delivery, real engine adapter, bounded lifecycle/transport, isolated acceptance harness and passing R01–R10 evidence. Unsupported required controls, uncertain cleanup or missing required cases block completion.

M10 consumes ownership/mount adapter interfaces and extends acceptance with persistent volume/secret materialization. M11 consumes private candidate identities and drain/status interfaces for authenticated route activation. M12 consumes verified capabilities, current approval checks, generation fencing and bounded operation outcomes for scheduling and reconciliation. No M09 candidate readiness result independently approves a deployment or exposes an application.

## Recovery sequence after the incomplete implementation increment

The [kernel observation](testing/isolation-direction.json) narrows the runtime
choice. With the tested shared rootless engine, two fixture apps share a user
namespace and remain unconfined despite a requested AppArmor option. Separate
rootless engines, one per app, plus a minimal fixed MAC supplement produced
separate app user namespaces and enforced MAC in the same disposable VM. This is
a feasibility result for two controls, not a completed capability/acceptance gate.

Use this as the next implementation candidate, preserving the requirement that
apps do not share user namespaces with other apps or the VM's initial namespace:

1. Build a bounded app-scoped backend factory. Bind each private engine/socket,
   data root, namespace identity, daemon incarnation and reservation to a durable
   worker/app assignment. Account for daemon overhead and duplicate image storage.
   Command input cannot select socket paths or engine options. Revocation and
   cleanup may never affect another app's daemon or resources.
2. Replace assumptions about explicit OCI namespace fields with independent
   measurements of actual process namespaces/maps. Missing OCI fields alone do
   not prove missing kernel isolation. An inherited rootless namespace is valid
   only when its trusted app ownership and separation are demonstrated. Integrate
   a fixed, pinned MAC supplement and verify actual enforcement after start.
   Finish the bounded network, disk/log/storage, cgroup and private-relay probes
   here: no backend may report ready while any required control is unimplemented.
3. Connect one stateless admitted image through current approval/lease checks,
   signed command, durable intent, app-scoped engine, observed readiness and
   owned stop/remove. Run this through a real runtime-agent process and mTLS
   polling. Do not use unit fixture maps as production admission adapters.
4. Extend the verified lifecycle with recovery, concurrency, revocation and
   resource/network attack cases. Finally execute every R01–R10 constituent
   case on frozen source/templates and require PASS plus confirmed cleanup.

Do not promote the prototype, weaken required controls or report the narrow
namespace/MAC observation as full M09 acceptance. No user-supplied secrets,
permissions or requirement waiver are needed to investigate this candidate.
