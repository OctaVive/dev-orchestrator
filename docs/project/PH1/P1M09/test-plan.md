# P1-M09 verification plan — current implementation and remaining acceptance

Created after the current code increment. **Implementation incomplete; M09 is
not passed.** This plan records executed software cases and defines the remaining
runtime cases. No case is treated as PASS merely because a unit test simulates an
engine or because a container create request succeeds.

## Executed software cases

[Software cases](testing/software-cases.json) lists every executed named test and
subtest in runtimeagent/runtimeengine/runtimeprofile/runtimerpc/artifacts with its
actual outcome. [Complete software log](testing/software.jsonl), [race log](testing/race.jsonl),
[normalized command fuzzing](testing/command-fuzz.log), [vet log](testing/vet.log)
and [reporter test](testing/reporter-test.log) provide the commands' evidence.
Raw repository parser tests retain their existing guest-only gates; their host
SKIPs do not become runtime acceptance and do not replace M08 evidence.

| Case family | Required assertion and executable coverage |
|---|---|
| S01 — signature and strict protocol | `TestSignatureFieldTampering`, `TestStrictDecoder`, `TestSemanticAndAuthorizationDenials`, `TestExecutionSchemaAndSigningGolden`: every signed field, malformed/unknown JSON, root identity, mounts/secrets, stale policy, lease/approval and canonical bytes. Invalid inputs cause no fake-engine calls; this is software-boundary evidence only. |
| S02 — durable command state | `TestSignedLifecycleAndDurableRetry`, `TestConcurrentReplayAndConflicts`, `TestGenerationFencesAndCleanup`, `TestPendingIntentAndUncertainFailure`, `TestLedgerIsolationAndRestartIdentity`: serialize concurrent retries, persist nonce/generation fences across restart, refuse conflicting identities and do not resume uncertain operations. |
| S03 — cancellation/readiness/logs | `TestRevocationDuringCreate`, `TestUnsupportedReadiness`, `TestBoundedSanitizedLogs`, `TestInventorySignatureAndControls`: refuse readiness with missing controls, bind signed reports/challenges/time, compensate failed creates and bound/sanitize workload output. |
| S04 — engine requests and drift | `TestRequiredEngineConfiguration`, `TestInspectDetectsDrift`, `TestMissingEnforcementRefusesWithoutEngineCalls`, `TestUnixClientResponseBoundsAndSanitizedErrors`, `TestLogFrameBounds`: fixed engine options, privilege/namespace/network/resource/ownership drift and bounded real Unix-socket HTTP framing. No claim of real-engine compatibility. |
| S05 — mTLS and artifacts | `TestMTLSPollBoundaries`, `TestRevocationOnReusedTLSConnection`, `TestRejectUnsafeOrigins`, `TestArtifactStreamIntegrityAndBounds`: chain/name/URI/pin/role, redirects, frame size, reused-connection revocation and archive digest/size. |
| S06 — artifact service/import | Runtime artifact authorization/corruption/symlink/revocation tests plus `TestDeliveryVerifiesBeforeImportAndCleansSpool`: trusted exact admission binding, certificate identity, no listing/path surface, complete hash before import and failed-transfer cleanup. |
| S07 — experimental OCI supplement | `TestFixedBundleSupplement`, `TestUnsafeBundlesDeniedBeforeNamespaceJoin`, `TestBundlePathAndSymlinkDenials`: fixed MAC, private namespace/mapping requirements, no privileges/capabilities/hooks or unsafe filesystem inputs. Unit success does not establish that this supplement works on the tested engine. |
| S08 — acceptance reporting | `python3 -m unittest discover -s infra/runtime -p test_report.py`: missing/failed/skipped/duplicated/changed cases refuse PASS. Synthetic reporter fixtures are never acceptance artifacts. |

## Mandatory runtime gates

Every assertion below requires the actual agent, durable ledger, real engine and
isolated runtime VM. Split these into a machine-generated per-case ledger when
the runtime driver is implemented; no hidden optional cases or development flags.
The current top-level ledger conservatively keeps these gates FAIL or NOT_RUN.

| Gate | Required cases before PASS |
|---|---|
| R01 — measured capability | Supported complete profile passes with observed cgroups, UID/GID maps, private namespaces, actual MAC/seccomp, storage/log quotas, network denial and relay connectivity. Each missing control refuses before candidate changes. Tampered/stale/wrong-worker reports and daemon restart refuse readiness. **Current complete-profile feasibility fails.** |
| R02 — SEC-16 | Real-engine zero-mutation snapshots for every field/signature/worker/incarnation/app/expiry/policy/generation/approval/certificate/replay denial, including concurrent duplicates and agent restart. Software tests alone are insufficient. |
| R03 — crash and revocation | Kill agent at every durable-intent/create/start/inspect/result/cleanup boundary; lose engine responses; expire/revoke during operations. One effect per identity, no stale readiness, confirmed owned cleanup or explicit uncertain incident/reservation. |
| R04 — runtime image delivery | Exact M07-admitted source/digest/platform reaches actual runtime through the private mTLS path. Cross-worker/revoked/stale grants, bad digests/platform, redirect, partial/corrupt/oversized archives, unpacked-storage exhaustion and import failures refuse and preserve correct charges. |
| R05 — actual hard profile | Single- and two-service stateless specs create privately with all intended controls before/after start. Inspect/mutate actual engine constraints and verify process/cgroup/namespace state independently. Tampered profiles, unmanaged volumes, supplementary groups, dangerous options or wrong networks never become ready. |
| R06 — network/SEC-03 | IPv4/IPv6 scans from independent host and app/relay identities show no app host ports. Host/management/metadata, egress and cross-app attempts denied. Intra-app and private relay fixture succeed, and removing the fixture removes ingress. |
| R07 — SEC-05 | Actual API/UI identities cannot access Docker/libvirt sockets or runtime credentials. Inventory process/account/VM permissions and mounts. Workloads cannot reach runtime/control sockets. |
| R08 — SEC-08 | CPU/RAM/swap/PID/tmpfs/writable storage/image cache/log/deadline exhaustion stays bounded; management remains responsive. Concurrent app/candidate reservations cannot overcommit. Restart budgets and stop fences survive agent/daemon restart. |
| R09 — lifecycle/ownership | Exact owned stop, grace expiry, force-kill, remove, log and status paths pass. Foreign objects/forged labels/wrong IDs/apps/stale generations are untouched. Drift and cleanup loss block readiness/capacity reuse. |
| R10 — integration/regression | Actual runtime mTLS polling/heartbeat/results, certificate rotation/revocation, backpressure, malformed/flooded commands/logs, secret sentinels, source freeze and final cleanup inventory pass; complete software/vet/race/fuzz regression and M08 handoff remain valid. |

## Execution and acceptance rule

Run software with a private umask, then freeze implementation/templates/policy and
run the full isolated runtime driver. Record command exit status, every named
case, source hashes, kernel/engine/API/template versions and final resource
inventory. Preserve failed development runs. Any FAIL, SKIP, NOT_RUN, missing case,
source change or uncertain cleanup prevents milestone PASS.

Current [acceptance report](testing/acceptance-report.md) explicitly records the
unfinished implementation and failed/incomplete runtime gates. There is no
accepted runtime template and no production deployment path in this increment.

## Post-implementation plan: app-scoped backend recovery increment

Run after the app backend implementation; all cases below are incremental
verification and **do not substitute for R01–R10**. Store commands, exit statuses,
source hashes and named results in `testing/backend-factory/`. Retain development
failures and superseded-source runs. Use `umask 077`,
`GOCACHE=/tmp/tap-go-cache` and `TMPDIR=/var/tmp/tap-m09` (private, short Unix socket
paths, sufficient physical free space). Do not use the nearly full `/tmp` tmpfs
for artifact reservation tests or a TMPDIR whose paths exceed Unix socket limits.

| Case | Required assertion and execution |
|---|---|
| BF01 — durable allocation | `TestBackendReservationDurability`, `TestBackendV1Migration`, `TestUnboundReservationSurvivesCrash`: capacity/path reservation precedes identity binding; restart preserves unbound charges, identity, pending commands and generation/replay state; unknown/unbound apps cannot route. |
| BF02 — collisions/capacity | `TestBackendOwnershipAndCapacityDenials`, `TestBackendConcurrentCapacity`: reject shared sockets/roots/daemons/namespaces, overlapping roots, initial user namespace, invalid maps/overhead and memory/disk exhaustion; concurrent reservations cannot exceed the pinned budget. Failed binding retains its prior reservation. |
| BF03 — routing/drift | `TestFactoryRoutesAndFences`, `TestBackendDaemonArguments`: independent Unix HTTP fixtures receive only their app's probe; wrong worker/app/report and changed observation refuse before engine calls. Running daemon ownership flags match the assigned data root and sole socket. This is component evidence. |
| BF04 — signed app capability | `TestInventoryAppBinding`, `TestInventorySignatureAndControls`: legacy/unbound inventory, cross-app use, changed signed app/backend, wrong trusted enrolled hash/challenge, stale reports and missing controls refuse. |
| BF05 — kernel observation | Build `infra/runtime/experiments/backendprobe`, copy it and `backend-observer-guest.sh` into a trusted never-booted fixture root, generate a fresh raw image without mounting it, boot with KVM, 2 CPUs, 1536 MiB, no NIC, snapshot writes and an external 180-second timeout. The actual Go observer must pass for both real rootless daemon socket peers, distinct kernel namespaces/maps and PID/start/boot identities after dropping to UID/GID 1000. Ledger reopen preserves both bindings; all eight altered start/map/namespace/boot checks deny. Capture serial completion, exit and shutdown. This fixture observes existing daemons; it does not establish production provisioning, workload enforcement or R01 readiness. |
| BF06 — regression | Full `go test -json ./...`, `go vet ./...`, five-package race checks, five-second/two-worker normalized-command fuzzing, reporter unit suite and actual fail-closed milestone report. Every required runtime gate remains independently mandatory. |

After these checks, update implementation evidence and the source/evidence
manifest. The next runtime increment still requires daemon provisioning/recovery,
physical quotas and aggregate candidate capacity, applied MAC/seccomp/cgroups,
default-deny network and private relay, trusted approval/admission/lease adapters,
a real agent service and all constituent R01–R10 cases on final frozen source.

## Completion increment validation plan (current working source)

Run component tests with `umask 077`, a short private TMPDIR on the large lab
filesystem, and the pinned Go executable. Run full Go tests/vet, targeted races
across runtimeagent/runtimeauthority/runtimeengine/runtimehost/runtimeisolation/
runtimemeasure/runtimenet/runtimerpc/storage, and bounded command fuzzing.

Development VM sequence: root provisioner twice; independently verify both app
backend and kernel profiles; test health and relay start/fetch/removal; remove
only the known fixture objects; run separately signed measured-canary probes.
The measuredprobe local authority denies all lifecycle/image grants and is only
a capability diagnostic. It cannot satisfy real mTLS or M07 lifecycle acceptance.
Retain failed logs. Pin every executable, maintained MAC policy and platform
canary. Regenerate a fresh image from the trusted never-booted root tree after
changes; never mount or reuse a booted workload filesystem on management.

Only after these diagnostics succeed, run the actual separate process/mTLS/M07
lifecycle and all constituent R01–R10 cases listed above. No NOT_RUN, SKIP or
component-only substitute is accepted. Freeze final source and regenerate the
manifest after implementation; the prior manifest is historical until refreshed.
