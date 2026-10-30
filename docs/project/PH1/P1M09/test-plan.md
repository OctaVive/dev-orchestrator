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
