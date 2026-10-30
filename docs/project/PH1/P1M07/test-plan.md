# P1-M07 post-implementation test plan

Status: **Executed — all 146 required ledger cases PASS**, 2026-10-30. See the [acceptance report](testing/acceptance-report.md) and [case ledger](testing/acceptance-results.json).

Created after the build, upload, OCI validation, scanner, storage and recovery
implementation. Failures found while executing this plan require fixes and a
new run of the affected checks. See [implementation plan](implementation-plan.md).

## Acceptance rules

The required gate is **digest matches, budgets kill guest, hostile archives
quarantined**. Run the entire matrix below. A missing case, FAIL, SKIP, truncated
evidence or unresolved cleanup is not acceptance. Software tests that deliberately
skip privileged entry points do not substitute for their actual isolated KVM
runs. Historical M04 V14/V15 qualifications remain outside this milestone; do
not relabel them PASS.

Use a disposable KVM host with verified M04/M05 prerequisites, pinned tools,
read-only database image and fresh builder/scanner templates. Run VMs
sequentially on this host. Never parse hostile OCI or scanner inputs on management.
The guest test binary runs the artifact corpus, real Trivy fixtures and bounded
OCI fuzzing inside an externally budgeted VM. The public upload listener never
serves the private control interface.

## Software cases

Each named root test and **every subcase it executes** is required to PASS.
`infra/build/report.py` records the individual results in the acceptance ledger.

| ID | Test | Required behavior |
|---|---|---|
| S01 | `contracts.TestBuildContractStrictness` | Framed round trip; unknown, duplicate, case-aliased, trailing and oversized JSON denied; undeclared build settings, malformed SHA/context/path, expired job, stale/future DB, excessive limits, changed policy and invalid exceptions denied. |
| S02 | `contracts.TestBuildResultBoundIdentity` | Accept complete matching evidence; deny stale identity, missing image digest and raw diagnostic text in digest fields. |
| S03 | `contracts.TestBuildAuthorizationStrict` | Only the predeclared settings and exact clone/job binding authorize a build; unknown nested fields and invalid source identity fail. |
| S04 | `artifacts.TestUploadQuarantine` | Wrong token/replay/revoked read denied; exact opaque bytes preserved; service restart invalidates grants and retains capacity accounting. |
| S05 | `artifacts.TestUploadLimitsAndFencing` | Oversize, cancellation, revocation, expiry, capacity exhaustion and object tampering fail closed. |
| S06 | `artifacts.TestArtifactServiceControlAndUpload` | Private Unix control plus dedicated TLS upload succeeds; promotion retries preserve exact bytes; guest-facing listener cannot issue grants, obtain receipts or promote objects. |
| S07 | `artifacts.TestQuarantineRetentionAndReservation`, `TestArtifactHostReserve` | Completed bytes remain charged during retention; expired quarantine is removed and its exact charge released; pending reservations cannot consume the management free-space reserve. |
| S08 | `builder.TestDockerfileFixturePolicy` | Supported fixture accepted; remote frontend/ADD, secret mount, host network, external COPY, unpinned base, multiple FROM, heredoc, continuation and oversized input denied. |
| S09 | `storage.TestBuildDurableAdmission` | Durable handoff, idempotent start/export/result, reopen, audit/outbox and immutable digest; admission leaves deployment SCANNING. |
| S10 | `storage.TestBuildTransactionFences` | Wrong source/context, rollback at start/admission, cancellation, stale generation, archive mismatch, policy change and scan denial cannot admit an artifact. |
| S11 | `storage.TestBuildExportRecoveryAndOutbox` | Exact receipt survives reopen; conflicting size denied; queue acknowledgment works. |
| S12 | `storage.TestBuildFailureAfterDeadline` | Timeout is durable after expiry; late admission remains denied. |
| S13 | `storage.TestCloneSchemaUpgradeRequiresVerifiedBackup` | Existing schema refuses automatic upgrade; verified snapshot precedes migration 003; data retained and snapshot not overwritten. |
| S14 | `buildjob.TestWorkflowAdmissionAndFailure` | Success, build/upload/scan failure, timeout, stale result, wrong digest, denial and cleanup failure; builder is cleaned before scanning. Resume after export/promotion crash revalidates; upload-service restart fails closed. |
| S15 | `provisioner.TestBuildSerialFrameFencing`, `TestBuildBoottimeTimerRearm` | Valid result accepted only after clone success; forged, unknown, credential-bearing and out-of-order frames denied. |
| S16 | Repository software suite | Fresh `go test -count=1 -json ./...` passes; compile all entry points; preserve earlier milestone software behavior. |
| S17 | Static/concurrency checks | `go vet ./...` and targeted race tests of artifacts, buildjob, storage and provisioner pass. |
| S18 | Contract fuzzing | Bounded `FuzzBuildJob` run completes without panic/crash. |
| S19 | Script validation | Python compilation and shell syntax checks pass for the new/changed harness and recipes. |

## Guest OCI cases

Every suffix below is an individual case of `TestGuestOCIValidation`.

| Group | Cases | Expected |
|---|---|---|
| G01 — supported content | `plain`, `gzip`, `internal-symlink`, `internal-hardlink`, `safe-whiteout` | Verified manifest and exact upload digest; supported links/whiteouts preserved semantically. |
| G02 — outer archive | `traversal`, `absolute`, `duplicate`, `symlink`, `device`, `fifo`, `truncated`, `trailing`, `pax` | Denied before scanner admission; no extraction outside private guest scratch. |
| G03 — OCI identity/graph | `bad-digest`, `extra-blob`, `platform`, `root-user`, `diff-id`, `external-url`, `blob-size`, `media-type`, `unreferenced-valid`, `case-alias`, `zero-user`, `uid-overflow` | Reject digest/size/platform/config/graph ambiguity, unsupported descriptors and root-user aliases. |
| G04 — layer semantics | `layer-traversal`, `layer-cycle`, `layer-ancestor`, `whiteout-link`, `suid`, `gzip-truncated`, `gzip-concatenated` | Reject unsafe paths/link relationships, unsupported whiteout combinations, privileged mode and malformed compressed streams. |
| G05 — expansion bounds | `upload-limit`, `expanded-limit`, `entries`, `ratio` | Streaming limits deny the artifact; no admitted partial object. |
| G06 — JSON | `json-duplicate` | Duplicate keys denied rather than interpreted inconsistently. |

## Guest scan cases

Every suffix below is an individual case of `TestGuestScanPolicy`.

| Group | Cases | Expected |
|---|---|---|
| G07 — baseline | `clean`, `high-unfixed`, `critical` | Clean passes; HIGH/CRITICAL block, including unfixed findings. |
| G08 — exceptions | `exception`, `wrong-digest`, `expired` | Only an exact image/package/finding match with a live operator exception passes. |
| G09 — incomplete evidence | `unknown`, `missing-coverage`, `eol`, `stale-db`, `malformed` | Fail closed. |
| G10 — actual tool | `TestGuestRealTrivy/clean`, `TestGuestRealTrivy/vulnerable` | Pinned Trivy/DB scans actual OCI layouts; clean image admitted; vulnerable fixture must produce actual HIGH/CRITICAL counts and policy denial. |
| G11 — parser fuzz | `FuzzGuestOCI` | Five seconds inside the guest, positive execution count, no crash, timeout or skipped instrumentation. |

## Real KVM cases

| ID | Case | Required external/transactional evidence |
|---|---|---|
| K01 | `TestRealM07Ingest/clean` | Fresh independent ingest VM, read-only artifact/database devices, full guest corpus/fuzz PASS, validated layout frozen before scanner UID runs, exact digest/report/SBOM evidence admitted. |
| K02 | `TestRealM07Ingest/vulnerable` | Actual scanner policy denial; no deployable artifact; all guest checks still PASS. |
| K03 | `TestRealM07Ingest/malformed` | Archive quarantined; scanner phase bypassed through a fixed denial response; all guest checks still PASS. |
| K04 | `TestRealM07Pipeline/success` | Actual Git clone and immutable SHA, durable authorization, rootless sandboxed RUN, digest-pinned registry pull through M05, metadata request unreachable, separate upload service, independent ingest/scanner, immutable promotion and SCANNING result. |
| K05 | `TestRealM07Pipeline/build-timeout` | Build-stage budget terminates/fences the guest; failure durable; no admission. |
| K06 | `TestRealM07Pipeline/cancelled` | Cancellation during build revokes grant and destroys owned resources; durable cancellation, no late admission. |
| K07 | `TestRealM07Pipeline/controller-loss` | No build driver deadline is running after authorization. Independent host CLOCK_BOOTTIME budget stops a CPU-consuming guest; management SQLite remains responsive. |
| K08 | `TestRealM07Pipeline/scanner-timeout` | Separate scanner VM has its own external expiry and bounded cleanup; partial scan cannot admit. |
| K09 | `TestRealM07Pipeline/log-flood` | Actual build output flood fails under output/time limits and destroys VM; no unbounded host log. Debug capture wrapper must be disabled. |
| K10 | `TestRealM07Pipeline/disk-exhaustion` | Controlled oversized build write fails within guest/storage envelope; fixed 10 GiB host-owned raw disk and host quotas verified; no admission. |
| K11 | `TestRealM07Pipeline/memory-exhaustion` | Actual large guest allocation fails under bounded VM memory/time; management remains available and resources cleaned. |
| K12 | `TestRealM07Pipeline/pid-exhaustion` | Actual guest process flood fails under guest PID/output/time controls; external host quotas remain active. Guest PIDs are not claimed as a host boundary against guest-root compromise. |
| K13 | `TestRealM07Pipeline/remote-source` | Pinned base carries an ONBUILD remote ADD. BuildKit source policy denies it even though the repository Dockerfile contains no ADD; controlled remote-target canary receives zero requests. |
| K14 | Every pipeline case | Check actual systemd CPU/memory/tasks and raw disk limits; preserve an unrelated foreign-file canary; confirm owned guest disks absent after cleanup. |
| K15 | Entire lab | Source/tool/template/database identities, registry requests, bounded packet capture with zero drops, zero forbidden arrivals, no required SKIPs, unchanged base firewall and restored temporary trust/aliases. |

## Execution and evidence

1. Run software/static/race/fuzz checks with `umask 077`; retain commands, exit
   codes and Go JSON output.
2. Build the pinned database and ingest template. Execute `TestRealM07Ingest`
   against the isolated scanner configuration; retain complete bounded guest logs
   and exact template/database identities.
3. Run `infra/build/lab.py` without `--debug`; it executes every pipeline case
   sequentially with fresh job IDs and a separate artifact-service process.
4. Run `infra/build/report.py` against the software JSON, ingest log and pipeline
   evidence. Inspect its complete ledger and add the static/race/fuzz/script
   check exit evidence. No missing case can be silently dropped.
5. Write an acceptance report with actual results and remaining limitations.
   Update milestone/project status only after every required case is PASS.
