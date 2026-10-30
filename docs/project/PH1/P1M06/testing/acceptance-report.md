# P1-M06 acceptance report

Decision: **PASS — all 83 required cases passed; no M06 acceptance SKIPs**. Executed on **2026-10-30** in the existing disposable Debian KVM lab. Implementation preceded creation of the [test plan](../test-plan.md). All 19 software/packaging groups, 51 actual Git cases and 13 lifecycle/evidence groups passed on the final host-deadline implementation. U17 also passed final link, whitespace and diff validation.

## Environment and immutable evidence

- Go 1.27.3; Git 2.47.3; kernel `6.12.113+deb13-amd64`; QEMU 10.0.13 (Debian).
- Actual KVM with broker-only guest networking; no local/container/emulator fallback.
- Template: `sha256:b20c58b9925e2716040b12bf1584237df6595ce30fa991d64021d994b1efec5f`.
- The final harness verified source content unchanged from binary build through completed tests. Source/policy/binary/image hashes are retained in private evidence.

| Evidence | Private directory |
|---|---|
| Final M06 corpus/lifecycle/storage integration | `/var/lib/orchestrator-builder/m05-lab.4cac6wpp/m06.1793358439686004579` |
| Final software/race/vet/fuzz/build checks | `/var/lib/orchestrator-builder/m05-lab.4cac6wpp/m06-software.1793358514384227456` |
| M05 controlled network regression | `/var/lib/orchestrator-builder/m05-lab.4cac6wpp/controlled.1793357364025456883` |

Files include `run.log`, `evidence.json`, `cleanup.json`, expected SHAs, per-case frames/captures, capture summaries and `final-inventory.json`. Private signing keys and ownership journals are not copied into this repository. The [machine-readable case ledger](acceptance-results.json) records each required case.

## Software cases

The final `go test -race -count=1 -json ./...` run recorded **320 test/subtest PASS results**. All 17 required named software checks were present and passed, including their nested cases. The ordinary software invocation skipped 31 opt-in infrastructure tests; required M06/M05 real-host checks were executed separately below with no skips. Other historical infrastructure skips are not converted to passes.

| Case | Result |
|---|---|
| U01 — `contracts.TestCloneContractAndImmutableInput` | PASS |
| U02 — `contracts.TestCloneResultBinding` | PASS |
| U03 — `cloner.TestRefResolutionRejectsAmbiguityAndMovementInputs` | PASS |
| U04 — `cloner.TestObjectAndTreeBudgets` | PASS |
| U05 — `cloner.TestSymlinkGraph` | PASS |
| U06 — `cloner.TestOutputCapCancels` | PASS |
| U07 — `cloner.TestRunnerRefusesHost` | PASS |
| U08 — `provisioner.TestCloneDeviceSealsFramingAndBounds` | PASS |
| U09 — `provisioner.TestLaunchDiagnosticIsBoundedAndDrains` | PASS |
| U10 — `storage.TestCloneDurableResolutionHandoffAndReplay` | PASS |
| U11 — `storage.TestCloneTransactionRollbackAndLateResults` | PASS |
| U12 — `storage.TestCloneSchemaUpgradeRequiresVerifiedBackup` | PASS |
| U13 — `clonejob.TestDriverFencesHandoffAndConfirmsCleanup` | PASS |
| U14 — `go test -race ./...` | PASS |
| U15 — `go vet ./...` and builds | PASS |
| U16 — `contracts.FuzzCloneInput`, `cloner.FuzzTree` | PASS |
| U17 — Shell/Python syntax, Markdown links and `git diff --check` | PASS |
| U18 — `cloner.TestExportCancellationBeforeBlob` | PASS |
| U19 — `egress.TestInspectedUpstreamAndPinnedAddress` and DNS-denial tests | PASS |

The two bounded fuzz runs passed: clone-job decoder **646 executions**, tree parser **40,910 executions**, each configured for 2 s / 2 workers. Vet, all CLI/package builds, shell syntax and Python syntax passed.

## Actual KVM Git cases

Each row is an installed `TestRealCloneCorpus/<case>` execution. Denial/limit/timeout outcomes are PASS when the contract requires rejection. All guests verified absent helper/filter/hook execution sentinels. Success cases also verified fixture content, executable bits/safe link behavior and absence of `.git`; resolved SHAs were checked against independently constructed expected object IDs.

| Case | Guest outcome | Result |
|---|---|
| G01 — `good` | `success` | PASS |
| G02 — `executable` | `success` | PASS |
| G03 — `symlink` | `success` | PASS |
| G04 — `moving` | `denied` | PASS |
| G05 — `mismatch` | `denied` | PASS |
| G06 — `submodule` | `denied` | PASS |
| G07 — `modules` | `denied` | PASS |
| G08 — `attributes` | `denied` | PASS |
| G09 — `lfs` | `denied` | PASS |
| G10 — `escape` | `denied` | PASS |
| G11 — `cycle` | `denied` | PASS |
| G12 — `collision` | `denied` | PASS |
| G13 — `metadata-path` | `denied` | PASS |
| G14 — `malformed` | `denied` | PASS |
| G15 — `sha256` | `denied` | PASS |
| G16 — `redirect` | `denied` | PASS |
| G17 — `redirect-same` | `denied` | PASS |
| G18 — `timeout` | `timeout` | PASS |
| G19 — `object-limit` | `limit` | PASS |
| G20 — `context-limit` | `limit` | PASS |
| G21 — `entry-limit` | `limit` | PASS |
| G22 — `ref-limit` | `limit` | PASS |
| G23 — `transfer-limit` | `limit` | PASS |
| G24 — `adv-limit` | `limit` | PASS |
| G25 — `corrupt` | `denied` | PASS |
| G26 — `rebind` | `denied` | PASS |
| G27 — `private` | `denied` | PASS |
| G28 — `metadata` | `denied` | PASS |
| G29 — `infra` | `denied` | PASS |
| G30 — `mixed` | `denied` | PASS |
| G31 — `mapped` | `denied` | PASS |
| G32 — `v6` | `success` | PASS |
| G33 — `badcert` | `denied` | PASS |
| G34 — `dnsfail` | `denied` | PASS |
| G35 — `nested` | `success` | PASS |
| G36 — `context-escape` | `denied` | PASS |
| G37 — `config-symlink` | `denied` | PASS |
| G38 — `deep-tree` | `limit` | PASS |
| G39 — `long-path` | `limit` | PASS |
| G40 — `object-count` | `limit` | PASS |
| G41 — `expanded-limit` | `limit` | PASS |
| G42 — `huge-object` | `limit` | PASS |
| G43 — `huge-ref-list` | `limit` | PASS |
| G44 — `log-flood` | `limit` | PASS |
| G45 — `redirect-301` | `denied` | PASS |
| G46 — `redirect-303` | `denied` | PASS |
| G47 — `redirect-307` | `denied` | PASS |
| G48 — `redirect-308` | `denied` | PASS |
| G49 — `directory-link` | `success` | PASS |
| G50 — `directory-cycle` | `denied` | PASS |
| G51 — `context-return` | `denied` | PASS |

The moving-branch case denied the changed advertisement while retaining the original resolved SHA. The mismatch, malformed/corrupt object and SHA-256 cases produced no accepted context. The 65 MiB expanded-object and progress-flood cases were bounded and denied.

## Lifecycle, persistence and external enforcement

| Case | Result |
|---|---|
| H01 — `TestRealCloneLifecycle/cancel-resolve` | PASS |
| H02 — `TestRealCloneLifecycle/cancel-fetch` | PASS |
| H03 — `TestRealCloneLifecycle/expiry-controller-loss` | PASS |
| H04 — `TestRealCloneLifecycle/worker-loss` | PASS |
| H05 — `TestRealCloneLifecycle/cancel-export` | PASS |
| H06 — `TestRealBrokerSetupCrashRecovery` | PASS |
| H07 — `TestRealBrokerForeignNetworkPreserved` | PASS |
| H08 — `TestRealBrokerCreateCancellationRace` | PASS |
| H09 — `TestRealCloneDurableAdapter/good` | PASS |
| H10 — `TestRealCloneDurableAdapter/attributes` | PASS |
| H11 — Guest/host captures and destination observations | PASS |
| H12 — Final isolated-lab cleanup | PASS |
| H13 — M05 controlled KVM regression on final backend | PASS |

All five M06 lifecycle subcases and both durable adapter subcases passed. Active resolve/fetch cancellation used controlled origin arrival observations. Independent expiry passed with both guest and broker supervisors SIGSTOPed. Worker loss, completed-context cancellation, delayed-start fencing, foreign namespace preservation and all seven setup-crash boundaries passed. A software export-cancellation case verified no blob publication when cancellation precedes object reading. The host-policy timeout subcase verified a stalled worker is stopped at its one-second clone budget rather than the five-second caller deadline, with durable `clone.timeout` and confirmed cleanup.

Durable integration recorded `clone.resolved` plus terminal result atomically with SHA/audit/outbox. The failed attributes context retained its resolved SHA and produced no accepted handoff. Software tests covered reopen/replay, conflicting SHA, wrong source/generation/version, cancellation, transaction rollback and explicit verified-backup migration.

The final M06 host capture recorded **9,700 selected frames**, including **118 IPv6 frames**, with **zero capture loss**, **zero escaped guest frames** and **zero protected-destination frames**. All 51 guest captures reported zero loss. DNS/canary evidence recorded **zero unexpected search-suffix queries** and **zero forbidden arrivals**.

The M05 regression passed every required N01–N13 coverage group: actual guest direct IP/DNS/UDP/IPv6/QUIC and authority/TLS bypass probes, captures, active-transfer cancel/expiry, policy failure, crash recovery, foreign ownership and race fencing. Its guest/host captures recorded **1,804 / 1,406 frames**, both with zero loss, **62 ingress drops**, and zero forbidden arrivals.

Final M06 inventory checked **67 owned jobs**: all fenced, no working disk/readiness files, no remaining namespaces, no active owned VM/broker units and no populated owned cgroups. Temporary trust, loopback aliases and fixture processes were removed. Base M04/M05 configurations and host firewall structure were preserved. Pristine images, reviewed binaries, private keys, captures and audit tombstones remain as retained evidence.

## Development failures and scope

Earlier M06 runs are preserved under the same M05 lab root and are not acceptance evidence: startup permission/BusyBox identity-tool failures, an overly strict branch-movement test expectation, the progress-flood streaming cap bypass, and the DNS search-suffix fallback. The preliminary full run failed `dnsfail`; the final run above passed after the broker correction. Additional directory-cycle and context-rebasing fixtures were included in the final frozen-source run. The earlier all-pass run `m06.1793357512372783402` is retained separately; the final run above includes the independent host adapter deadline and its new regression test.

Acceptance covers public credential-free SHA-1 cloning and safe same-guest context handoff on this tested host/template. All `.gitattributes`, submodules/LFS and private credentials remain unsupported. M07 builds/ingestion and M12 complete scheduling/controller integration remain separate; no production service was enabled. M04 V14/V15 remain historical SKIPs, and host patch compliance or complete PH1 release readiness is not asserted.
