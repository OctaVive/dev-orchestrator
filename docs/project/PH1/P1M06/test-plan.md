# P1-M06 test plan — restricted clone runner

Status: **Executed — all 83 required cases PASS**. See the [acceptance report](testing/acceptance-report.md) and [per-case ledger](testing/acceptance-results.json). Created after implementation. Each case below must have recorded PASS evidence before P1-M06 is accepted. FAIL, SKIP and Not run never count as PASS.

## Scope and execution

Run software checks with `umask 077` and Go satisfying `go.mod`. Contract/parser tests may run on the host; hostile Git parsing must run only in disposable KVM guests. The real-host harness is `infra/clone/lab.py` with the explicit M06 lab opt-in documented in [the runbook](../../../../infra/clone/README.md). A `--cases` subset cannot pass acceptance.

Keep source/binary/template/policy hashes, UTC date, versions, commands/exit codes, test logs, SHA/result frames, guest sentinel/context markers, packet capture loss summaries, destination canaries and final cleanup inventory. The harness rejects missing corpus/root tests, failures and infrastructure SKIPs. Preserve failed development runs separately.

## Software cases

| ID | Test/check | Required assertion |
|---|---|---|
| U01 | `contracts.TestCloneContractAndImmutableInput` | Strict bounded job/device decoding; unknown/duplicate/case-variant keys, identity, policy, origin, ref, path and expiry denials |
| U02 | `contracts.TestCloneResultBinding` | Wrong lease/attempt/format/SHA, counters and outcome denied |
| U03 | `cloner.TestRefResolutionRejectsAmbiguityAndMovementInputs` | Only exact branch SHA; duplicate, malformed, excessive and missing refs denied |
| U04 | `cloner.TestObjectAndTreeBudgets` | Object sizes/types/counts and tree metadata/modes/path/collision/entry limits |
| U05 | `cloner.TestSymlinkGraph` | Internal link allowed; external, dangling, direct and directory link cycles, and non-directory traversal denied |
| U06 | `cloner.TestOutputCapCancels` | Streaming `io.Copy` cannot bypass the output cap; process context cancelled |
| U07 | `cloner.TestRunnerRefusesHost` | Invalid input cannot start host Git execution |
| U08 | `provisioner.TestCloneDeviceSealsFramingAndBounds` | Read-only sealed job; ordered identity-bound frames; partial/forged/excess serial data and future manifest rejection |
| U09 | `provisioner.TestLaunchDiagnosticIsBoundedAndDrains` | QEMU and host command diagnostic caps hold through streaming, while draining output |
| U10 | `storage.TestCloneDurableResolutionHandoffAndReplay` | Atomic immutable SHA/events/outbox; replay/reopen; no premature handoff; delivery acknowledgement |
| U11 | `storage.TestCloneTransactionRollbackAndLateResults` | All six subcases PASS: rollback, cancelled, generation, version, wrong-source, context-failure |
| U12 | `storage.TestCloneSchemaUpgradeRequiresVerifiedBackup` | Old schema refuses automatic upgrade; verified snapshot, preserved data/history and no overwrite |
| U13 | `clonejob.TestDriverFencesHandoffAndConfirmsCleanup` | All six subcases PASS: success, denied, cancelled, cleanup-failure, success-without-resolution, policy-timeout |
| U14 | `go test -race ./...` | Entire software regression suite passes; opt-in host cases executed separately below |
| U15 | `go vet ./...` and builds | Static analysis and all CLI/test builds succeed |
| U16 | `contracts.FuzzCloneInput`, `cloner.FuzzTree` | At least 2 s each, 2 workers; no crash/unbounded parser behavior |
| U17 | Shell/Python syntax, Markdown links and `git diff --check` | Packaging/documentation checks succeed |
| U18 | `cloner.TestExportCancellationBeforeBlob` | Cancelled export writes no blob and starts no Git parser on the host |
| U19 | `egress.TestInspectedUpstreamAndPinnedAddress` and DNS-denial tests | Absolute origin DNS names, validated numeric-IP dial and fail-closed resolution |

## Actual KVM Git corpus

Every row runs as `TestRealCloneCorpus/<case>`. All cases also verify that poisoned global/environment helper/filter/hook sentinels remain absent. Success cases verify actual fixture content, executable bits/internal symlink behavior and absence of `.git` inside the guest. Expected full SHAs are constructed independently by the fixture generator and compared when resolved.

| ID | Case | Required outcome |
|---|---|---|
| G01 | `good` | Success, exact SHA and safe context |
| G02 | `executable` | Success, exact SHA and safe context |
| G03 | `symlink` | Success, exact SHA and safe context |
| G04 | `moving` | Structured denial retaining original SHA; no moving-tip substitution |
| G05 | `mismatch` | Denied within policy; no successful context |
| G06 | `submodule` | Denied within policy; no successful context |
| G07 | `modules` | Denied within policy; no successful context |
| G08 | `attributes` | Denied within policy; no successful context |
| G09 | `lfs` | Denied within policy; no successful context |
| G10 | `escape` | Denied within policy; no successful context |
| G11 | `cycle` | Denied within policy; no successful context |
| G12 | `collision` | Denied within policy; no successful context |
| G13 | `metadata-path` | Denied within policy; no successful context |
| G14 | `malformed` | Denied within policy; no successful context |
| G15 | `sha256` | Denied within policy; no successful context |
| G16 | `redirect` | Denied within policy; no successful context |
| G17 | `redirect-same` | Denied within policy; no successful context |
| G18 | `timeout` | Explicit timeout within the configured clone deadline |
| G19 | `object-limit` | Denied within policy; no successful context |
| G20 | `context-limit` | Denied within policy; no successful context |
| G21 | `entry-limit` | Denied within policy; no successful context |
| G22 | `ref-limit` | Denied within policy; no successful context |
| G23 | `transfer-limit` | Denied within policy; no successful context |
| G24 | `adv-limit` | Denied within policy; no successful context |
| G25 | `corrupt` | Denied within policy; no successful context |
| G26 | `rebind` | Denied within policy; no successful context |
| G27 | `private` | Denied within policy; no successful context |
| G28 | `metadata` | Denied within policy; no successful context |
| G29 | `infra` | Denied within policy; no successful context |
| G30 | `mixed` | Denied within policy; no successful context |
| G31 | `mapped` | Denied within policy; no successful context |
| G32 | `v6` | Success, exact SHA and safe context |
| G33 | `badcert` | Denied within policy; no successful context |
| G34 | `dnsfail` | Denied within policy; no successful context |
| G35 | `nested` | Success, exact SHA and safe context |
| G36 | `context-escape` | Denied within policy; no successful context |
| G37 | `config-symlink` | Denied within policy; no successful context |
| G38 | `deep-tree` | Denied within policy; no successful context |
| G39 | `long-path` | Denied within policy; no successful context |
| G40 | `object-count` | Denied within policy; no successful context |
| G41 | `expanded-limit` | Denied within policy; no successful context |
| G42 | `huge-object` | Denied within policy; no successful context |
| G43 | `huge-ref-list` | Denied within policy; no successful context |
| G44 | `log-flood` | Denied within policy; no successful context |
| G45 | `redirect-301` | Denied within policy; no successful context |
| G46 | `redirect-303` | Denied within policy; no successful context |
| G47 | `redirect-307` | Denied within policy; no successful context |
| G48 | `redirect-308` | Denied within policy; no successful context |
| G49 | `directory-link` | Success with a safe internal directory link |
| G50 | `directory-cycle` | Deny cycles formed through directory links |
| G51 | `context-return` | Deny a link that leaves and reenters the original subtree; rebased export must remain contained |

## Lifecycle, storage and external boundary cases

| ID | Actual installed test | Required assertion |
|---|---|---|
| H01 | `TestRealCloneLifecycle/cancel-resolve` | Cleanup during resolution; no late results or delayed restart |
| H02 | `TestRealCloneLifecycle/cancel-fetch` | Resolution reached; cancel active fetch; confirm resources absent |
| H03 | `TestRealCloneLifecycle/expiry-controller-loss` | Pause guest/broker supervisors; PID-1 independently terminates owned guests at expiry |
| H04 | `TestRealCloneLifecycle/worker-loss` | Kill owned guest unit during fetch; cleanup confirmed, no successful late handoff |
| H05 | `TestRealCloneLifecycle/cancel-export` | Cancel completed context before use; destroy guest/context and fence replay |
| H06 | `TestRealBrokerSetupCrashRecovery` | Every existing seven-boundary crash/recovery subcase passes on updated backend |
| H07 | `TestRealBrokerForeignNetworkPreserved` | Foreign namespace/firewall canary preserved; uncertain ownership refuses cleanup |
| H08 | `TestRealBrokerCreateCancellationRace` | Create/cleanup race settles, capacity resources removed and delayed start denied |
| H09 | `TestRealCloneDurableAdapter/good` | Actual guest SHA/results persist through driver; two outbox events; accepted same-guest handoff |
| H10 | `TestRealCloneDurableAdapter/attributes` | Resolution persists, context denied; durable SHA retained; no handoff |
| H11 | Guest/host captures and destination observations | Zero capture loss, escaped guest frames, protected-destination frames, forbidden HTTP arrivals and search-suffix DNS queries |
| H12 | Final isolated-lab cleanup | No working guest disks/active owned VM/broker/namespace; trust/aliases/processes removed; base configs and host firewall preserved |
| H13 | M05 controlled KVM regression on final backend | Existing N01–N13 suite PASS, including direct DNS/IP/UDP/IPv6/QUIC and authority/TLS bypass probes |

## Gate mapping

C01 maps to U01–U03/U08/U16; C02 to U06/U09 and all guest sentinels; C03 to G01/G04/G05 and U10/H09; C04 to submodule/modules/attributes/LFS cases; C05 to tree/context cases and U04/U05; C06 to all budget/flood cases; C07/SEC-07 to network/redirect corpus plus H11/H13; C08 to H01–H08/H12; C09 to U10–U13/H09/H10.

[Implementation plan](implementation-plan.md) and [milestone](README.md) define boundaries. M04 V14/V15 remain historical SKIPs; passing M06 does not relabel them or establish production release readiness.
