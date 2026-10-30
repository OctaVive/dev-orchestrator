# P1-M08 post-implementation test plan

Written after implementation of the normalizer, protocol v2 handoff, finalizer,
agent policy gate, metadata admission bridge and lab driver. Status: **all required cases executed PASS**; see the [acceptance report](testing/acceptance-report.md) and [machine-readable ledger](testing/acceptance-results.json) for actual outcomes.

## Pass rule

P1-M08 passes only when every required case below and every discovered subcase
under its required test roots executes PASS. FAIL, SKIP, missing evidence, a
partial/development run, debug wrapper, changed source, unexpected network arrival
or uncertain cleanup prevents PASS. Historical optional M04/M09 tests skipped in
the generic software suite are outside this milestone's required inventory; the
required guest tests must additionally execute in KVM and cannot be credited from
host skips. Do not enable guest-test environment flags on management.

Use a frozen source tree and pinned fresh never-booted builder/ingest templates.
Record Go/parser/frontend/scanner/database/template identities and source hashes.
All raw YAML/Dockerfile/OCI parsing, hostile fixtures and parser fuzzing execute in
disposable guests. Host tests use normalized JSON and trusted control metadata.

## Cases and expected results

| ID | Required cases and execution | PASS condition |
|---|---|---|
| C01 | Guest `TestGuestComposeAccepted`, `TestGuestServiceCount`, `TestGuestRepositoryCorpus`; real `TestRealM08Pipeline/m08-dockerfile` and `/m08-compose` | Accepted Dockerfile and two-service subset compile; five services within app budget accepted, sixth/second local build denied. Both real specs pass finalizer and independent agent gate. External service references the first exact scanned admission; local service has a fresh separate admission. |
| C02 | Guest `TestGuestComposeDenials` and all subcases; Compose fuzzer | Duplicate/nested keys, aliases/anchors/merges/tags, multiple documents, unknown fields, key/scalar types, nulls, invalid UTF-8/NUL, interpolation, size/depth/node limits and command/dependency ambiguity denied. Nonzero bounded fuzz executions, no crash or invalid normalized output. |
| C03 | Guest forbidden-field subcases and embedded hostile files; host `TestIndependentAgentPolicy/unknown-*`; actual `/m08-denied` | All forbidden keys, including false/empty values, denied. Controller rejects malformed/unsafe normalized plans; direct agent rejects equivalent unknown options. Real denied fixture must have fetched/exported source and durable denied result, not a startup/infrastructure error. |
| C04 | Guest `TestGuestDockerfile`, `TestGuestRepositoryPaths`, `TestGuestPathRace`, `TestGuestNestedComposeContext`, embedded Dockerfiles and Dockerfile fuzzer; M07 `/remote-source` | Pinned scratch/multi-stage inputs accepted; directives, remote ADD/external COPY, unpinned bases, SSH/network/security/device flags, unsupported instructions and shell entrypoints denied. Traversal/static/racing symlinks never read outside the root; config changes alter plan hash. External inherited remote source remains blocked. |
| C05 | Host `TestNormalizationAndCanonicalIdentity`, `TestPlanSemanticDenials`; accepted guest cases | Golden canonical hash stable across fresh/race test processes and map ordering; argv order preserved. Duplicate names/ports, cycles, missing dependencies, resource overflow/aggregate limits, output budget, invalid mounts, health/restart bounds and reserved env deny. |
| C06 | Host `TestFinalizationAdmissionAndOwnership`, `TestRuntimeInputsRemainOutsideBuild`, `TestBuiltImageSourceBinding`; real image metadata bridge | Missing/wrong digest/platform/policy admission and mismatched local-build SHA/context/deployment, root/named/root-group/overflow users, unmanaged image volumes and wrong-app mounts denied. Trusted runtime environment/secret refs remain outside build plan; conflicting env, duplicate secret targets and unknown service refs denied. Metadata comes from digest-verified isolated OCI validation. |
| C07 | Host `TestIndependentAgentPolicy` and normalized-input fuzzer | Valid spec accepted for policy checks only. Wrong worker/generation/expiry/schema, stale policy, changed hash, malformed signature shape, root UID, bad ingress/URL/secret target, unknown fields, case aliases, duplicate JSON keys, exponent integers and trailing documents denied without trusting controller validation. Signature authorization/engine execution remain M09. |
| C08 | Host `TestConfigurationProtocolVersions`, `TestConfigurationSerialFrameFencing`, `TestConfigurationDurabilityAndFences` and existing build frame/timer tests; M07 timeout/cancel/controller-loss cases | v1/v2 separation, required plan identity, mode/policy/expiry, stage ordering, unknown/duplicate/partial/oversize frames, wrong generation/hash/path, cancellation and idempotency enforced. No build starts without durable matching accepted clone/plan. Independent expiry kills guests without controller. |
| C09 | Guest `TestGuestParserBudgetAndDiagnostics` plus hostile corpus/fuzz; storage `/audit-redaction` and metadata redaction checks | Actual parser cgroup reports 128 MiB/no swap/1 CPU/32 PIDs. Child analysis succeeds within 5-second dispatcher bound; parent cancellation denies. Oversized child input has no output; diagnostic sentinel absent. Repository/image environment values absent from audit/events/outbox. Management remains available in external controller-loss/budget tests. |
| C10 | Full `go test ./...`, `go vet ./...`, targeted race, agent fuzz, Python/shell validation; complete real M07 ten-scenario matrix plus M08 three-scenario matrix | All required tests PASS on frozen source. Build/ingest remains SCANNING, never APPROVED. M07 success, build timeout, cancellation, controller loss, scanner timeout, log/disk/memory/PID exhaustion and remote source all PASS. Zero forbidden canary arrivals, actual registry pulls, packet capture present, fixture trust/firewall restored, guest disks absent and foreign canaries preserved. |

All named roots and their subcases are individual ledger cases. The report also
requires complete guest corpus markers from both positive M08 VMs, actual fuzz
execution evidence, one- and two-service spec hashes, no required skips and source
identity consistency. `infra/config/report.py` refuses incomplete evidence.

## Execution procedure

1. Run software suite with `umask 077; go test -count=1 -json ./...`, retain JSON log.
2. Run `go vet ./...`; race-test contracts/policy/agentpolicy/storage/provisioner/
   clonejob/buildjob; fuzz `FuzzAgentPolicy` for 5 seconds with bounded parallelism.
   Validate modified Python and shell scripts. Record each command's actual exit
   status and SHA-256 of its log in a private checks manifest.
3. Build current-source ingest template with `infra/ingest/build-template.sh` and
   exact pinned database backend configuration. Run the full `infra/config/lab.py`
   procedure from its README without `--cases` or debug mode. It builds fresh
   builder binaries/template and runs both complete matrices. Guest parser tests
   and two separate coverage-guided fuzzers run there; never rerun them on host.
4. Run `infra/config/report.py --software <json-log> --checks <manifest>
   --pipeline <complete-private-run> --output <acceptance-results.json>`.
5. Review each ledger row, inspect sanitized logs and cleanup record, then update
   milestone evidence/status only when the report exits zero and all rows PASS.
   Preserve failed development runs separately; they never become PASS retroactively.

## Scope of evidence

M08 proves normalization and policy boundaries on the tested isolated host. It
does not deploy runtime containers, verify runtime command signatures/replay state,
materialize volumes/secrets, schedule jobs or approve deployments. M09/M10/M12 own
those gates. Existing M04 V14/V15 SKIPs remain unchanged and cannot be inferred PASS.
