# P1-M04 — Debian-based Linux VM test checklist

**Current M04 status: PASS\*.** \* V14 and V15 marked as SKIP. V01–V13 and V16 passed; neither skipped case is counted as passed. See the [acceptance record](P1-M04-acceptance-report.md). The procedure below describes complete, unqualified acceptance. The explicit Linux QEMU/KVM/systemd backend is implemented; default execution remains disabled. Complete this checklist AND [the mandatory real-host procedure](P1-M04-real-host.md), then sign [the acceptance record](P1-M04-acceptance-report.md). All mandatory tests MUST actually execute successfully before M04 PASS.

Use `[x]` only after recording evidence. Record **FAIL**, **BLOCKED** or **NOT RUN** rather than ticking an unavailable test. Passing every software test does **not** complete the real-guest acceptance section.

## 0. Run record and safety

Fill this in before testing:

| Item | Value |
|---|---|
| Tester / date (UTC) | |
| Repository commit | |
| Local source changes | |
| Debian/Ubuntu distribution and version | |
| Kernel / architecture | |
| Outer hypervisor / provider | |
| RAM / vCPUs allocated to this Linux VM | |
| Nested virtualization enabled by outer host administrator? | YES / NO / UNKNOWN |
| Evidence directory | |

- [ ] **A01 — Trusted source.** Clone your own trusted repository/commit. Do not run an unknown fork/PR with infrastructure credentials.
- [ ] **A02 — Non-root testing.** Run Go tests/builds as your normal user, not with `sudo`. Stop if `id -u` prints `0`.
- [ ] **A03 — Safe lab.** No production app volumes, management database, controller private keys or real repositories are used as fixtures. Do not change an existing service to make a negative test pass.
- [ ] **A04 — Correct toolchain.** Install a maintained **Linux Go toolchain satisfying `go.mod` (currently Go 1.27.0+)**. Debian's packaged Go may be older. Verify official download checksums if installing Go separately; do not lower `go.mod` or copy the Windows `.exe` toolchain.

All command blocks below use **Bash**, from the cloned repository root. Go dependency download/build caches will be populated. Tests use temporary files, fixed test-binary subprocesses and temporary loopback TLS listeners. They do not install services, contact libvirt, change firewall rules or start actual guests.

Create a private run directory **outside** the repository:

```bash
umask 077
set -o pipefail
export GOTOOLCHAIN=local
EVIDENCE="$(mktemp -d "$HOME/m04-evidence.XXXXXX")"
export EVIDENCE
mkdir -m 700 "$EVIDENCE/tmp"
export TMPDIR="$EVIDENCE/tmp"
cp docs/testing/P1-M04-linux-checklist.md "$EVIDENCE/checklist.md"
printf '%s\n' "$EVIDENCE"
```

Keep this terminal open: later blocks use these variables. Edit the copied `checklist.md` to check items off without dirtying the repository. Do not commit evidence containing private host details or any credentials.

Capture source/environment:

```bash
git rev-parse HEAD | tee "$EVIDENCE/commit.txt"
git status --short | tee "$EVIDENCE/source-status.txt"
id | tee "$EVIDENCE/user.txt"
cat /etc/os-release | tee "$EVIDENCE/os-release.txt"
uname -a | tee "$EVIDENCE/kernel.txt"
go version | tee "$EVIDENCE/go-version.txt"
go env GOOS GOARCH GOVERSION CGO_ENABLED GOTOOLCHAIN | tee "$EVIDENCE/go-env.txt"
```

Expected: Linux Go >=1.27, non-root identity, known commit and understood source changes. `GOTOOLCHAIN=local` intentionally fails rather than silently obtaining another compiler if the installed version is too old.

## 1. Nested virtualization / host preflight — read-only

These checks are **prerequisites**, not proof of working guest creation. If blocked, continue with software tests; do not enable an unsafe alternative backend.

```bash
systemd-detect-virt | tee "$EVIDENCE/virtualization.txt"
lscpu | tee "$EVIDENCE/cpu.txt"
ls -l /dev/kvm 2>&1 | tee "$EVIDENCE/kvm-device.txt"
stat -fc %T /sys/fs/cgroup | tee "$EVIDENCE/cgroup-type.txt"
free -h | tee "$EVIDENCE/memory.txt"
df -h "$HOME" | tee "$EVIDENCE/disk.txt"
findmnt -T "$HOME" -o TARGET,SOURCE,FSTYPE,OPTIONS | tee "$EVIDENCE/filesystem.txt"
```

For the proposed first **x86-64 Intel/AMD** backend:

```bash
grep -m1 -Eo '\b(vmx|svm)\b' /proc/cpuinfo | tee "$EVIDENCE/virtualization-flags.txt"
{
  test -c /dev/kvm
  printf 'Character-device check exit code: %s\n' "$?"
  test -r /dev/kvm
  printf 'Read-access check exit code: %s\n' "$?"
  test -w /dev/kvm
  printf 'Write-access check exit code: %s\n' "$?"
} 2>&1 | tee "$EVIDENCE/kvm-access-checks.txt"
```

Every device-check exit code must be `0`; a successful `tee` does not override a nonzero individual check. Running as root would make access checks misleading for the intended service identity.

- [ ] **H01 — Platform identified.** Outer hypervisor/provider and Linux VM resource allocation recorded. `systemd-detect-virt` output alone does not identify who can change its settings.
- [ ] **H02 — Architecture decided.** `x86_64` for the proposed first backend. An ARM machine requires a separate image/backend review; do not treat missing x86 flags on ARM as a software-test failure.
- [ ] **H03 — Nested KVM prerequisites exposed.** `/dev/kvm` is a character device and `vmx` or `svm` is exposed on x86. If absent, mark BLOCKED and ask the **outer hypervisor administrator** to enable nested virtualization. Do not use privileged DinD, TCG/local builds or a simulator to claim a pass.
- [ ] **H04 — Device permissions understood.** Access results and `id` recorded. Actual backend tests must later use the provisioner's intended service identity, not an all-powerful root shell. Review any future group/ACL changes separately.
- [ ] **H05 — cgroup v2 present.** Expected filesystem type: `cgroup2fs`. This does not prove delegation, controller availability or enforcement.
- [ ] **H06 — Capacity/local storage reviewed.** Leave room for the Linux VM OS, control services and any other nested VMs. One proposed build needs 4 GiB guest memory plus bounded overhead (4.5 GiB host budget) and an 11 GiB physical disk allowance. Do not consume all outer VM resources. SQLite metadata must not live on NFS/SMB/shared folders.

If `$HOME` is on a network/shared filesystem, choose an approved private **local** evidence/TMPDIR location and restart section 0 there before running SQLite tests. Do not treat a successful SQLite test on an unsupported shared filesystem as a supported deployment configuration.

Optional, **only if libvirt tools are already installed and access is authorized**:

```bash
virt-host-validate qemu 2>&1 | tee "$EVIDENCE/libvirt-host-validation.txt"
virsh --readonly --connect qemu:///system version 2>&1 | tee "$EVIDENCE/libvirt-version.txt"
```

Record missing tools/permission failures as BLOCKED. Do not automatically install libvirt, enable its default NAT network, start services, change boot parameters, load modules or grant broad libvirt access for this checklist. A libvirt connection may socket-activate an already installed daemon. A tool reporting KVM support is still not the actual M04 guest test. Device-passthrough/IOMMU support is not permission to enable host devices.

**Preflight result:** PASS / BLOCKED / FAIL: __________

## 2. Current software-core verification — runnable now

No KVM, Docker, production certificate or manual CA setup is required here. Tests generate short-lived identities and use a VM simulator **only in `_test.go`**. Privileged `TestLinuxHost*` cases intentionally SKIP in this normal-user suite; they MUST separately run without SKIP in the real-host procedure.

Each pipeline uses `pipefail`. A `tee` log is not a pass by itself: verify exit code 0 and the test output. Do not ignore an initial failure because a later retry passed; retain both logs and explain the cause.

### S01 — Dependency integrity and build

```bash
go mod download 2>&1 | tee "$EVIDENCE/module-download.txt"
go mod verify 2>&1 | tee "$EVIDENCE/module-verify.txt"
mkdir -m 700 "$EVIDENCE/bin"
CGO_ENABLED=0 go build -o "$EVIDENCE/bin/orchestrator-provisioner" ./cmd/provisioner 2>&1 | tee "$EVIDENCE/provisioner-build.txt"
```

- [ ] **S01 PASS:** all exit 0; module verification says `all modules verified`; Linux binary exists in the private evidence directory. No source/dependency files were edited to get it working. Module integrity is not a vulnerability/malware verdict.

### S02 — Focused M04 tests on Linux

```bash
CGO_ENABLED=0 go test -p 1 -count=1 -v -cover ./internal/contracts ./internal/provisioner ./internal/provisionerrpc ./cmd/provisioner 2>&1 | tee "$EVIDENCE/m04-core-tests.txt"
```

- [ ] **S02 PASS:** every selected package returns `ok`/`PASS`; no failing or unexpectedly skipped assertion (the explicit real-host authorization skips above are expected here only). Record coverage but do not equate a coverage percentage with isolation assurance.

Check these groups in that output:

| Check off | Behavior | Existing test names / evidence |
|---|---|---|
| [ ] | Bounded schema, no raw host XML/path/network/resource/identity override | `TestBuildLeaseStrictContractAndDeadline`, `TestInvalidCatalogAndInputCannotReachBackend`, `TestReleaseAcceptsOnlyEmptyObject` |
| [ ] | Separate ledger, checksum/version refusal, atomic events | `TestLedgerNamespaceAndVersionFailClosed`, `TestLedgerAtomicEventsAndImmutableIdentity` |
| [ ] | Idempotency; no expiry extension or cleaned-job resurrection | `TestCreateIdempotencyAndNoSecretResponse`, `TestReleaseTombstonesAndReplayProtection` |
| [ ] | Logical expiry, guard freshness, fixed budget and disabled backend | `TestExpiryIsIndependentAndImmutable`, `TestExpiredCreateIsNeverReportedActive`, `TestStaleGuardAndMissingControlsBlockAdmission`, `TestUnconfiguredBackendCannotExecute` |
| [ ] | Partial cleanup holds capacity; foreign VM model untouched | `TestFailedOrPartialCleanupKeepsCapacity`, `TestForeignResourceIsNeverRemoved` |
| [ ] | Cancellation, delayed-start fence model, concurrent duplicates, restart recovery | `TestCreateFailureAndCanceledRequestCleanUp`, `TestReleaseFencesDelayedStart`, `TestConcurrentDuplicateCreateAndSeparateHandles`, `TestReopenRecoversInterruptedStartupWithoutController` |
| [ ] | Real mTLS: no/untrusted/expired client denied; worker/pin/URI/browser confusion denied | `TestRealMutualTLSAndControllerOnlyAdmission`, `TestCertificatePolicyRejectsLongLifetimeAndCommonNameFallback` |
| [ ] | No production simulator/unsafe backend flag; prototype rejects public bind | `TestPrototypeCannotEnableExecutionOrExposePublicBind` |

**Important:** the named expiry/foreign-VM/fence model tests above operate on simulated VM maps. SQLite and TLS are real; those guests are not. They cannot satisfy section 5; execute the separate authorized `TestLinuxHost*` cases and required fault/workload matrix.

### S03 — Full M01–M04 regression

```bash
CGO_ENABLED=0 go test -p 1 -count=1 -v -cover ./... 2>&1 | tee "$EVIDENCE/full-regression.txt"
CGO_ENABLED=0 go vet ./... 2>&1 | tee "$EVIDENCE/vet.txt"
```

- [ ] **S03 PASS:** full suite and vet exit 0. Existing auth, role/CSRF, SQLite crash recovery and contract tests still pass. `go vet` may produce an empty successful log.

`-p 1` serializes packages to reduce RAM pressure; it does not remove concurrency assertions within tests. Full regression uses real Argon2id (64 MiB per hash, bounded service concurrency). The tests do not require production secrets. Abrupt test-helper exits are intentional only when the **parent crash-recovery test reports PASS**.

### S04 — Linux race detector

Requires a supported Linux/Go race-detector architecture and a working C compiler. Check first:

```bash
command -v cc
cc --version
```

If absent, mark BLOCKED and arrange an approved compiler installation separately (Debian-family package `build-essential` is a usual option). Do not run Go tests as root or call a normal test run a race-detector pass.

```bash
CGO_ENABLED=1 go test -race -p 1 -count=1 ./internal/provisioner ./internal/provisionerrpc ./internal/contracts ./cmd/provisioner 2>&1 | tee "$EVIDENCE/m04-race.txt"
```

- [ ] **S04 PASS:** exit 0, no `DATA RACE` report. This is new Linux evidence; the previous Windows verification did not establish it. If BLOCKED, software verification remains partial for this item.

### S05 — Repeat concurrency/cancellation cases

```bash
CGO_ENABLED=0 go test -count=20 -run 'TestReleaseFencesDelayedStart|TestConcurrentDuplicateCreateAndSeparateHandles|TestCreateFailureAndCanceledRequestCleanUp|TestLedgerAtomicEventsAndImmutableIdentity' ./internal/provisioner 2>&1 | tee "$EVIDENCE/m04-repeated.txt"
```

- [ ] **S05 PASS:** all 20 repetitions pass. Keep any timeout/flakiness evidence; do not increase/disable policy deadlines simply to obtain green output. These are still lifecycle-model tests, not kernel deadlines.

### S06 — Recommended bounded fuzz smoke

```bash
CGO_ENABLED=0 go test ./internal/contracts -run '^$' -fuzz '^FuzzBuildLeaseDecode$' -fuzztime=30s -parallel=2 -timeout=2m 2>&1 | tee "$EVIDENCE/m04-fuzz.txt"
```

- [ ] **S06 PASS:** no panic, failing seed or test timeout. Save any failing input and report it; do not delete the seed or weaken the schema. A short fuzz run is not a completeness or DoS-resistance proof.

**Software results:** S01 ___ S02 ___ S03 ___ S04 ___ S05 ___ S06 ___

## 3. Manual Linux fail-closed and permissions checks — runnable now

Use only the dedicated scratch paths below. Do not point these commands at your management database or any existing service ledger. The all-zero digest below is deliberately a **fictional test value**, not an approved image or readiness assertion. There is no image download or VM creation.

### P01 — Guard must refuse fake readiness

```bash
mkdir -m 700 "$EVIDENCE/guard-probe"
TEST_DIGEST="sha256:$(printf '%064d' 0)"
"$EVIDENCE/bin/orchestrator-provisioner" \
  -mode guard \
  -ledger "$EVIDENCE/guard-probe/leases.db" \
  -template-digest "$TEST_DIGEST" \
  > "$EVIDENCE/guard-disabled.txt" 2>&1
guard_status=$?
cat "$EVIDENCE/guard-disabled.txt"
printf 'Guard exit code: %s\n' "$guard_status"
```

- [ ] **P01 PASS:** **nonzero** exit with `build isolation or watchdog unavailable`. No healthy guard/VM execution is advertised. This expected failure is correct for the current backend. If it succeeds, stop and investigate.

Optional if `sqlite3` is already installed:

```bash
sqlite3 -readonly "$EVIDENCE/guard-probe/leases.db" 'SELECT count(*) FROM leases; SELECT heartbeat_at FROM guard WHERE id=1;'
```

Expected: `0` then `0`. The prototype may initialize its private ledger, but must not reserve a job or publish a healthy heartbeat.

### P02 — Public parent directory must be rejected

Only change permissions on this newly created scratch directory:

```bash
mkdir -m 755 "$EVIDENCE/public-parent-probe"
chmod 755 "$EVIDENCE/public-parent-probe"
"$EVIDENCE/bin/orchestrator-provisioner" \
  -mode guard \
  -ledger "$EVIDENCE/public-parent-probe/leases.db" \
  -template-digest "$TEST_DIGEST" \
  > "$EVIDENCE/public-parent-rejected.txt" 2>&1
permission_status=$?
cat "$EVIDENCE/public-parent-rejected.txt"
printf 'Permission rejection exit code: %s\n' "$permission_status"
test ! -e "$EVIDENCE/public-parent-probe/leases.db"
```

- [ ] **P02 PASS:** nonzero exit with `invalid build lease operation` and **no ledger file created** in the 0755 directory. Merely seeing any nonzero exit is insufficient, because the unconfigured backend would also fail later.

### P03 — Private ledger file remains private

```bash
stat -c '%a %U %n' "$EVIDENCE/guard-probe" "$EVIDENCE/guard-probe/leases.db"
```

- [ ] **P03 PASS:** directory mode `700`, database mode `600`, expected normal-user owner. Do not relax these permissions to work around startup errors.

No manual mTLS certificate generation is required for current verification: S02 runs the actual local TLS matrix, including expected create **503**. Do not disable verification with `curl -k`, add an HTTP fallback or install test CAs into the system trust store to tick a box.

## 4. Evidence / current-core sign-off

```bash
git status --short | tee "$EVIDENCE/source-status-after.txt"
git diff --exit-code -- go.mod go.sum
```

- [ ] **E01 — Source understood.** No unexplained dependency/source changes. Logs/binaries/ledgers stayed outside the checkout; any saved fuzz failure is explicitly recorded.
- [ ] **E02 — Evidence retained privately.** Commit, Linux/kernel/Go versions, commands, exit codes and failed/retried runs recorded. Do not upload private keys, tokens or sensitive host inventory.
- [ ] **E03 — Test resources ended.** Automatic tests completed and closed their temporary TLS servers/subprocesses. No production service/VM/network changes were made. Do not run global Docker/libvirt prune, delete foreign VM paths or change production data to clean a test run.
- [ ] **E04 — Core result recorded.** S01–S05 and P01–P03 PASS to mark the required core checks verified; record S06 separately. Any required BLOCKED/FAIL means partial/failed core verification, not a full pass.

**Linux software-core result:** PASS / PARTIAL / FAIL: __________

**Fuzz smoke:** PASS / FAIL / NOT RUN: __________

**Nested-KVM preflight:** PASS / BLOCKED / FAIL: __________

**Recorded M04 acceptance: PASS\*.** \* V14 and V15 marked as SKIP.

Send back `checklist.md`, `commit.txt`, distro/kernel/Go details, the relevant failure logs, and virtualization/KVM/cgroup results (redact private host information). Do not send the entire evidence tree if it contains credentials from unrelated work.

## 5. Real nested-KVM acceptance — mandatory, execution pending

Do **not** check these off using software-model logs, an arbitrary manually started VM, libvirt demo, TCG, DinD or a different program. Execute [the real-host procedure](P1-M04-real-host.md): it provides opt-in real backend test commands, workload/fault evidence requirements and mandatory sign-off. Moving the repo to Linux alone is insufficient.

Use an **explicitly approved disposable lab** with a pinned credential-free image, dedicated storage/IDs and recorded baseline inventory. Guests have no NIC. Confirm the intended service identity and record backend/kernel/QEMU/systemd/image/policy versions. Do not run resource-exhaustion, process-kill, clock-change or storage-fault tests on production infrastructure.

Record the timing criteria before testing: host enforcement must be scheduled at the immutable deadline; proposed healthy-host observation tolerance is at most 5 seconds, with cleanup confirmation within the architecture's 2-minute cleanup SLA. Tolerance is for observation/scheduling measurement, **not lease renewal**. A frozen or failed host cannot offer an absolute timing guarantee; disclose that residual risk. Missing hard-kill/fence evidence fails acceptance.

| Check off only with real evidence | Case / action in approved lab | Required observation |
|---|---|---|
| [ ] **V01 — Backend and image pin** | Admit a valid fixed-template request through the actual provisioner; separately test a tampered **lab copy** | Fresh KVM-accelerated guest, not TCG/container; image bytes match approved digest; tampered/unapproved image denied before start |
| [ ] **V02 — No host authority exposed** | Inspect actual guest definition and guest-visible devices/boot material | No host mounts/sockets, privileged host namespace/device sharing, management keys, controller certificates or long-lived secrets; initially no NIC/control channel |
| [ ] **V03 — Fresh guest lifecycle** | Create, release, then submit a new job | Separate clean guest/disk for new job; all owned artifacts removed after release; prior guest never reused |
| [ ] **V04 — Replay and immutable expiry** | Replay same command and try altered expiry/nonce/job/identity | One guest only; no deadline extension or cross-controller takeover; cleaned job cannot resurrect |
| [ ] **V05 — CPU** | Run a bounded approved CPU fixture **inside the disposable guest** | 2 vCPUs plus externally enforced aggregate 2000 host CPU millis for the VM group; management/guard remain responsive |
| [ ] **V06 — Memory/swap** | Apply bounded in-guest pressure and inspect host cgroup counters | 4096 MiB guest, 4608 MiB host envelope, bounded/no uncontrolled swap; no control-plane memory exhaustion |
| [ ] **V07 — Disk/IO** | Use a bounded guest write/IO fixture against only its test disk | 10240 MiB virtual limit, 11264 MiB physical allowance including COW overhead, 1000 IOPS externally enforced; host filesystem not filled |
| [ ] **V08 — Processes** | Inspect/cross-check limits with a bounded approved fixture, never a fork bomb | 128 host process/thread budget; 512 runner PID defense tested, with explicit admission that malicious guest root can bypass guest-local PID limits |
| [ ] **V09 — Controller loss** | Admit short-TTL job; stop only the dedicated test controller | Real guest stops at hard expiry; no controller heartbeat can extend lease; independent inventory proves absence |
| [ ] **V10 — Provisioner/guard loss** | In separate controlled cases stop/kill only this run's provisioner or guard | Fresh admission blocked when guard is stale; existing guest still bounded by independent host deadline; restart reconciles without duplicate start |
| [ ] **V11 — Late-start fencing** | Delay/intercept the lab hypervisor create operation, then release/expire | After cleanup acknowledgment no delayed create can start/resurrect a guest; all operation outcomes reconciled |
| [ ] **V12 — Partial failure and capacity** | Inject safe lab failures after disk allocation/start and during cleanup | Failure visible; one build slot held until VM absence, artifact absence and start fence are all confirmed; retry cleans only owned resources |
| [ ] **V13 — Foreign canary** | Use a separate throwaway foreign-resource canary with mismatched ownership proof | No deletion/modification of canary, even with similar names/UUID collision; operation quarantines/fails closed |
| [ ] **V14 — Time/ledger faults** | In an isolated lab exercise clock discontinuity, ledger unavailability and interrupted metadata writes | Independent monotonic deadline still bounds running guest; no false CLEANED/silent capacity release; durable recovery/audit evidence preserved |
| [ ] **V15 — Network and patch posture** | Inspect no-NIC guest/host management separation and versions | No management/host/metadata access path; maintained hypervisor/kernel; M05 broker egress remains disabled until separately tested |
| [ ] **V16 — Safe final inventory** | Compare exact owned guest/disk/quota/timer inventory to baseline | No owned orphan guest, timer, disk or lease left active; foreign resources unchanged; evidence retained |

Use the linked backend-specific procedure; do not improvise dangerous production commands. Inspection alone (a quota setting, CPU flags, a successful callback or `execution_enabled:true`) is not the required enforcement test. Raw preallocation/file-size bounds replace COW/project quotas in this backend.

**Real-guest result:** NOT RUN / BLOCKED / PASS / FAIL: __________

**M04 can be accepted only when:** required core checks pass, the actual backend is reviewed, every applicable V01–V16 case passes with evidence, and unsupported patterns/residual risks remain documented. Only then proceed to enabling M05 controlled egress and later real cloning/building. No production repositories or application deployment are authorized by this checklist.

References: [M04 implementation/remaining gates](../implementation/build-provisioner.md), [security evidence checklist](../implementation/ph1-capability-checklist.md), [general test strategy](../implementation/testing-strategy.md).
