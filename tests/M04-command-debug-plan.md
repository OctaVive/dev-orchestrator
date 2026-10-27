# M04 command and backend debugging — execute with Codex on the lab server

## Task for Codex

Debug and fix the code exercised by this command, then execute its automated
tests on the existing disposable Debian lab VM:

```bash
export EVIDENCE="$(mktemp -d "$HOME/m04-retry.XXXXXX")"
M04_DISPOSABLE_HOST=YES-I-AUTHORIZE-REAL-KVM \
  bash infra/builder/m04-acceptance.sh host-tests
```

This is an execution/code-debugging task, not just a documentation review.
Read applicable AGENTS.md instructions. Inspect the code, gather diagnostics,
implement targeted fixes and regression tests, rebuild/install both binaries,
and execute the tests yourself. Use sudo for specific installation/host-test
commands only, never for Go dependency resolution or compilation. If sudo is
unavailable, report the exact blocked command; do not request passwords in chat.

The reported PC freeze was a separate PC issue according to the operator. It
is NOT the subject of this plan and must not be claimed as a backend-caused
crash. Stop if new real instability occurs, but do not investigate the old freeze
as the presumed root cause of these command failures.

## Scope and acceptance

- Use the existing isolated lab, not a production server or physical desktop.
- Fix startup/FD/readiness failures and script diagnostics without weakening
  sandboxing, KVM-only acceleration, resource limits, immutable expiry, image
  pins, or ownership/fencing checks.
- The immediate goal is all four `TestLinuxHost*` tests PASS with no SKIP, and
  no owned running guest, populated cgroup, active timer, raw disk or ready
  marker left after cleanup. Preserve fenced JSON audit tombstones.
- These four tests are a subset only: full **M04 remains NOT PASSED** until the
  separate V01–V16 matrix and acceptance sign-off are complete.
- Do not run clock-change, host exhaustion, reboot, or additional manual fault
  experiments as part of this debugging task.

## Known failures and changes to verify

1. Lifecycle and frozen-supervisor tests timed out after about 20 seconds.
   Foreign-disk protection and delayed-start fencing passed.
2. Supervisor needed the configured KVM supplementary group because its
   capability bounding set excludes DAC overrides. Verify the generated unit
   includes `SupplementaryGroups` equal to the actual device GID.
3. Supervisor stderr was discarded. Verify it goes to the journal, with QEMU
   stderr captured in a bounded buffer and included in launch failures.
4. Captured QEMU failure:
   `Failed to find file descriptor with matching flags=0x0` for
   `file=/dev/fdset/1,format=raw,...`. A code fix supplies both read/write and
   read-only descriptors for the same verified owned disk inode. Verify the
   inherited FD numbers, access modes and `-add-fd` arguments agree. This fix
   has NOT yet been confirmed by a successful real-host test.
5. The most recent invocation exited before tests because `mitchel` lacked
   read/write permission on root:kvm `/dev/kvm` mode 0660. An earlier ACL had
   disappeared. User was advised to join `kvm` and log in again. Verify current
   access rather than assuming it is fixed. Do not chmod the device 0666.
6. BOTH installed binaries contain backend code: the host-test binary creates
   the transient units; the production binary runs the guest supervisor.
   Replacing only the production binary previously left stale test code.
7. Historical failed systemd units accumulate. Those records are not evidence
   that QEMU is still running. Do not delete job JSON or globally prune units.

Reported platform: Debian VM under VirtualBox (`oracle`), systemd 257.13,
QEMU 10.0.13, x86-64 with `svm`. Prior config used QEMU UID 101, GID 104,
KVM GID 993; these are observations, NOT values to hardcode.

## 1. Inspect source and preserve evidence

Read:

- `infra/builder/m04-acceptance.sh`
- `infra/builder/m04-auto-lab.py`
- `infra/builder/backend.example.json`
- `internal/provisioner/linux_backend.go`
- `internal/provisioner/linux_backend_linux.go`
- `internal/provisioner/linux_backend_linux_test.go`
- Relevant manager/ledger code and tests, `cmd/provisioner/main.go`
- `infra/builder/README.md` and `docs/testing/P1-M04-real-host.md`

Do not overwrite unrelated source changes. Start a private run directory:

```bash
umask 077
set -o pipefail
export GOTOOLCHAIN=local
export EVIDENCE="$(mktemp -d "$HOME/m04-debug.XXXXXX")"
mkdir -m 700 "$EVIDENCE/tmp" "$EVIDENCE/bin"
export TMPDIR="$EVIDENCE/tmp"
git rev-parse HEAD | tee "$EVIDENCE/commit.txt"
git status --short | tee "$EVIDENCE/source-status-before.txt"
date -u | tee "$EVIDENCE/time.txt"
id | tee "$EVIDENCE/identity.txt"
uname -a | tee "$EVIDENCE/kernel.txt"
systemctl --version | tee "$EVIDENCE/systemd.txt"
qemu-system-x86_64 --version | tee "$EVIDENCE/qemu.txt"
go version | tee "$EVIDENCE/go.txt"
systemd-detect-virt --vm | tee "$EVIDENCE/virtualization.txt"
ls -l /dev/kvm | tee "$EVIDENCE/kvm-device.txt"
test -r /dev/kvm; printf 'read_access_exit=%s\n' "$?" | tee "$EVIDENCE/kvm-access.txt"
test -w /dev/kvm; printf 'write_access_exit=%s\n' "$?" | tee -a "$EVIDENCE/kvm-access.txt"
```

Record exit codes for each operation; do not confuse successful `tee` with a
passing command. Inspect prior `/home/mitchel/m04-auto-*` and `m04-retry.*`
logs as needed; do not rerun the fresh-install script against this existing lab.

If KVM access is still absent, report it explicitly. With operator approval,
add only the intended lab user to `kvm`, then require a new login/session with
effective membership before testing. Do not silently broaden device permissions.

Privately inspect backend.json and trusted path ownership, account/device IDs,
image pin, executable locations and actual installed binary hashes. Never copy
job ownership proofs or credentials into public output or the repository.

## 2. Baseline inventory and focused reproduction

Capture baseline, and verify no active owned orphan from an earlier run:

```bash
sudo systemctl list-units --all 'orchestrator-build-*' 'orchestrator-expiry-*' \
  | tee "$EVIDENCE/units-before.txt"
sudo find /var/lib/orchestrator-builder/host -maxdepth 1 -type f -printf '%f %s\n' \
  | tee "$EVIDENCE/artifacts-before.txt"
sudo sha256sum /usr/local/sbin/orchestrator-provisioner /usr/local/libexec/m04-host.test \
  | tee "$EVIDENCE/installed-hashes-before.txt"
```

If active resources exist, inspect exact ownership/cgroups and reconcile using
the documented backend mechanism before starting another guest. Never kill
unrelated QEMU processes or delete state to free capacity.

Run the current lifecycle test ONCE to isolate startup before the entire suite:

```bash
sudo env M04_DISPOSABLE_HOST=YES-I-AUTHORIZE-REAL-KVM \
  M04_HOST_CONFIG=/var/lib/orchestrator-builder/host/backend.json \
  /usr/local/libexec/m04-host.test -test.v -test.count=1 \
  -test.run '^TestLinuxHostLifecycleAndKernelEnvelope$' -test.timeout=2m \
  2>&1 | tee "$EVIDENCE/lifecycle-before.txt"
rc=${PIPESTATUS[0]}
printf '%s\n' "$rc" > "$EVIDENCE/lifecycle-before-exit.txt"
```

Use the exact UUID logged by the test, not a wildcard:

```bash
UNIT="orchestrator-build-$JOB.service" # JOB = recorded test UUID
sudo systemctl show "$UNIT" \
  -p Result -p ExecMainCode -p ExecMainStatus -p MainPID -p ControlGroup \
  -p SupplementaryGroups -p StandardError -p MemoryPeak -p CPUUsageNSec
sudo journalctl -b -u "$UNIT" --no-pager -n 100
```

Save these outputs privately. Early supervisor/QEMU exit must be diagnosed from
the journal, not treated as a slow-boot timeout. If installed diagnostics are
stale, rebuild/install the current diagnostic code before one further attempt.

## 3. Debug and fix code

Follow the actual evidence through config validation, trusted-path checks,
image preparation, transient unit properties, supervisor credential changes,
FD inheritance, QEMU startup, readiness acknowledgement and cleanup/fencing.

Prioritize:

- Correct paired FD access modes and same-inode verification, with no host-path
  exposure to QEMU and no disk format probing/backing-chain fallback.
- Meaningful bounded errors when the child exits, including launch failures.
- Script prerequisites that explain a refusal instead of exiting silently.
- Failing early when a known owned unit exits before readiness, if needed;
  preserve context cancellation, startup fencing and safe cleanup semantics.
- Regression tests for each source change; do not claim an argument-string
  assertion alone proves actual QEMU compatibility.

Do not remove sandbox settings, grant broad capabilities, switch acceleration,
extend the 20-second operation policy, or discard failed evidence to pass tests.
If a platform prerequisite cannot be met, report BLOCKED rather than improvise.

## 4. Software verification and deployment of the fix

Use the private TMPDIR above (ledger tests require private directories):

```bash
CGO_ENABLED=0 go test -p 1 -count=1 ./...
CGO_ENABLED=0 go vet ./...
CGO_ENABLED=1 go test -race -p 1 -count=1 \
  ./internal/provisioner ./internal/provisionerrpc ./internal/contracts ./cmd/provisioner
git diff --check
CGO_ENABLED=0 go build -o "$EVIDENCE/bin/orchestrator-provisioner" ./cmd/provisioner
CGO_ENABLED=0 go test -c -o "$EVIDENCE/bin/m04-host.test" ./internal/provisioner
sha256sum "$EVIDENCE/bin/orchestrator-provisioner" "$EVIDENCE/bin/m04-host.test" \
  | tee "$EVIDENCE/built-hashes.txt"
```

Save logs and exit codes; stop deployment on failed tests/builds. A missing C
compiler blocks race verification; do not count a non-race run as a substitute.
Review the diff, confirm no active owned guest, then install BOTH exact binaries:

```bash
sudo install -o root -g root -m 0755 \
  "$EVIDENCE/bin/orchestrator-provisioner" /usr/local/sbin/orchestrator-provisioner
sudo install -o root -g root -m 0755 \
  "$EVIDENCE/bin/m04-host.test" /usr/local/libexec/m04-host.test
sudo sha256sum /usr/local/sbin/orchestrator-provisioner /usr/local/libexec/m04-host.test \
  | tee "$EVIDENCE/installed-hashes-after.txt"
```

Do not install or enable the production API/guard services for these tests.

## 5. Verify real execution and the original command

Rerun the focused lifecycle test with a distinct log name. If it fails, collect
the new job's journal and fix based on evidence; avoid unchanged repeated runs.
If it passes, execute the original full helper command with the same private
EVIDENCE directory (the helper creates a unique child run directory):

```bash
M04_DISPOSABLE_HOST=YES-I-AUTHORIZE-REAL-KVM \
  bash infra/builder/m04-acceptance.sh host-tests
rc=$?
printf '%s\n' "$rc" > "$EVIDENCE/helper-final-exit.txt"
```

Require exit 0, all four named cases PASS, no SKIP, and final safe inventory.
Inspect any unexpected leftover raw/ready files, active timers, populated
cgroups or QEMU processes by exact ownership. Do not delete foreign resources.
Failed historical unit records and fenced JSON tombstones are expected audit
artifacts, not reusable jobs. Retain prior failed logs and explain retries.

## 6. Deliverable

Write `$EVIDENCE/report.md` and give the operator a concise summary containing:

- Original command failure and evidence-supported root cause(s).
- Changed source files and regression tests.
- Source commit/diff and built/installed binary hashes.
- Software and real-host results with exit codes, including failures and retries.
- Exact final resource inventory and any unresolved cleanup/blockers.
- Evidence directory and next remaining acceptance work.

Do not commit private evidence. State **automated host subset PASS**, **FAIL** or
**BLOCKED** accurately; never mark full M04 PASS from this debugging task alone.
