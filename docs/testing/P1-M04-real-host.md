# Mandatory M04 real-host execution procedure

**Recorded acceptance status: PASS\*.** \* V14 and V15 marked as SKIP. V01–V13 and V16 passed. See the [acceptance record](P1-M04-acceptance-report.md); skipped cases remain SKIP. The full procedure below retains the requirements for an unqualified PASS. This is a required continuation of
[the Linux checklist](P1-M04-linux-checklist.md), not an optional smoke test.
All V01–V16 must have actual evidence before M04 PASS. The automated real-host
tests cover a subset; they do not replace the workload/fault matrix below.

## 1. Dedicated host preparation

Use a disposable Debian 12+/Ubuntu 24.04+ **x86-64** VM with nested `/dev/kvm`,
systemd PID 1, unified cgroup v2, and private local ext4/XFS storage. Allocate at
least 8 GiB RAM, 4 vCPUs, and 30 GiB free local disk. No production resources,
keys or repositories. QEMU/systemd/kernel must be maintained and patched.

Read [the host runbook](../../infra/builder/README.md) and install the reviewed
binary/config/image there. **Do not start the API or guard yet.** PID-1 alarm
timers (`WakeSystem=yes`, CLOCK_BOOTTIME) must work in the outer VM: failure is
BLOCKED, never permission to remove this property or use TCG.

The approved credential-free **raw BIOS boot disk must be 512 bytes–1 GiB** and
boot with virtio block on Q35. Provisioning copies its exact pinned bytes into
a preallocated 10 GiB disk; partition/filesystem growth is a guest task. No
qcow2/backing files, guest agent, NIC, shared mounts, metadata, Docker socket or
host certificate is provided. The guest must mount cgroup v2 and configure its
runner with `pids.max=512` (root can bypass that guest-local limit).

For controlled load cases prepare separate reviewed, credential-free fixture
images whose init runs the specified bounded workload automatically. Pin and
record each image digest; change configuration **only after all owned guests
have stopped**. Do not mount a guest-modified filesystem on the host or execute
guest output. These are lab fixtures, not untrusted repository builds.

The repository includes `infra/builder/build-lab-fixture.sh`: review it, then
install the exact script root:root 0700 at
`/usr/local/libexec/m04-build-lab-fixture`. Through the approved Debian package
process install `busybox-static`, `grub-pc-bin`, `grub2-common`, `fdisk`,
`e2fsprogs`, `cpio`, `kmod`, `python3`, `fio` and a bootable host kernel with
matching `/lib/modules`. It constructs only a new 768 MiB raw image/loop device;
it never formats a caller-specified disk. It retains all build files and prints
the exact image path/hash. Do not run it on production infrastructure.

```bash
sudo env M04_IMAGE_BUILD=YES-I-AUTHORIZE-LOOP-IMAGE \
  /usr/local/libexec/m04-build-lab-fixture idle
```

Repeat for `cpu`, `memory`, `io`, `pids`, recording hashes and manifests. Review
the produced never-booted images before installation. The fixture writes boot/
result evidence to the **last sector of its expanded disposable disk**; IO mode
also writes a bounded fio JSON result to the preceding 64 KiB. No host mount of
a guest-modified filesystem is needed. Production builder images still require
their own review: these fixtures contain neither BuildKit nor a build runner.

## 2. Run software checks as normal user

Execute checklist sections 0–4 first. Disabled-backend probes still apply to the
default CLI: only `-backend linux-kvm -linux-config ...` enables Linux execution.
Do not run the Go compiler/dependency resolution with sudo.

Build the reviewed production and integration binaries as the normal user:

```bash
CGO_ENABLED=0 go build -o "$EVIDENCE/bin/orchestrator-provisioner" ./cmd/provisioner
CGO_ENABLED=0 go test -c -o "$EVIDENCE/bin/m04-host.test" ./internal/provisioner
sha256sum "$EVIDENCE/bin/orchestrator-provisioner" "$EVIDENCE/bin/m04-host.test" | tee "$EVIDENCE/binary-digests.txt"
```

After reviewing code and digest, install those **exact** files as root into the
root-owned `/usr/local/sbin` (production) and `/usr/local/libexec` (test) paths.
Installation commands are in the runbook. Never run a root test binary from a
user-writable directory. The service executable path in `backend.json` must be
the production binary, not the Go test binary.

## 3. Execute real guest tests (explicitly privileged)

Inventory first; save output privately. Missing-unit `systemctl show` must report
`LoadState=not-found` on this systemd version (if it exits nonzero, report failure,
do not weaken ownership checks). Do not reuse an existing production host root.

```bash
sudo systemctl list-units --all 'orchestrator-build-*' 'orchestrator-expiry-*' | tee "$EVIDENCE/units-before.txt"
sudo find /var/lib/orchestrator-builder/host -maxdepth 1 -type f -printf '%f %s\n' | tee "$EVIDENCE/artifacts-before.txt"
sudo env M04_DISPOSABLE_HOST=YES-I-AUTHORIZE-REAL-KVM \
  M04_HOST_CONFIG=/var/lib/orchestrator-builder/host/backend.json \
  /usr/local/libexec/m04-host.test -test.v -test.count=1 \
  -test.run '^TestLinuxHost' -test.timeout=5m \
  2>&1 | tee "$EVIDENCE/real-host-tests.txt"
```

Use Bash `set -o pipefail`. Required: exit 0; all four `TestLinuxHost*`
cases PASS; **no SKIP**. They create/destroy real guests, check actual cgroup
limits, reject tombstone resurrection, freeze the supervisor with SIGSTOP and
observe independent expiry, and preserve an intentionally colliding foreign
disk. The fourth case delays startup with an exact lab-owned systemd drop-in,
releases before helper execution and attempts restart after cleanup to prove
durable fencing. No API/guard/controller runs during these tests. Each job UUID is logged.
The test's cleanup removes only its exact canary and owned artifacts; private
journal tombstones are intentionally retained. Never prune global resources.

On failure save the exact job IDs, these owned units' `systemctl status`,
`systemctl show`, `journalctl -u UNIT`, the private state files and cgroup
counters. **Private state contains ownership proofs: do not publish it.** Failed
cleanup holds capacity; manually review instead of deleting the ledger.

## 4. Required enforcement/fault matrix (V01–V16)

Run each case in the disposable lab, recording action, start/deadline/stop times,
kernel counters before/after, exit status and exact cleanup. A configuration
value alone is NOT evidence that a limit held under load. Use the job ID printed
by the host test to identify the exact unit; run one job at a time. For extended
workload cases use `TestLinuxHostLifecycleAndKernelEnvelope` with a 90-second lease, 60-second
observation window **before cleanup**, and the approved fixture digest. This is
built in: set `M04_OBSERVE_SECONDS=60` and select only the lifecycle test below.
Do not change the production profile.

```bash
sudo env M04_DISPOSABLE_HOST=YES-I-AUTHORIZE-REAL-KVM \
  M04_HOST_CONFIG=/var/lib/orchestrator-builder/host/backend.json \
  M04_OBSERVE_SECONDS=60 /usr/local/libexec/m04-host.test \
  -test.v -test.count=1 -test.run '^TestLinuxHostLifecycleAndKernelEnvelope$' \
  -test.timeout=2m 2>&1 | tee "$EVIDENCE/workload-CASE.txt"
```

Run once per pinned fixture, replacing `CASE` in the log name; use a second
terminal for the observation commands below. The test logs the exact unit and
reads the bounded result sector, failing if the fixture never proves boot. Save
the IO result region before automatic cleanup with a bounded **read-only** `dd`
of the exact job raw file (`bs=512 skip=20971390 count=128`); do not parse/execute
guest text with a shell. Independently assess fio results and host counters.

Inspection commands while that job runs (`JOB` is its logged UUID):

```bash
UNIT="orchestrator-build-$JOB.service"
sudo systemctl show "$UNIT" -p MainPID -p ControlGroup -p CPUQuotaPerSecUSec -p MemoryMax -p MemorySwapMax -p TasksMax -p PrivateNetwork -p RuntimeMaxUSec -p Description
CG="$(sudo systemctl show "$UNIT" -p ControlGroup --value)"
sudo cat "/sys/fs/cgroup$CG/cpu.stat" "/sys/fs/cgroup$CG/cpu.max" "/sys/fs/cgroup$CG/memory.events" "/sys/fs/cgroup$CG/memory.current" "/sys/fs/cgroup$CG/pids.current" "/sys/fs/cgroup$CG/io.stat"
sudo systemctl show "orchestrator-expiry-$JOB.timer" -p ActiveState -p WakeSystem -p NextElapseUSecMonotonic -p AccuracyUSec
sudo stat -c '%s %b %B %u %a' "/var/lib/orchestrator-builder/host/$JOB.raw"
```

Use `MainPID` only after independently checking it is this exact unit. Inspect
its children under `/proc`: QEMU must have the configured nonzero UID/GID,
the KVM group, no effective capabilities, only the expected raw-disk FD and KVM
devices; its command line must have KVM only, no NIC or management socket.
Check `/proc/QEMU_PID/ns/net` differs from the host. Do not dump process
environments or unrelated credential files into evidence.

| Cases | Required action and passing observation |
|---|---|
| V01–V03 | Boot the approved idle fixture; independently prove guest boot via fixture changes to a predetermined raw-disk sector, read that sector with bounded `dd` after shutdown (no host filesystem mount). Repeat with a new job: clean original sector, new disk inode. In a separate empty lab root, alter one image byte without updating its pin: create fails before QEMU launch and owned partial disk is cleaned. Check QEMU KVM FD and non-root identity; reject any TCG fallback. |
| V04 | Start real API+guard using test-only mTLS identities and exercise the existing create/release contract: duplicate command, nonce conflict, changed expiry, wrong controller, and cleaned-job replay. Record statuses and exactly one QEMU PID/disk. Repeat software mTLS negatives; do not disable verification. |
| V05 | Fixture launches four CPU-bound loops for 60 seconds. Sample `cpu.stat` over a 20-second interval: aggregate use <= 40 CPU-seconds plus predeclared 10% measurement tolerance; `nr_throttled` increases and control services stay responsive. |
| V06 | Fixture allocates/touches more than guest RAM, with a fixed 30-second workload timeout. Verify bounded guest/QEMU failure or reclamation, `memory.peak <= 4831838208`, `memory.swap.current=0`, no host OOM outside this group, guard still responsive. Do not run host memory stress. |
| V07 | Fixture uses bounded direct 4 KiB random writes at queue depth 32 for 30 seconds (reviewed fio included in the fixture). Measure completed operations inside the fixture and write result to its predetermined result sector; <= 1000/s plus a predeclared 10% observation/burst tolerance over the full interval. Separately write to end-of-disk: capacity 10737418240 bytes, writes beyond it fail. Host allocated disk blocks <=11264 MiB, allocation was reserved before launch, no extra writable files/backing chain; no host ENOSPC. `io.stat` alone does not prove IOPS. |
| V08 | Inspect `pids.max=128`; run a bounded guest runner fixture that attempts 520 children in its guest `pids.max=512` cgroup and records rejection. Never run a fork bomb. Explicitly record that guest root can change this guest limit, but cannot affect host `pids.max`. |
| V09–V10 | Already covered with no controller/API/guard and a frozen supervisor by the real-host expiry test. Additionally create through API then SIGKILL only these test API/guard services; immutable expiry still kills VM, stale guard denies admission after 10s. Restart and confirm ledger reconciliation/no duplicate. |
| V11 | `TestLinuxHostDelayedStartCannotResurrect` automatically adds an exact lab-owned 10-second ExecStartPre delay, releases while starting, restarts the unit after cleanup and waits 12 seconds. It requires no active unit/populated cgroup/ready marker and removes only its own drop-in. Retain its successful log and final inventory. |
| V12 | On a separate dedicated test filesystem force disk allocation failure by a known insufficient capacity (do not fill the OS filesystem). Then inject cleanup failure with an exact job-owned file changed to an unrecognized inode: cleanup fails and ledger slot stays held. Restore the saved exact owned inode and retry: cleanup succeeds. Inject process death after reserve/allocation/start using local test instrumentation; restart recovers all owned resources. Preserve instrumentation diff/hash and all failures. |
| V13 | Automated foreign disk case must pass. Additionally create a throwaway **foreign systemd unit** colliding with a test job name but with a different Description; Create/Cleanup must refuse to stop it. Stop/remove only the exact test canary you created afterwards. |
| V14 | Only in isolated outer-VM snapshot: disable time sync temporarily, move wall clock forward/back after admission, restore it afterwards. Independent expiry remains tied to boot time. Make only the private test ledger unavailable after admission; existing VM expires despite ledger failure; no false CLEANED. Interrupt private metadata `.new` writes: corrupted/unconfirmed state quarantines capacity, never removes a foreign disk. Reboot: no transient VM restarts and old boot-ID state refuses launch. |
| V15–V16 | Verify no guest network device and distinct network namespace, no host mounts/sockets/credentials; review current kernel/QEMU CVEs. Compare final inventory below to baseline: no running owned QEMU, populated owned cgroup, active timer, `.raw` or `.ready`; foreign resources unchanged. Inactive unit metadata and root-owned fenced JSON tombstones are expected, not reusable VM artifacts. |

The load fixtures and local fault-injection variation are part of the acceptance
evidence and must be reviewed before privileged execution. An unavailable fixture
or unexecuted variation is **BLOCKED**, not waived. Clock/suspend/frozen-host
residual risk remains: a failed kernel/PID1 cannot guarantee timely termination.

## 5. Final inventory and mandatory decision

```bash
sudo systemctl list-units --all 'orchestrator-build-*' 'orchestrator-expiry-*' | tee "$EVIDENCE/units-after.txt"
sudo find /var/lib/orchestrator-builder/host -maxdepth 1 -type f -printf '%f %s\n' | tee "$EVIDENCE/artifacts-after.txt"
```

Fill [the acceptance report](P1-M04-acceptance-report.md), including every V01–V16
log, observed timing and review/sign-off. **M04 MUST NOT be marked PASS unless
this procedure has actually run successfully on Linux and every mandatory case
has passed.** No Linux runtime acceptance has been performed on the Windows
development host. Do not enable untrusted repository work under M04 acceptance;
M05 networking and later build/runtime gates remain separate.
