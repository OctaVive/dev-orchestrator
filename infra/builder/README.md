# Debian/Linux KVM builder host — acceptance required

The explicit `linux-kvm` backend uses QEMU directly under systemd, not libvirt.
This avoids an asynchronous libvirt start outside the lifetime/ownership unit.
KVM remains mandatory. There is no emulation, DinD, container or local-build
fallback. **M04 is NOT PASSED until the mandatory Linux acceptance run succeeds.**

## Operator-approved lab setup

### Staged acceptance helper

For a **fresh disposable VM**, the opt-in automatic setup installs required apt
packages, creates the dedicated account/storage, builds and installs binaries,
builds/pins the idle fixture, writes the backend configuration, and runs the four
automated real-host tests:

```bash
export PATH="$HOME/.local/opt/go1.27.3/go/bin:$PATH" # if installed here
python3 infra/builder/m04-auto-lab.py --configure-and-test
```

Run as a normal user with sudo available, after reviewing the scripts. Requires
Go satisfying go.mod, at least four vCPUs/~8 GiB RAM/30 GiB free storage, nested
KVM access, and a running kernel with its boot image and matching modules.
Refuses physical hosts and existing builder installations; partial failures
retain files and logs for review (use a fresh VM snapshot to retry). Packages,
image-build files and ownership tombstones remain installed; no global cleanup
or production API/guard service enablement occurs. This automates only the four
host cases, **not full M04 acceptance** or the destructive/manual fault matrix.

Run `bash infra/builder/m04-acceptance.sh` for usage. As your normal user:

```bash
export EVIDENCE="$(mktemp -d "$HOME/m04-evidence.XXXXXX")"
export PATH="$HOME/.local/opt/go1.27.3/go/bin:$PATH" # if installed here
bash infra/builder/m04-acceptance.sh preflight
bash infra/builder/m04-acceptance.sh build
```

The build prints the exact private binary directory. Review and install those
binaries using the setup below, prepare/pin the fixture image and configuration,
then **inside the approved disposable lab VM only** run:

```bash
M04_DISPOSABLE_HOST=YES-I-AUTHORIZE-REAL-KVM \
  bash infra/builder/m04-acceptance.sh host-tests
```

Each invocation retains a separate log and exit code under `$EVIDENCE`. The
helper never installs packages, creates accounts, changes configuration, or
enables services. It refuses host tests outside a detected VM and rejects unsafe
installed executable/config paths. VM detection is not proof the lab is safe:
the operator must still approve its isolation. It does not automate or waive the
remaining V01–V16 workload/fault matrix or acceptance sign-off.

Read [the mandatory procedure](../../docs/testing/P1-M04-real-host.md) first.
Commands below install files/services and reserve real disk/RAM. Run only after
approving a dedicated Debian-family lab. Nothing is installed automatically.
Use maintained systemd/QEMU packages; nested KVM, alarm timers and cgroup v2 must
work. This first backend is x86-64 only (Q35/BIOS, virtio disk).

1. As a normal user, build/review `cmd/provisioner` and the host test binary as
   described in the procedure. Record source and binary hashes.
2. Install maintained `qemu-system-x86`, `qemu-utils` and `systemd` through your
   approved package process. No libvirt daemon or default NAT network is needed.
3. Create a **dedicated, non-login, non-root** QEMU account. Do not reuse an
   administrator/runtime account or allow any other service to run as this user.

```bash
sudo adduser --system --group --no-create-home --home /nonexistent --shell /usr/sbin/nologin orchestrator-qemu
id orchestrator-qemu
stat -c '%g %a %n' /dev/kvm
sudo install -d -m 0700 /var/lib/orchestrator-builder
sudo install -d -m 0700 /var/lib/orchestrator-builder/host /var/lib/orchestrator-builder/images /var/lib/orchestrator-builder/ledger
sudo install -d -m 0755 /usr/local/sbin /usr/local/libexec
sudo install -o root -g root -m 0755 "$EVIDENCE/bin/orchestrator-provisioner" /usr/local/sbin/orchestrator-provisioner
sudo install -o root -g root -m 0755 "$EVIDENCE/bin/m04-host.test" /usr/local/libexec/m04-host.test
```

4. Prepare/review a credential-free BIOS raw image, 512 bytes–1 GiB, with a
   virtio-capable kernel and guest cgroup-v2 runner limit 512. Use a reproducible
   trusted Debian image build, record package manifests and SHA-256, remove all
   credentials/SSH host keys/machine identity and disable networking. This is an
   operator-supplied image: **no opaque prebuilt image is downloaded or trusted
   by this repository**. No login credential is required for the automatic lab
   fixtures. `build-lab-fixture.sh` supplies a transparent BIOS/BusyBox fixture
   recipe (idle/CPU/memory/IO/PID modes), not a production builder image. It uses
   only installed trusted Debian kernel/packages and a newly allocated loop
   device; its exact mount/loop are released and build files retained. Review
   before running as root; see the acceptance procedure. M05/build-runner
   capabilities are not implied by a bootable image.
5. Install that exact raw image at the example image path, root:root mode 0600.
   Hash the installed file, independently compare to approved output. Copy
   `backend.example.json`, replace digest/UID/GID/KVMGID with actual values
   (`getent group kvm` / device stat); install as
   `/var/lib/orchestrator-builder/host/backend.json`, root:root 0600. The numeric
   examples are **not defaults**. All paths and ancestors must be root-owned,
   non-writable by other accounts and contain no symlinks. No spaces, `%` or shell
   substitutions in host paths. Never put the root under `/home` or `/tmp`.
6. Run the complete acceptance procedure **before enabling services**. Tests do
   not need service certificates. Keep evidence and private tombstones. Initial
   image hashing/copy/preallocation must finish within the 20-second operation
   budget; slow/full storage is a failure, not a reason to weaken limits.

## Services (after approved testing)

The supplied API and guard units run as root because they mediate systemd and
drop QEMU to the dedicated UID. The host is a separate security boundary; never
install this privileged service in the portal/runtime VM. The controller has
only mTLS RPC authority, not SSH or systemd access. Keep the dedicated ledger
separate from management data and guest artifacts. Both API and guard must use
the exact same root-owned configuration/ledger.

Provision test/production PKI separately: dedicated controller client CA,
short-lived <=24-hour controller client certificate with exact URI SAN and
clientAuth EKU, pin its leaf digest; private provisioner server key mode 0600.
Place CA/server/key at the paths in `orchestrator-builder-api.service` and a
root-owned 0600 `/etc/orchestrator-builder/controller.env` containing only
`CONTROLLER_ID=<uuid>` and `CONTROLLER_CERT_SHA256=<hex leaf SHA256>`.
No key is copied into any guest. Listener remains literal loopback; remote
network rollout requires a separately authenticated/approved transport design,
not a public bind or an unauthenticated proxy. Rotate leaves/pins explicitly.

```bash
sudo install -o root -g root -m 0644 infra/builder/orchestrator-builder-guard.service infra/builder/orchestrator-builder-api.service /etc/systemd/system/
sudo systemctl daemon-reload
# Only after acceptance, PKI review and explicit service-enable approval:
sudo systemctl enable --now orchestrator-builder-guard.service orchestrator-builder-api.service
```

No service automatically asserts M04 PASS. Default CLI backend is still disabled;
`-backend simulator` and all unknown backends fail. Non-Linux fails closed.

## Enforcement and recovery

- Every lease has durable boot-ID/absolute CLOCK_BOOTTIME deadline and private
  ownership proof. One global flock serializes host create/cleanup/start checks.
  Root-owned JSON is fsync+rename+directory-fsync; fenced journals are permanent.
- Each guest has a separate systemd service: 200% CPU, 4608 MiB host memory,
  zero swap, 128 tasks; QEMU has 2 vCPUs/4096 MiB, a 10 GiB preallocated raw disk
  (not sparse COW), a 10 GiB file-size ceiling and total 1000 IOPS block throttle.
  Fixed-size raw storage replaces project quotas: maximum guest writes cannot
  grow a backing chain/file beyond the physical 11264 MiB envelope. Metadata is
  bounded and no serial log, core dump, snapshot or disk backing chain exists.
- Private host network namespace and `-nic none`; no control socket, guest
  agent, shared filesystem or host path arguments. Disk uses an inherited FD set;
  QEMU does not need access to the private journal/template directories.
- QEMU runs unprivileged with seccomp sandbox, no capabilities or writable host
  tree. Supervisor privilege is limited to SETUID/SETGID in the guest unit.
  PID-1 `RuntimeMaxSec`, independent absolute boot-time alarm timer, and timerfd
  supervisor enforce lifetime. Guard/API/controller failure cannot renew it.
- Expiry verifies ownership before killing the exact unit; cleanup additionally
  verifies empty cgroup and inode/device/link identities before removing the
  exact `.raw`/`.ready` files. No recursive deletion. Foreign collisions,
  interrupted unknown files, or unverifiable state quarantine capacity.
- A kernel/PID1/hypervisor failure cannot guarantee deadlines. CLOCK_BOOTTIME
  counts suspend and fires on resume; guest cannot run while host is suspended.
  The reviewed image must configure the 512 guest runner PID limit: host task
  limits do not count malicious guest-root processes.

Stop only the API/guard to disable admission; existing guests still expire via
their independent units. For emergency release use authenticated release or
wait for hard expiry, then guard reconciliation. Do not delete ledger/state,
change image/config/executable in flight, kill unrelated QEMU processes, globally
prune systemd/libvirt/Docker, or remove unknown paths. On failed cleanup preserve
private proofs and exact inventory for operator review. A leftover `.new`, bad
journal or inode mismatch is intentionally fail-closed; repair only after a
verified backup and proof that the exact owned guest is absent. Fenced JSON and
inactive systemd unit metadata are expected retained audit/fence artifacts.

Rollback: disable these two named service units, wait for/confirm all exact
owned guests and timers to stop, preserve ledger/tombstones/evidence, then
replace only reviewed binaries/config. Do not erase fencing history or reuse a
job ID. No automated existing-ledger upgrade is provided.
