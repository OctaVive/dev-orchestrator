#!/usr/bin/env bash
# Run from a reviewed checkout. Never run this script itself as root.
set -euo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
usage() {
  cat <<'EOF'
Usage: bash infra/builder/m04-acceptance.sh preflight|build|host-tests

EVIDENCE must name an existing private directory outside the checkout.
Create one with: export EVIDENCE="$(mktemp -d "$HOME/m04-evidence.XXXXXX")"
Requires Go >= go.mod and GOTOOLCHAIN=local for builds.

preflight   Read-only host inventory; does not boot a guest.
build       Build production/test binaries as normal user and record hashes.
host-tests  Run installed real-KVM tests via sudo in an approved disposable VM.
            Requires M04_DISPOSABLE_HOST=YES-I-AUTHORIZE-REAL-KVM.

This helper does NOT install packages, accounts, images, configuration or services.
Follow infra/builder/README.md for reviewed privileged setup.
Four host tests are only a subset of V01–V16: never infer M04 PASS from this script.
EOF
}
[[ ${1:-} =~ ^(preflight|build|host-tests)$ && $# == 1 ]] || { usage; exit 2; }
[[ $(id -u) != 0 ]] || { echo 'Run as normal user, not root.' >&2; exit 1; }
: "${EVIDENCE:?Create/export a private evidence directory first; see --help}"
[[ -d $EVIDENCE && ! -L $EVIDENCE ]] || { echo 'Invalid evidence directory.' >&2; exit 1; }
EVIDENCE="$(realpath -- "$EVIDENCE")"
[[ $EVIDENCE != "$ROOT" && $EVIDENCE != "$ROOT/"* ]]
[[ $(stat -c %u "$EVIDENCE") == $(id -u) && $(stat -c %a "$EVIDENCE") == 700 ]] || {
  echo 'Evidence directory must be owned by you, mode 0700.' >&2; exit 1;
}
RUN="$(mktemp -d "$EVIDENCE/${1}.XXXXXX")"
exec > >(tee "$RUN/output.txt") 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$RUN/exit-code.txt"' EXIT
echo "Evidence: $RUN"
date -u
git rev-parse HEAD
git status --short
export GOTOOLCHAIN=local

case $1 in
  preflight)
    [[ $(uname -m) == x86_64 ]]
    id
    cat /etc/os-release
    uname -a
    virt="$(systemd-detect-virt || true)"; echo "Virtualization: $virt"
    lscpu
    free -h
    df -h "$EVIDENCE"
    findmnt -T "$EVIDENCE" -o TARGET,SOURCE,FSTYPE,OPTIONS
    [[ $(stat -fc %T /sys/fs/cgroup) == cgroup2fs ]]
    [[ $(cat /proc/1/comm) == systemd ]]
    [[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]
    qemu-system-x86_64 --version
    qemu-img --version
    qemu-system-x86_64 -accel help
    echo 'Prerequisites inspected; guest boot and enforcement NOT proven.'
    ;;
  build)
    mkdir -m 700 "$RUN/bin" "$RUN/tmp"
    export TMPDIR="$RUN/tmp" CGO_ENABLED=0
    go version
    go mod download
    go mod verify
    go build -o "$RUN/bin/orchestrator-provisioner" ./cmd/provisioner
    go test -c -o "$RUN/bin/m04-host.test" ./internal/provisioner
    sha256sum "$RUN/bin/orchestrator-provisioner" "$RUN/bin/m04-host.test" | tee "$RUN/binary-digests.txt"
    echo 'Review these exact binaries before privileged installation. See infra/builder/README.md.'
    ;;
  host-tests)
    [[ ${M04_DISPOSABLE_HOST:-} == YES-I-AUTHORIZE-REAL-KVM ]] || {
      echo 'Explicit disposable-lab authorization required.' >&2; exit 1;
    }
    virt="$(systemd-detect-virt --vm || true)"
    [[ -n $virt && $virt != none ]] || {
      echo 'Refusing fault tests outside a detected VM. Use a disposable lab VM.' >&2; exit 1;
    }
    [[ $(cat /proc/1/comm) == systemd && $(stat -fc %T /sys/fs/cgroup) == cgroup2fs ]]
    [[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]
    # Validate root ownership and non-writability of every installed path component.
    sudo python3 - <<'PY'
import os, pathlib, stat
for name in ['/usr/local/libexec/m04-host.test', '/usr/local/sbin/orchestrator-provisioner', '/var/lib/orchestrator-builder/host/backend.json']:
    p = pathlib.Path(name)
    for part in [p, *p.parents]:
        s = part.lstat()
        if stat.S_ISLNK(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise SystemExit('Unsafe installed path: ' + str(part))
    if not p.is_file():
        raise SystemExit('Not a regular file: ' + name)
PY
    sudo sha256sum /usr/local/libexec/m04-host.test /usr/local/sbin/orchestrator-provisioner
    inventory() {
      sudo systemctl list-units --all 'orchestrator-build-*' 'orchestrator-expiry-*'
      sudo find /var/lib/orchestrator-builder/host -maxdepth 1 -type f -printf '%f %s\n'
    }
    inventory | tee "$RUN/inventory-before.txt"
    set +e
    sudo env M04_DISPOSABLE_HOST=YES-I-AUTHORIZE-REAL-KVM \
      M04_HOST_CONFIG=/var/lib/orchestrator-builder/host/backend.json \
      /usr/local/libexec/m04-host.test -test.v -test.count=1 \
      -test.run '^TestLinuxHost' -test.timeout=5m 2>&1 | tee "$RUN/real-host-tests.txt"
    rc=${PIPESTATUS[0]}
    set -e
    inventory | tee "$RUN/inventory-after.txt"
    [[ $rc == 0 ]]
    ! grep -q -- '--- SKIP:' "$RUN/real-host-tests.txt"
    for test in TestLinuxHostLifecycleAndKernelEnvelope TestLinuxHostExpiryWithFrozenSupervisor TestLinuxHostForeignDiskIsRetained TestLinuxHostDelayedStartCannotResurrect; do
      grep -q -- "--- PASS: $test " "$RUN/real-host-tests.txt"
    done
    echo 'Four automated host cases passed. V01–V16 matrix and acceptance sign-off STILL REQUIRED.'
    ;;
esac
