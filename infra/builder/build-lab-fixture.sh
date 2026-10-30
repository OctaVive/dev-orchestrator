#!/bin/bash
# Trusted Debian host tools only. This creates a NEW loop-backed BIOS image;
# never use it to mount a guest-modified disk. Review before privileged execution.
set -euo pipefail
umask 077
[[ ${M04_IMAGE_BUILD:-} == YES-I-AUTHORIZE-LOOP-IMAGE && $EUID == 0 ]] || {
  echo 'Requires root and M04_IMAGE_BUILD=YES-I-AUTHORIZE-LOOP-IMAGE' >&2; exit 1;
}
MODE=${1:-idle}
case "$MODE" in idle|cpu|memory|io|pids|egress|clone|m07|build|ingest) ;; *) exit 1;; esac
for tool in busybox grub-install sfdisk losetup mkfs.ext4 mount umount cpio gzip modprobe ldd; do
  command -v "$tool" >/dev/null
done
busybox true
# Require Debian busybox-static, not a dynamically linked executable.
if ldd /usr/bin/busybox 2>&1 | grep -q '=>'; then echo 'Install busybox-static' >&2; exit 1; fi
KERNEL=$(uname -r)
[[ -f /boot/vmlinuz-$KERNEL && -d /lib/modules/$KERNEL/kernel ]]
BASE=/var/lib/orchestrator-builder/image-build
# Ancestors must be root-owned, non-symlink and not writable by other users.
python3 - "$BASE" <<'PY'
import os, stat, sys
p=sys.argv[1]
create=not os.path.lexists(p)
if create: p=os.path.dirname(p)
while True:
    s=os.lstat(p)
    assert s.st_uid == 0 and not s.st_mode & 0o022 and not stat.S_ISLNK(s.st_mode)
    if p == '/': break
    p=os.path.dirname(p)
if create: os.mkdir(sys.argv[1], 0o700)
assert os.stat(sys.argv[1]).st_mode & 0o077 == 0
PY
WORK=$(mktemp -d "$BASE/fixture.XXXXXXXX")
IMAGE=$WORK/fixture.raw
MNT=$WORK/mount
ROOT=$WORK/initramfs
mkdir -m 0700 "$MNT" "$ROOT"
LOOP=
MOUNTED=0
finish() {
  local rc=$?
  if [[ $MOUNTED == 1 ]]; then umount "$MNT" || rc=1; fi
  if [[ -n $LOOP ]]; then losetup -d "$LOOP" || rc=1; fi
  echo "Build directory retained: $WORK (exit $rc)"
  exit "$rc"
}
trap finish EXIT
fallocate -l 768M "$IMAGE"
printf 'label: dos\nstart=2048,type=83,bootable\n' | sfdisk "$IMAGE"
LOOP=$(losetup --find --show --partscan "$IMAGE")
for n in {1..50}; do [[ -b ${LOOP}p1 ]] && break; sleep .1; done
[[ -b ${LOOP}p1 ]]
mkfs.ext4 -F -L M04_FIXTURE "${LOOP}p1"
mount -o nodev,nosuid,noexec "${LOOP}p1" "$MNT"
MOUNTED=1
mkdir -p "$MNT/boot/grub" "$ROOT/bin" "$ROOT/sbin" "$ROOT/proc" "$ROOT/sys" "$ROOT/dev" "$ROOT/run" "$ROOT/lib/modules/$KERNEL"
cp /boot/vmlinuz-"$KERNEL" "$MNT/boot/vmlinuz"
cp -L /usr/bin/busybox "$ROOT/bin/busybox"
for name in sh mount mkdir sleep yes kill dd cat awk sync wc timeout nc head tail; do ln -s busybox "$ROOT/bin/$name"; done
copy_binary() {
  local src=$1 dest=$2 lib
  cp -L "$src" "$ROOT/$dest"
  while read -r lib; do
    [[ -f $lib ]] || continue
    mkdir -p "$ROOT/$(dirname "$lib")"
    cp -L "$lib" "$ROOT/$lib"
  done < <(ldd "$src" | awk '/=> \//{print $3} /^[[:space:]]*\//{print $1}')
}
copy_binary "$(command -v modprobe)" sbin/modprobe
if [[ $MODE == clone || $MODE == build ]]; then
  # Clone needs only virtio dependencies, not the host's entire driver tree.
  for module in virtio_pci virtio_blk virtio_net; do
    while read -r lib; do cp --parents "$lib" "$ROOT/"; done < <(modprobe --show-depends "$module" | awk '/^insmod /{print $2}')
  done
  cp /lib/modules/"$KERNEL"/modules.builtin* /lib/modules/"$KERNEL"/modules.order "$ROOT/lib/modules/$KERNEL/"
  depmod -b "$ROOT" "$KERNEL"
else
  cp -a /lib/modules/"$KERNEL"/kernel "$ROOT/lib/modules/$KERNEL/"
  cp /lib/modules/"$KERNEL"/modules.* "$ROOT/lib/modules/$KERNEL/"
fi
if [[ $MODE == io ]]; then copy_binary /usr/bin/fio bin/fio; fi
if [[ $MODE == clone || $MODE == build ]]; then
  [[ -f ${M06_CA_CERT:-} && -x ${M06_RUNNER:-} ]]
  openssl x509 -in "$M06_CA_CERT" -noout >/dev/null
  if grep -q 'PRIVATE KEY' "$M06_CA_CERT"; then exit 1; fi
  mkdir -p "$ROOT/usr/bin" "$ROOT/usr/lib/git-core" "$ROOT/work" "$ROOT/etc"
  cp "$M06_CA_CERT" "$ROOT/build-ca.pem"
  cp "$M06_RUNNER" "$ROOT/bin/clone-runner"
  if [[ -n ${M08_TESTS:-} ]]; then cp "$M08_TESTS" "$ROOT/bin/config-tests"; fi
  copy_binary /usr/bin/git usr/bin/git
  copy_binary /usr/lib/git-core/git-remote-https usr/lib/git-core/git-remote-https
  copy_binary /usr/bin/ip bin/ip
  printf 'root:x:0:0:root:/:/bin/sh\nrunner:x:1000:1000:runner:/work:/bin/false\nscanner:x:1001:1001:scanner:/scan-work:/bin/false\n' > "$ROOT/etc/passwd"
  printf 'root:x:0:\nrunner:x:1000:\n' > "$ROOT/etc/group"
  copy_binary /usr/bin/setpriv bin/runner-identity
  for name in chown chmod false; do ln -s busybox "$ROOT/bin/$name"; done
  { /usr/bin/git --version; dpkg-query -W git libcurl3t64-gnutls ca-certificates; sha256sum "$M06_RUNNER"; } > "$WORK/clone-packages.txt"
fi
if [[ $MODE == m07 || $MODE == build ]]; then
  [[ -d ${M07_TOOLS:-}/buildkit/bin && -x ${M07_TOOLS:-}/uidmap/usr/bin/rootlesskit ]]
  mkdir -p "$ROOT/usr/bin" "$ROOT/etc" "$ROOT/work" "$ROOT/dev/pts" "$ROOT/tmp"
  for binary in buildkitd buildctl buildkit-runc; do cp "$M07_TOOLS/buildkit/bin/$binary" "$ROOT/usr/bin/"; done
  if [[ $MODE == build && ${M07_BUILD_DEBUG:-} == YES ]]; then
    mv "$ROOT/usr/bin/buildctl" "$ROOT/usr/bin/buildctl-real"
    cat > "$ROOT/usr/bin/buildctl" <<'DEBUG'
#!/bin/sh
/usr/bin/buildctl-real "$@" > /work/build-diagnostic 2>&1
rc=$?
head -c 49152 /work/build-diagnostic | dd of=/dev/vda bs=512 seek=20971390 conv=notrunc,fsync
cat /work/build-diagnostic
exit "$rc"
DEBUG
    chmod 0755 "$ROOT/usr/bin/buildctl"
  fi
  copy_binary "$M07_TOOLS/uidmap/usr/bin/rootlesskit" usr/bin/rootlesskit
  copy_binary "$M07_TOOLS/uidmap/usr/bin/newuidmap" usr/bin/newuidmap
  copy_binary "$M07_TOOLS/uidmap/usr/bin/newgidmap" usr/bin/newgidmap
  chmod 4755 "$ROOT/usr/bin/newuidmap" "$ROOT/usr/bin/newgidmap"
  copy_binary /usr/bin/setpriv usr/bin/setpriv
  printf 'root:x:0:0:root:/:/bin/sh\nrunner:x:1000:1000:runner:/work:/bin/sh\n' > "$ROOT/etc/passwd"
  printf 'root:x:0:\nrunner:x:1000:\n' > "$ROOT/etc/group"
  for name in chown chmod env seq; do ln -sf busybox "$ROOT/bin/$name"; done
  cp "$(dirname "$0")/../build/guest-init.sh" "$ROOT/bin/m07-init"
fi
if [[ $MODE == ingest ]]; then
  [[ -x ${M07_INGEST_RUNNER:-} && -x ${M07_INGEST_TESTS:-} && -f ${M07_TOOLS:-}/cache/db/trivy.db ]]
  mkdir -p "$ROOT/usr/bin" "$ROOT/etc" "$ROOT/work" "$ROOT/tmp" "$ROOT/scan-cache/db"
  cp "$M07_TOOLS/trivy/trivy" "$ROOT/usr/bin/trivy"
  # The large pinned database is attached read-only as /dev/vdd.
  cp "$M07_INGEST_RUNNER" "$ROOT/bin/ingest-runner"
  cp "$M07_INGEST_TESTS" "$ROOT/bin/ingest-tests"
  copy_binary /usr/bin/setpriv bin/runner-identity
  printf 'root:x:0:0:root:/:/bin/sh\nrunner:x:1000:1000:runner:/work:/bin/false\nscanner:x:1001:1001:scanner:/scan-work:/bin/false\n' > "$ROOT/etc/passwd"
  printf 'root:x:0:\nrunner:x:1000:\n' > "$ROOT/etc/group"
  for name in chown chmod; do ln -s busybox "$ROOT/bin/$name"; done
fi
if [[ $MODE == egress ]]; then
  [[ -f ${M05_CA_CERT:-} && ${M05_PROBE_HOST:-} =~ ^[a-z0-9][a-z0-9.-]+[a-z0-9]$ && ${M05_CONTROL_IP:-} =~ ^[0-9.]+$ ]]
  # Only the public build CA is installed. Never copy its private signing key.
  openssl x509 -in "$M05_CA_CERT" -noout -text >/dev/null
  if grep -q 'PRIVATE KEY' "$M05_CA_CERT"; then exit 1; fi
  cp "$M05_CA_CERT" "$ROOT/build-ca.pem"
  printf '%s\n' "$M05_PROBE_HOST" > "$ROOT/egress-host"
  printf '%s\n' "$M05_CONTROL_IP" > "$ROOT/egress-control-ip"
  copy_binary /usr/bin/curl bin/curl
  copy_binary /usr/bin/ip bin/ip
  cp "$(dirname "$0")/../egress/guest-probes.sh" "$ROOT/bin/m05-probes"
  chmod 0755 "$ROOT/bin/m05-probes"
  if [[ ${M05_CONTROLLED:-} == YES ]]; then printf 'yes\n' > "$ROOT/egress-controlled"; fi
  if [[ -n ${M05_RAW_PROBE:-} ]]; then cp "$M05_RAW_PROBE" "$ROOT/bin/m05-raw-probe"; chmod 0755 "$ROOT/bin/m05-raw-probe"; fi
fi

printf '%s\n' "$MODE" > "$ROOT/fixture-mode"
cat > "$ROOT/init" <<'INIT'
#!/bin/sh
export PATH=/bin:/sbin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts
mount -t tmpfs tmpfs /run
mkdir -p /sys/fs/cgroup
mount -t cgroup2 none /sys/fs/cgroup
echo +pids +memory +cpu > /sys/fs/cgroup/cgroup.subtree_control
mkdir /sys/fs/cgroup/runner
echo 512 > /sys/fs/cgroup/runner/pids.max
echo +pids +memory +cpu > /sys/fs/cgroup/runner/cgroup.subtree_control
mkdir /sys/fs/cgroup/runner/workload /sys/fs/cgroup/runner/config-parser
echo 134217728 > /sys/fs/cgroup/runner/config-parser/memory.max
echo 0 > /sys/fs/cgroup/runner/config-parser/memory.swap.max
echo 32 > /sys/fs/cgroup/runner/config-parser/pids.max
echo "100000 100000" > /sys/fs/cgroup/runner/config-parser/cpu.max
# Delegation permits migration only within runner; its populated internal node
# cannot accept processes while controllers are enabled.
chown 1000:1000 /sys/fs/cgroup/runner/cgroup.procs /sys/fs/cgroup/runner/config-parser/cgroup.procs
modprobe virtio_pci
modprobe virtio_blk
MODE=$(cat /fixture-mode)
for n in 1 2 3 4 5; do [ -b /dev/vda ] && break; sleep 1; done
result() { printf 'M04-FIXTURE %s\n' "$*" | dd of=/dev/vda bs=512 seek=20971519 count=1 conv=notrunc,fsync; }
result "BOOT mode=$MODE runner_pids=$(cat /sys/fs/cgroup/runner/pids.max)"
case "$MODE" in
  clone|build)
    result CLONE-BOOT
    modprobe virtio_net
    ip link set eth0 address 02:00:00:00:00:02
    ip addr add 192.0.2.2/30 dev eth0
    ip link set eth0 up
    ip link set lo up
    mkdir -p /run/orchestrator-clone-worker /work
    runner_extra=--no-new-privs
    if [ "$MODE" = build ]; then
      runner_extra=
      mkdir -p /run/orchestrator-build-worker /run/user/1000 /tmp
      chmod 0755 /run/orchestrator-build-worker
      chown 1000:1000 /run/user/1000
      chmod 0700 /run/user/1000
      chmod 1777 /tmp
      if [ -e /usr/bin/buildctl-real ]; then chown 1000:1000 /dev/vda; fi
      mount -t devpts devpts /dev/pts
      mount --make-rprivate /
      printf 'runner:100000:65536\n' > /etc/subuid
      printf 'runner:100000:65536\n' > /etc/subgid
    fi
    chmod 0755 /run/orchestrator-clone-worker
    mount -t tmpfs -o size=2300m,nodev,nosuid tmpfs /work
    chown 1000:1000 /work
    chmod 0700 /work
    # The job device is sealed/read-only at the host; the guest user only reads.
    chown 1000:1000 /dev/vdb /dev/ttyS1
    chmod 0600 /dev/vdb /dev/ttyS1
    echo $$ > /sys/fs/cgroup/runner/workload/cgroup.procs
    # Env injection is intentional: the runner must discard all inherited Git
    # settings, including helper/proxy/loader inputs, before invoking Git.
    mkdir -p /work/hooks
    printf '[credential]\n helper = !touch /work/helper-ran\n[core]\n hooksPath = /work/hooks\n[filter "evil"]\n smudge = touch /work/filter-ran\n[url "ext::sh -c false"]\n insteadOf = https://\n[submodule]\n recurse = true\n' > /work/poison
    printf '#!/bin/sh\ntouch /work/hook-ran\n' > /work/hooks/post-checkout
    chmod 0755 /work/hooks/post-checkout
    if [ -x /bin/config-tests ]; then
      (
      M08_GUEST_TESTS=1 TMPDIR=/work /bin/runner-identity --reuid=1000 --regid=1000 --clear-groups --no-new-privs /bin/config-tests -test.v -test.run '^TestGuest' > /run/config-tests.log 2>&1
      m08_tests=$?
      M08_GUEST_TESTS=1 TMPDIR=/work /bin/runner-identity --reuid=1000 --regid=1000 --clear-groups --no-new-privs /bin/config-tests -test.run '^$' -test.fuzz '^FuzzGuestCompose$' -test.fuzztime 3s -test.fuzzcachedir /work/config-fuzz -test.parallel 1 >> /run/config-tests.log 2>&1
      m08_yaml=$?
      M08_GUEST_TESTS=1 TMPDIR=/work /bin/runner-identity --reuid=1000 --regid=1000 --clear-groups --no-new-privs /bin/config-tests -test.run '^$' -test.fuzz '^FuzzGuestDockerfile$' -test.fuzztime 3s -test.fuzzcachedir /work/dockerfile-fuzz -test.parallel 1 >> /run/config-tests.log 2>&1
      m08_dockerfile=$?
      echo "M08-GUEST-EXIT tests=$m08_tests yaml=$m08_yaml dockerfile=$m08_dockerfile" >> /run/config-tests.log
      head -c 262144 /run/config-tests.log | dd of=/dev/vda bs=512 seek=20970000 conv=notrunc,fsync
      ) &
    fi
    result CLONE-RUNNER-START
    GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=credential.helper GIT_CONFIG_VALUE_0='!touch /work/helper-ran' \
      GIT_CONFIG_GLOBAL=/work/poison GIT_EXEC_PATH=/work HTTPS_PROXY=http://127.0.0.1:9 \
      /bin/runner-identity --reuid=1000 --regid=1000 --clear-groups $runner_extra /bin/clone-runner 2>/run/clone-error
    rc=$?
    context_check=not-applicable
    if [ "$rc" = 0 ]; then
      context_dir=$(tail -n 1 /work/context-ready)
      context_check=PASS
      [ "$(cat "$context_dir/Dockerfile")" = 'FROM scratch' ] || context_check=FAIL
      [ ! -e "$context_dir/.git" ] || context_check=FAIL
      if [ -e "$context_dir/run.sh" ]; then [ -x "$context_dir/run.sh" ] || context_check=FAIL; fi
      if [ -L "$context_dir/link" ]; then [ "$(cat "$context_dir/link")" = 'bounded clone fixture' ] || context_check=FAIL; fi
    fi
    helper=absent; filter=absent; hook=absent
    [ -e /work/helper-ran ] && helper=RAN
    [ -e /work/filter-ran ] && filter=RAN
    [ -e /work/hook-ran ] && hook=RAN
    result "CLONE-EXIT status=$rc helper=$helper filter=$filter hook=$hook context_check=$context_check diagnostic=$(head -c 128 /run/clone-error)"
    ;;
  ingest)
    mkdir -p /run/orchestrator-ingest-worker /work
    modprobe ext4
    for n in 1 2 3 4 5; do [ -b /dev/vdd ] && break; sleep 1; done
    mount -t ext4 -o ro,nodev,nosuid,noexec /dev/vdd /scan-cache > /run/db-mount.log 2>&1
    ls -l /dev/vd* >> /run/db-mount.log 2>&1
    ls -ld /scan-cache /scan-cache/db >> /run/db-mount.log 2>&1
    chmod 0755 /run/orchestrator-ingest-worker
    mount -t tmpfs -o size=1800m,nodev,nosuid tmpfs /work
    chown 1000:1000 /work
    chmod 0700 /work
    chown 1000:1000 /dev/vdb /dev/vdc
    chown 1001:1001 /dev/ttyS1
    chmod 0600 /dev/vdb /dev/vdc /dev/ttyS1
    echo $$ > /sys/fs/cgroup/runner/workload/cgroup.procs
    # Unit corpus and real tool policy checks execute inside this VM only.
    M07_GUEST_TESTS=1 TMPDIR=/work /bin/runner-identity --reuid=1000 --regid=1000 --clear-groups --no-new-privs /bin/ingest-tests -test.v -test.run '^TestGuest' > /run/tests.log 2>&1
    test_rc=$?
    M07_GUEST_TESTS=1 TMPDIR=/work /bin/runner-identity --reuid=1000 --regid=1000 --clear-groups --no-new-privs /bin/ingest-tests -test.run '^$' -test.fuzz '^FuzzGuestOCI$' -test.fuzztime 5s -test.fuzzcachedir /work/fuzzcache -test.parallel 1 >> /run/tests.log 2>&1
    fuzz_rc=$?
    if [ "$fuzz_rc" != 0 ]; then test_rc=1; fi
    cat /run/db-mount.log >> /run/tests.log
    (exit $test_rc)
    tests=$?
    head -c 49152 /run/tests.log | dd of=/dev/vda bs=512 seek=20971390 conv=notrunc,fsync
    mkdir /sys/fs/cgroup/validator
    echo 256 > /sys/fs/cgroup/validator/pids.max
    sh -c 'echo $$ > /sys/fs/cgroup/validator/cgroup.procs; exec /bin/runner-identity --reuid=1000 --regid=1000 --clear-groups --no-new-privs /bin/ingest-runner -phase validate'
    ingest=$?
    echo 1 > /sys/fs/cgroup/validator/cgroup.kill
    if [ "$ingest" = 0 ]; then
      # The validator and all descendants are gone before freezing its output.
      while [ "$(cat /sys/fs/cgroup/validator/pids.current)" != 0 ]; do sleep .1; done
      chown -R 0:0 /work
      chmod 0711 /work
      chmod -R a+rX /work/oci-*
      chmod 0444 /work/verified.json /dev/vdb /dev/vdc
      chown 1001:1001 /dev/ttyS1
      mkdir -p /scan-work
      mount -t tmpfs -o size=300m,nodev,nosuid,noexec tmpfs /scan-work
      chown 1001:1001 /scan-work
      chmod 0700 /scan-work
      /bin/runner-identity --reuid=1001 --regid=1001 --clear-groups --no-new-privs /bin/ingest-runner -phase scan
      ingest=$?
    else
      chmod 0444 /dev/vdb
      /bin/runner-identity --reuid=1001 --regid=1001 --clear-groups --no-new-privs /bin/ingest-runner -phase deny
      ingest=$?
    fi
    result "M07-INGEST tests=$tests runner=$ingest"
    ;;
  m07) . /bin/m07-init ;;
  egress) /bin/m05-probes ;;
  cpu)
    yes >/dev/null & a=$!; yes >/dev/null & b=$!
    yes >/dev/null & c=$!; yes >/dev/null & d=$!
    sleep 60; kill "$a" "$b" "$c" "$d"; result CPU-DONE ;;
  memory)
    # Fixed maximum allocation attempt, no unbounded host stress.
    timeout 30 awk 'BEGIN{s="0123456789abcdef";for(i=0;i<29;i++)s=s s;print length(s)}' >/run/memory-result
    result "MEMORY-DONE status=$?" ;;
  io)
    fio --name=m04 --filename=/dev/vda --offset=1G --size=1G --rw=randwrite --bs=4k --direct=1 --ioengine=libaio --iodepth=32 --runtime=30 --time_based --output=/run/fio.json --output-format=json
    # Full result kept in a fixed 64 KiB tail region; sector marker is separate.
    dd if=/run/fio.json of=/dev/vda bs=512 seek=20971390 count=128 conv=notrunc,fsync
    # A write immediately beyond the fixed raw device must fail.
    dd if=/dev/zero of=/dev/vda bs=512 seek=20971520 count=1 conv=notrunc,fsync
    end_status=$?
    result "IO-DONE beyond_end_status=$end_status sectors=$(cat /sys/block/vda/size)" ;;
  pids)
    sh -c 'echo $$ > /sys/fs/cgroup/runner/workload/cgroup.procs; n=0; while [ "$n" -lt 520 ]; do sleep 60 & n=$((n+1)); done; sleep 60' &
    sleep 3
    result "PIDS count=$(cat /sys/fs/cgroup/runner/pids.current) events=$(cat /sys/fs/cgroup/runner/pids.events)" ;;
esac
while :; do sleep 100; done
INIT
chmod 0755 "$ROOT/init"
if [[ $MODE == build || $MODE == m07 ]]; then
  # runc cannot pivot_root from the special initramfs rootfs. Switch PID 1 to
  # a normal private tmpfs root before starting rootless namespaces.
  mv "$ROOT/init" "$ROOT/init-real"
  cat > "$ROOT/init" <<'SWITCH'
#!/bin/sh
/bin/busybox mount -t devtmpfs devtmpfs /dev
/bin/busybox mkdir -p /newroot
/bin/busybox mount -t tmpfs -o size=700m,nodev tmpfs /newroot
for name in bin sbin usr lib lib64 etc init-real fixture-mode build-ca.pem; do
  if [ -e "/$name" ]; then /bin/busybox cp -a "/$name" /newroot/; fi
done
/bin/busybox mkdir -p /newroot/dev /newroot/proc /newroot/sys /newroot/run /newroot/work /newroot/tmp
exec /bin/busybox switch_root /newroot /init-real
SWITCH
  chmod 0755 "$ROOT/init"
fi

# The clone runner is unprivileged; this credential-free template contains only
# public tools/configuration. Runtime work directories are private separately.
if [[ $MODE == clone || $MODE == m07 || $MODE == build || $MODE == ingest ]]; then chmod -R a+rX "$ROOT"; fi
(cd "$ROOT"; find . -xdev -print0 | cpio --null -o --format=newc | gzip -1) > "$MNT/boot/initrd"
cat > "$MNT/boot/grub/grub.cfg" <<'GRUB'
set timeout=0
set default=0
menuentry 'M04 bounded credential-free lab fixture' {
  linux /boot/vmlinuz quiet console=ttyS0 panic=1 rdinit=/init
  initrd /boot/initrd
}
GRUB
grub-install --target=i386-pc --boot-directory="$MNT/boot" --modules='part_msdos ext2 normal linux' --no-floppy --recheck "$LOOP"
sync -f "$MNT"
umount "$MNT"; MOUNTED=0
losetup -d "$LOOP"; LOOP=
sha256sum "$IMAGE"
printf 'Fixture mode=%s kernel=%s image=%s\n' "$MODE" "$KERNEL" "$IMAGE"
echo 'Review/hash/install this never-booted image; never mount its guest-modified copies.'
