#!/bin/bash
# Trusted Debian host tools only. This creates a NEW loop-backed BIOS image;
# never use it to mount a guest-modified disk. Review before privileged execution.
set -euo pipefail
umask 077
[[ ${M04_IMAGE_BUILD:-} == YES-I-AUTHORIZE-LOOP-IMAGE && $EUID == 0 ]] || {
  echo 'Requires root and M04_IMAGE_BUILD=YES-I-AUTHORIZE-LOOP-IMAGE' >&2; exit 1;
}
MODE=${1:-idle}
case "$MODE" in idle|cpu|memory|io|pids) ;; *) exit 1;; esac
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
for name in sh mount mkdir sleep yes kill dd cat awk sync wc; do ln -s busybox "$ROOT/bin/$name"; done
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
cp -a /lib/modules/"$KERNEL"/kernel "$ROOT/lib/modules/$KERNEL/"
cp /lib/modules/"$KERNEL"/modules.* "$ROOT/lib/modules/$KERNEL/"
if [[ $MODE == io ]]; then copy_binary /usr/bin/fio bin/fio; fi
printf '%s\n' "$MODE" > "$ROOT/fixture-mode"
cat > "$ROOT/init" <<'INIT'
#!/bin/sh
export PATH=/bin:/sbin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /run
mkdir -p /sys/fs/cgroup
mount -t cgroup2 none /sys/fs/cgroup
mkdir /sys/fs/cgroup/runner
echo 512 > /sys/fs/cgroup/runner/pids.max
modprobe virtio_pci
modprobe virtio_blk
MODE=$(cat /fixture-mode)
for n in 1 2 3 4 5; do [ -b /dev/vda ] && break; sleep 1; done
result() { printf 'M04-FIXTURE %s\n' "$*" | dd of=/dev/vda bs=512 seek=20971519 count=1 conv=notrunc,fsync; }
result "BOOT mode=$MODE runner_pids=$(cat /sys/fs/cgroup/runner/pids.max)"
case "$MODE" in
  cpu)
    yes >/dev/null & a=$!; yes >/dev/null & b=$!
    yes >/dev/null & c=$!; yes >/dev/null & d=$!
    sleep 60; kill "$a" "$b" "$c" "$d"; result CPU-DONE ;;
  memory)
    # Fixed maximum allocation attempt, no unbounded host stress.
    awk 'BEGIN{s="0123456789abcdef";for(i=0;i<29;i++)s=s s;print length(s)}' >/run/memory-result
    result "MEMORY-DONE status=$?" ;;
  io)
    fio --name=m04 --filename=/dev/vda --offset=1G --size=1G --rw=randwrite --bs=4k --direct=1 --ioengine=libaio --iodepth=32 --runtime=30 --time_based --output=/run/fio.json --output-format=json
    # Full result kept in a fixed 64 KiB tail region; sector marker is separate.
    dd if=/run/fio.json of=/dev/vda bs=512 seek=20971390 count=128 conv=notrunc,fsync
    result IO-DONE ;;
  pids)
    sh -c 'echo $$ > /sys/fs/cgroup/runner/cgroup.procs; n=0; while [ "$n" -lt 520 ]; do sleep 60 & n=$((n+1)); done; sleep 60' &
    sleep 3
    result "PIDS count=$(cat /sys/fs/cgroup/runner/pids.current) events=$(cat /sys/fs/cgroup/runner/pids.events)" ;;
esac
while :; do sleep 100; done
INIT
chmod 0755 "$ROOT/init"
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
