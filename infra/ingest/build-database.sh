#!/bin/bash
# Creates a NEW trusted read-only database image. Never mounts guest output.
set -euo pipefail
umask 077
[[ $EUID == 0 && ${M07_DATABASE_BUILD:-} == YES-I-AUTHORIZE-DATABASE-IMAGE ]]
[[ $# == 2 && -d $1/db && ! -e $2 ]]
SOURCE=$1
IMAGE=$2
WORK=$(mktemp -d /var/lib/orchestrator-builder/image-build/database.XXXXXXXX)
MOUNT=$WORK/mount
mkdir -m 0700 "$MOUNT"
fallocate -l 2G "$IMAGE"
mkfs.ext4 -F "$IMAGE"
LOOP=$(losetup --find --show --read-only "$IMAGE")
losetup -d "$LOOP"
# This newly created image has never been attached to a guest.
mount -o loop,nodev,nosuid,noexec "$IMAGE" "$MOUNT"
finish(){ umount "$MOUNT"; }
trap finish EXIT
mkdir "$MOUNT/db"
cp "$SOURCE/db/trivy.db" "$SOURCE/db/metadata.json" "$MOUNT/db/"
chmod -R a+rX "$MOUNT/db"
sync -f "$MOUNT"
umount "$MOUNT"
trap - EXIT
sha256sum "$IMAGE"
