#!/bin/sh
set -eu
[ -f /etc/m09-disposable-guest ]
exec >/dev/ttyS0 2>&1
as_runtime() { runuser -u runtime -- env XDG_RUNTIME_DIR=/run/user/1000 DOCKER_HOST=unix:///run/user/1000/app-$app.sock "$@"; }
finish() {
 rc=$?
 for app in a b; do
  as_runtime docker rm -f tap-profile-$app >/dev/null 2>&1 || true
  runuser -u runtime -- env XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus systemctl --user stop m09-app-$app.service || true
 done
 echo "M09-PROFILE-END rc=$rc"
 sync
 systemctl poweroff --no-block
}
trap finish EXIT
chmod 0666 /dev/net/tun /dev/fuse
mkdir -p /run/user/1000
chown 1000:1000 /run/user/1000
chmod 0700 /run/user/1000
apparmor_parser -r /etc/apparmor.d/tap-runtime
for app in a b; do
 mkdir -p /home/runtime/app-$app-data
 mount -o loop,nodev,nosuid /opt/m09/app-$app.ext4 /home/runtime/app-$app-data
 chown 1000:1000 /home/runtime/app-$app-data
 chmod 0700 /home/runtime/app-$app-data
 done
systemctl start user@1000.service
for app in a b; do
 runuser -u runtime -- env XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus systemctl --user start m09-app-$app.service
 for n in $(seq 1 45); do if as_runtime docker info >/dev/null 2>&1; then break; fi; sleep 1; done
 chmod 0600 /run/user/1000/app-$app.sock
 done
/opt/m09/profileprobe enroll
for app in a b; do
 appid=11111111-1111-4111-8111-111111111111
 [ "$app" != b ] || appid=22222222-2222-4222-8222-222222222222
 as_runtime docker import --change 'USER 1000:1000' /opt/m09/fixture.tar tap-feasibility:probe
 as_runtime docker run -d --runtime tap-runc --name tap-profile-$app --label tap.app=$appid --label tap.owner=11111111-1111-4111-8111-111111111111 --user 1000:1000 --read-only --cap-drop ALL --security-opt no-new-privileges=true --security-opt apparmor=tap-runtime --memory 64m --memory-swap 64m --cpus 0.1 --pids-limit 16 --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8388608,mode=1777 --tmpfs /run:rw,noexec,nosuid,nodev,size=8388608,mode=755 --network bridge --log-driver local --log-opt max-size=1m --log-opt max-file=2 tap-feasibility:probe /busybox sleep 90 > /run/m09-profile-$app.id
 done
/opt/m09/profileprobe verify
