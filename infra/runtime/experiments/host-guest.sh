#!/bin/sh
set -eu
[ -f /etc/m09-disposable-guest ]
exec >/dev/ttyS0 2>&1
apps='11111111-1111-4111-8111-111111111111 22222222-2222-4222-8222-222222222222'
worker=11111111-1111-4111-8111-111111111111
finish() {
 rc=$?
 for app in $apps; do
  runuser -u runtime -- env DOCKER_API_VERSION=1.47 DOCKER_HOST=unix:///run/tap-runtime/apps/$app/docker.sock docker rm -f tap-host-fixture >/dev/null 2>&1 || true
  compact=$(echo "$app" | tr -d '-')
  runuser -u runtime -- env XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus systemctl --user stop tapapp$compact.service || true
 done
 [ -z "${measure_pid:-}" ] || kill "$measure_pid" || true
 echo "M09-HOST-END rc=$rc"
 sync
 systemctl poweroff --no-block
}
trap finish EXIT
chmod 0666 /dev/net/tun /dev/fuse
apparmor_parser -r /etc/apparmor.d/tap-runtime
/usr/local/bin/tap-runtime-host
/usr/local/bin/tap-runtime-host
echo M09-HOST-PROVISIONED-TWICE
/usr/local/bin/tap-runtime-measure &
measure_pid=$!
for n in $(seq 1 20); do [ -S /run/tap-runtime/measure.sock ] && break; sleep 1; done
for app in $apps; do
 as_runtime() { runuser -u runtime -- env DOCKER_API_VERSION=1.47 DOCKER_HOST=unix:///run/tap-runtime/apps/$app/docker.sock "$@"; }
 as_runtime docker load -i /usr/local/share/tap-runtime/canary.oci.tar
 as_runtime docker image ls --no-trunc
 as_runtime docker import --change 'USER 1000:1000' /opt/m09/fixture.tar tap-feasibility:probe
 as_runtime docker run -d --runtime tap-runc --name tap-host-fixture --label tap.worker=$worker --label tap.incarnation=$worker --label tap.app=$app --label tap.deployment=$worker --label tap.generation=1 --label tap.spec=sha256:9a5099c52df4cef281936db949cdb9b83e90efe28d208a34b9722f56c309ab5d --label tap.owner=$worker --label tap.service=web --user 1000:1000 --read-only --cap-drop ALL --security-opt no-new-privileges=true --security-opt apparmor=tap-runtime --memory 64m --memory-swap 64m --cpus 0.1 --pids-limit 16 --shm-size 1m --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8388608,mode=1777 --tmpfs /run:rw,noexec,nosuid,nodev,size=8388608,mode=755 --network bridge --log-driver local --log-opt max-size=1m --log-opt max-file=2 tap-feasibility:probe /busybox sh -c 'printf ready > /tmp/index.html; exec /busybox httpd -f -p 8080 -h /tmp' > /run/m09-host-$app.id
 chmod 0644 /run/m09-host-$app.id
 done
runuser -u runtime -- /opt/m09/hostprobe
