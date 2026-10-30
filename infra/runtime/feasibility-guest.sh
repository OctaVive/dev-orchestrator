#!/bin/sh
# Trusted boot-time probe in a disposable VM without a NIC. Not an installer.
set -eu
[ -f /etc/m09-disposable-guest ]
exec >/dev/ttyS0 2>&1
finish() { rc=$?; journalctl --no-pager -n 40 _UID=1000; echo "M09-FEASIBILITY-END rc=$rc"; sync; systemctl poweroff --no-block; }
trap finish EXIT
chmod 0666 /dev/net/tun /dev/fuse
mkdir -p /run/m09 /run/user/1000
chown 1000:1000 /run/user/1000
chmod 0700 /run/user/1000
apparmor_parser -r /etc/apparmor.d/tap-runtime
systemctl start user@1000.service
runuser -u runtime -- env XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus systemctl --user start m09-docker.service
for n in $(seq 1 45); do [ -S /run/user/1000/docker.sock ] && break; sleep 1; done
as_runtime() { runuser -u runtime -- env XDG_RUNTIME_DIR=/run/user/1000 DOCKER_HOST=unix:///run/user/1000/docker.sock "$@"; }
as_runtime docker info
as_runtime docker import --change 'USER 1000:1000' /opt/m09/fixture.tar tap-feasibility:probe
# This is a trusted static BusyBox canary, not repository content.
as_runtime docker run --runtime tap-runc --name tap-feasibility --user 1000:1000 --read-only --cap-drop ALL --security-opt no-new-privileges=true --security-opt apparmor=tap-runtime --memory 64m --memory-swap 64m --cpus 0.1 --pids-limit 16 --network none tap-feasibility:probe /busybox sh -c '/busybox cat /proc/self/attr/current; /busybox grep -E "^(CapEff|NoNewPrivs|Seccomp):" /proc/self/status; [ "$(/busybox cat /proc/self/attr/current)" = "tap-runtime (enforce)" ]'
as_runtime docker inspect tap-feasibility
as_runtime docker rm tap-feasibility
echo M09-FEASIBILITY-PASS
