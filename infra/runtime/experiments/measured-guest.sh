#!/bin/sh
set -eu
[ -f /etc/m09-disposable-guest ]
exec >/dev/ttyS0 2>&1
apps='11111111-1111-4111-8111-111111111111 22222222-2222-4222-8222-222222222222'
finish() {
 rc=$?
 for app in $apps; do
  compact=$(echo "$app" | tr -d '-')
  runuser -u runtime -- env XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus systemctl --user stop tapapp$compact.service || true
 done
 [ -z "${measure_pid:-}" ] || kill "$measure_pid" || true
 echo "M09-MEASURED-END rc=$rc"
 sync
 systemctl poweroff --no-block
}
trap finish EXIT
chmod 0666 /dev/net/tun /dev/fuse
apparmor_parser -r /etc/apparmor.d/tap-runtime
/usr/local/bin/tap-runtime-host
/usr/local/bin/tap-runtime-host
/usr/local/bin/tap-runtime-measure &
measure_pid=$!
for n in $(seq 1 20); do [ -S /run/tap-runtime/measure.sock ] && break; sleep 1; done
runuser -u runtime -- /opt/m09/measuredprobe
