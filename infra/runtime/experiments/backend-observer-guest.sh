#!/bin/sh
set -eu
[ -f /etc/m09-disposable-guest ]
exec >/dev/ttyS0 2>&1
finish() {
 rc=$?
 for app in a b; do
  runuser -u runtime -- env XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus systemctl --user stop m09-app-$app.service || true
 done
 echo "M09-BACKEND-OBSERVATION-END rc=$rc"
 sync
 systemctl poweroff --no-block
}
trap finish EXIT
chmod 0666 /dev/net/tun /dev/fuse
mkdir -p /run/user/1000
chown 1000:1000 /run/user/1000
chmod 0700 /run/user/1000
systemctl start user@1000.service
for app in a b; do
 runuser -u runtime -- env XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus systemctl --user start m09-app-$app.service
 for n in $(seq 1 45); do [ -S /run/user/1000/app-$app.sock ] && break; sleep 1; done
 # Socket existence precedes completion of daemon startup.
 for n in $(seq 1 30); do
  if runuser -u runtime -- env DOCKER_HOST=unix:///run/user/1000/app-$app.sock docker info >/dev/null 2>&1; then break; fi
  sleep 1
 done
 done
/opt/m09/backendprobe
