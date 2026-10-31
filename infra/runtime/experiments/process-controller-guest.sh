#!/bin/sh
set -eu
[ -f /etc/m09-disposable-guest ]
exec >/dev/ttyS0 2>&1
finish() {
 rc=$?
 [ -z "${controller_pid:-}" ] || kill "$controller_pid" || true
 echo "M09-PROCESS-CONTROLLER-END rc=$rc"
 sync
 systemctl poweroff --no-block
}
trap finish EXIT
interface=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2;exit}')
ip addr add 192.0.2.11/24 dev "$interface"
ip link set "$interface" up
runuser -u controller -- /usr/local/bin/tap-runtime-controller -config /var/lib/m09-process/config.json &
controller_pid=$!
runuser -u controller -- /opt/m09/processlab drive
