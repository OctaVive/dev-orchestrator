#!/bin/sh
set -eu
[ -f /etc/m09-disposable-guest ]
exec >/dev/ttyS0 2>&1
as_runtime() { runuser -u runtime -- env XDG_RUNTIME_DIR=/run/user/1000 DOCKER_HOST=unix:///run/user/1000/app-$app.sock "$@"; }
finish() {
 rc=$?
 for app in a b;do as_runtime docker rm -f tap-observe-$app >/dev/null 2>&1 || true;done
 echo "M09-APP-ENGINE-OBSERVATION-END rc=$rc"
 sync;systemctl poweroff --no-block
}
trap finish EXIT
chmod 0666 /dev/net/tun /dev/fuse
mkdir -p /run/user/1000
chown 1000:1000 /run/user/1000
chmod 0700 /run/user/1000
apparmor_parser -r /etc/apparmor.d/tap-runtime
systemctl start user@1000.service
runuser -u runtime -- env XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus systemctl --user daemon-reload
for app in a b; do
 runuser -u runtime -- env XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus systemctl --user start m09-app-$app.service
 for n in $(seq 1 45);do [ -S /run/user/1000/app-$app.sock ] && break;sleep 1;done
 as_runtime docker info --format 'M09-APP-ENGINE version={{.ServerVersion}} id={{.ID}} cgroup={{.CgroupDriver}}'
 as_runtime docker import --change 'USER 1000:1000' /opt/m09/fixture.tar tap-feasibility:probe
 as_runtime docker run -d --runtime tap-runc --name tap-observe-$app --label tap.app=fixture-$app --user 1000:1000 --read-only --cap-drop ALL --security-opt no-new-privileges=true --security-opt apparmor=tap-runtime --memory 64m --memory-swap 64m --cpus 0.1 --pids-limit 16 --network none --log-driver local --log-opt max-size=1m --log-opt max-file=2 tap-feasibility:probe /busybox sleep 90
 pid=$(as_runtime docker inspect --format '{{.State.Pid}}' tap-observe-$app)
 echo "M09-APP-PROCESS app=$app pid=$pid"
 for ns in user pid ipc mnt uts net cgroup;do echo "M09-APP-NAMESPACE app=$app kind=$ns value=$(readlink /proc/$pid/ns/$ns)";done
 echo "M09-APP-MAC app=$app value=$(cat /proc/$pid/attr/current)"
 [ "$(cat /proc/$pid/attr/current)" = 'tap-runtime (enforce)' ]
 grep -E '^(Uid|Gid|Groups|CapEff|CapPrm|CapBnd|NoNewPrivs|Seccomp):' /proc/$pid/status
 if [ "$app" = a ];then user_a=$(readlink /proc/$pid/ns/user);else user_b=$(readlink /proc/$pid/ns/user);fi
 done
initial_user=$(readlink /proc/1/ns/user)
[ "$user_a" != "$user_b" ]
[ "$user_a" != "$initial_user" ]
[ "$user_b" != "$initial_user" ]
echo "M09-APP-INITIAL-USER-NAMESPACE value=$initial_user"
echo M09-APP-ENGINE-OBSERVATION-COMPLETE
