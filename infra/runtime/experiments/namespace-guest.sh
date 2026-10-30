#!/bin/sh
# Trusted namespace observation only, inside a disposable NIC-less VM.
set -eu
[ -f /etc/m09-disposable-guest ]
exec >/dev/ttyS0 2>&1
as_runtime() { runuser -u runtime -- env XDG_RUNTIME_DIR=/run/user/1000 DOCKER_HOST=unix:///run/user/1000/docker.sock "$@"; }
finish() {
 rc=$?
 as_runtime docker rm -f tap-observe-a tap-observe-b >/dev/null 2>&1 || true
 echo "M09-NAMESPACE-OBSERVATION-END rc=$rc"
 sync
 systemctl poweroff --no-block
}
trap finish EXIT
chmod 0666 /dev/net/tun /dev/fuse
mkdir -p /run/user/1000
chown 1000:1000 /run/user/1000
chmod 0700 /run/user/1000
systemctl start user@1000.service
runuser -u runtime -- env XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus systemctl --user start m09-docker.service
for n in $(seq 1 45); do [ -S /run/user/1000/docker.sock ] && break; sleep 1; done
as_runtime docker info --format 'M09-ENGINE version={{.ServerVersion}} cgroup={{.CgroupDriver}} cgroup_version={{.CgroupVersion}} security={{json .SecurityOptions}}'
as_runtime docker import --change 'USER 1000:1000' /opt/m09/fixture.tar tap-feasibility:probe
for name in a b; do
 as_runtime docker run -d --runtime runc --name tap-observe-$name --label tap.app=fixture-$name --user 1000:1000 --read-only --cap-drop ALL --security-opt no-new-privileges=true --security-opt apparmor=tap-runtime --memory 64m --memory-swap 64m --cpus 0.1 --pids-limit 16 --network none --log-driver local --log-opt max-size=1m --log-opt max-file=2 tap-feasibility:probe /busybox sleep 90
 pid=$(as_runtime docker inspect --format '{{.State.Pid}}' tap-observe-$name)
 echo "M09-PROCESS app=$name pid=$pid"
 for ns in user pid ipc mnt uts net cgroup; do echo "M09-NAMESPACE app=$name kind=$ns value=$(readlink /proc/$pid/ns/$ns)"; done
 echo "M09-UID-MAP app=$name";cat /proc/$pid/uid_map
 echo "M09-GID-MAP app=$name";cat /proc/$pid/gid_map
 echo "M09-MAC app=$name value=$(cat /proc/$pid/attr/current)"
 grep -E '^(Uid|Gid|Groups|CapEff|CapPrm|CapBnd|NoNewPrivs|Seccomp):' /proc/$pid/status
 as_runtime docker inspect --format 'M09-ENGINE-MAC requested={{json .HostConfig.SecurityOpt}} applied={{json .AppArmorProfile}}' tap-observe-$name
 done
echo "M09-INITIAL-USER-NAMESPACE value=$(readlink /proc/1/ns/user)"
echo M09-NAMESPACE-OBSERVATION-COMPLETE
