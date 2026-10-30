#!/bin/sh
# Called by trusted fixture init inside the disposable KVM guest only.
mount -t devpts devpts /dev/pts
mount --make-rprivate /
chmod 1777 /tmp
mkdir -p /work /run/user/1000 /tmp /etc/buildkit
mount -t tmpfs -o size=2600m,nodev tmpfs /work
chown 1000:1000 /work /run/user/1000
chmod 0700 /work /run/user/1000
printf 'runner:100000:65536\n' >/etc/subuid
printf 'runner:100000:65536\n' >/etc/subgid
mkdir -p /work/context
printf 'FROM scratch\nCOPY hello /hello\nUSER 1000\n' >/work/context/Dockerfile
printf 'M07-rootless\n' >/work/context/hello
chown -R 1000:1000 /work/context
# uidmap helpers need their narrowly scoped setuid transition before namespace
# entry. The BuildKit daemon itself runs as the mapped unprivileged guest user.
/usr/bin/setpriv --reuid=1000 --regid=1000 --clear-groups env HOME=/work XDG_RUNTIME_DIR=/run/user/1000 PATH=/usr/bin:/bin \
 rootlesskit --copy-up=/etc --copy-up=/run --state-dir=/work/rootless \
 buildkitd --rootless --root /work/buildkit --addr unix:///work/buildkit.sock \
 --oci-worker=true --containerd-worker=false --oci-worker-snapshotter=native \
 --oci-worker-binary=/usr/bin/buildkit-runc --oci-worker-net=host --cdi-disabled \
 >/run/buildkit.log 2>&1 &
for n in $(seq 1 30); do [ -S /work/buildkit.sock ] && break; sleep 1; done
/usr/bin/setpriv --reuid=1000 --regid=1000 --clear-groups env HOME=/work PATH=/usr/bin:/bin \
 buildctl --addr unix:///work/buildkit.sock debug workers >/run/workers 2>&1
workers=$?
/usr/bin/setpriv --reuid=1000 --regid=1000 --clear-groups env HOME=/work PATH=/usr/bin:/bin \
 buildctl --addr unix:///work/buildkit.sock build --frontend=dockerfile.v0 --local context=/work/context --local dockerfile=/work/context \
 --opt platform=linux/amd64 --opt cmdline= --output type=oci,dest=/work/image.tar,oci-mediatypes=true,compression=gzip \
 >/run/build.log 2>&1
rc=$?
# Evidence copied to bounded fixed disk-tail regions; host never mounts it.
cat /run/buildkit.log /run/workers /run/build.log | head -c 49152 | dd of=/dev/vda bs=512 seek=20971390 conv=notrunc,fsync
result "M07-FEASIBILITY build=$rc workers=$workers uidmap=$(cat /work/rootless/child_pid 2>/dev/null)"
