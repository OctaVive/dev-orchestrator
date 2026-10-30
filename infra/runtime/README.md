# M09 runtime development lab — not accepted for deployment

The runtime implementation is incomplete. The Engine adapter refuses readiness
without a measured enforcement adapter and approved image delivery. No production
runtime service is installed or enabled by this directory.

`feasibility-guest.sh` runs a trusted static BusyBox canary inside a disposable KVM
VM with no NIC. It is not the M09 acceptance suite. Its PASS marker covers only
that narrow canary and cannot establish networking, quotas, image admission,
replay enforcement or management isolation. A shell exit code alone is never
proof that Docker applied every requested control.

## Current experiment

A fresh Debian trixie minbase was prepared with systemd, dbus-user-session,
libpam-systemd, iproute2, nftables, apparmor, uidmap, rootlesskit, slirp4netns,
docker.io/docker-cli, fuse-overlayfs, ca-certificates, libcap2-bin, kmod and procps.
The trusted host kernel/modules were copied into the never-executed root tree.
Host services were not enabled; Docker was launched only inside the guest.

Public Docker 29.5.0/static rootless extras are pinned in `tools.lock.json` for
this development experiment, not approved as a release stack. Relevant upstream
contracts: [rootless resource delegation](https://docs.docker.com/engine/security/rootless/tips/#limiting-resources),
[Engine API](https://docs.docker.com/reference/api/engine/) and
[Moby AppArmor support checks](https://github.com/moby/moby/blob/master/daemon/apparmor_linux.go).
Engine API 1.47 remains the adapter's explicit wire version.

A dedicated runtime UID/GID 1000 has subordinate IDs 100000:65536 and a systemd
user daemon with CPU/cpuset/io/memory/PID delegation. The VM loads the experimental
`tap-runtime.apparmor` profile before starting rootless Docker. The experiment
registers `tap-runc` pointing to the compiled `cmd/runtime-runc`, with pinned real
runc at `/usr/local/libexec/runc-real`. The supplement requires a private user
namespace and non-host-root mappings; it cannot waive these controls. It is not
yet integrated into the Engine adapter or certified for any runtime template.

Docker accepted an AppArmor option while its inspected AppArmorProfile remained
empty. A minimal isolated prototype could force the profile at the OCI boundary
and observe `tap-runtime (enforce)`, zero effective capabilities, NNP=1 and
seccomp=2. That prototype did not verify the full hard profile. The current stricter
supplement still fails container creation. A failed earlier namespace experiment
reported uid_map EPERM; the latest diagnostic identifies the current rejection as the absence of a
separate user namespace and UID/GID mappings in Docker's generated OCI bundle. These are
development results, not passing acceptance evidence.

Every image is built from the trusted never-booted root tree using a new raw file
and `mkfs.ext4 -d`. QEMU runs with KVM, 2 CPUs, 1536 MiB RAM, no NIC and snapshot
writes, a 120-second external timeout and a five-second forced-kill margin. No
guest-modified disk is mounted on the host. Source root trees and previous raw
images must never be modified while referenced by a running VM.

Private development artifacts are under
`/var/lib/orchestrator-builder/m09-tools/`. The repository contains bounded
credential-free software/feasibility evidence only. This experiment has no packet
capture or real candidate lifecycle/approval integration, and cannot pass M09.

## Reporting

Run software checks with `umask 077`; the existing metadata tests require private
parent directories. `test_report.py` tests reporting failures with synthetic data;
its fixture PASS is not runtime evidence. The reporter refuses missing, failed,
skipped or changed required evidence:

```sh
python3 infra/runtime/report.py \
  --ledger docs/project/PH1/P1M09/testing/required-cases.json \
  --manifest docs/project/PH1/P1M09/testing/evidence-manifest.json
```

The current expected output is INCOMPLETE with a nonzero exit. A full isolated
runtime acceptance driver and measured network/storage/capacity adapters remain
to be implemented before this reporter may be used to accept a real runtime.
