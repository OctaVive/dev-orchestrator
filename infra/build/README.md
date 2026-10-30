# M07 rootless build and artifact admission

The narrow `buildjob.Driver` consumes M06's durable same-guest context. It does
not schedule jobs, approve deployments or enable production services.

## Trusted inputs and boundaries

`CloneJob.Build` predeclares operator-owned `BuildSettings`. A successful clone
waits on a bounded raw serial authorization. `Store.BeginBuild` verifies the
accepted SHA/context and atomically enters BUILDING before the private backend
publishes the matching authorization. The guest receives no arbitrary command,
host path, runtime secret, registry push credential or engine socket. Result
frames contain closed codes and bounded hashes/counters; tokens never enter
build subprocess environments or management events.

The Linux supervisor re-arms its independent CLOCK_BOOTTIME timer before sending
build authorization. Input delivery has a separate five-second maximum; an
unresponsive guest cannot postpone its external deadline. Existing VM expiry,
late-start fences, ownership checks and cleanup reservations remain active.

BuildKit 0.34.1 runs through Debian RootlessKit as UID 1000 with process sandboxing,
private native snapshotter state and a dedicated socket. runc requires a normal
root mount; the fixture switches from initramfs rootfs to a private tmpfs root.
No `--oci-worker-no-process-sandbox` or insecure entitlement fallback exists.
The trusted init supplies user mappings and guest PID limits. Host caps remain
2 vCPU, 4 GiB guest RAM, 4.5 GiB host service RAM, 10 GiB guest disk, 1,000 IOPS
and 128 host tasks. Guest PID limit 512 is defense in depth.

## Initial compatibility

One linux/amd64 image, SHA-256 OCI descriptors, plain/gzip layers. The fixture
Dockerfile profile permits a single FROM scratch or digest-pinned image, COPY,
RUN, USER, WORKDIR, ENV, EXPOSE, CMD, ENTRYPOINT and LABEL. It rejects parser
comments/directives, continuations, heredocs, ADD, external COPY flags, secret/
SSH/device mounts, caller options and multiple FROM statements. M08 supplies the
general normalization/policy producer later.

The pinned built-in frontend is selected with a fixed `cmdline` option. BuildKit
source policy denies every source except the two fixed local inputs and
SHA-256-pinned image references; this also covers inherited ONBUILD remote ADD.
Build steps use network mode none. Registry pulls and the job upload use only
M05's fixed broker at 192.0.2.1:8443 with the public build CA. Approved registry
origins must be in the external broker policy. Builds needing online package
installation are intentionally unsupported in this profile; vendor dependencies.

## Resource policy

| Resource | Default / fixed maximum |
|---|---:|
| Build time | 1,200 s, also bounded by original lease |
| Scan/ingest time | 300 s, externally enforced on a separate VM |
| Architecture total attempt budget | 40 min; current M04/M06 lease maximum remains a stricter 30 min |
| Upload bytes | 1 GiB |
| Aggregate expanded layer bytes | 4 GiB |
| Single expanded layer | 2 GiB |
| Archive + layer entries | 100,000 |
| Descriptors | 256 |
| OCI JSON document | 4 MiB |
| Path bytes / depth | 1,024 / 64 |
| Expansion ratio | 100 |
| Concurrent uploads / grant inventory | 2 / 128 |
| Quarantine capacity / retention | 4 GiB / 24 h |
| Admitted store capacity | 16 GiB; preserve at least 4 GiB free space; full retention/inventory policy remains P1-R04 |
| Scanner report / SBOM | 16 MiB each; stderr 64 KiB |
| Build stdout / stderr | 256 KiB each |
| DB maximum age | 48 h; actual frozen DB UpdatedAt must match policy |

Operators may lower job limits. Repositories cannot raise them. Fixed VM maxima
and broker limits may be stricter. The fixture uses bounded tmpfs workspaces;
large legitimate builds may fail before the exported-image maximum. Capacity
reservations cover live uploads, then charge actual retained bytes. Service
restart revokes in-memory grants; existing opaque files remain quarantined and
charged. Failed attempts require fresh builder VMs.

## Separate artifact service

`cmd/artifact-service` takes private quarantine/artifact directories, a new Unix
control socket and a dedicated TLS upload address/certificate. Serve it as a
separate trusted service; it receives no management database configuration or credentials and never
parses archives. The guest interface supports only PUT with a short-lived opaque
grant. Issue/receipt/revoke/promotion operations exist only on the private Unix
socket. Restrict its parent directory and socket to the controller/service owner.
No control interface is attached to the public listener.

Opaque promotion hashes original uploaded bytes, fsyncs a private pending inode,
and atomically links the complete inode into content-addressed storage. SQLite
admission commits afterward. An orphan copy is never authorization. Recovery
from a completed export uses `ResumeIngest`: reconcile old scanner VMs, rerun
verification/scanning, retry identical promotion and CAS the current attempt.
Upload-service loss invalidates its grant/receipt and fails the attempt closed.
Pending promotion debris and full artifact reference GC require explicit
operator reconciliation; capacity caps stop further writes before exhaustion.

## Pinned tools and lab

`tools.lock.json` records reviewed public archive/package hashes and the frozen
Trivy 0.76.1 database identity. `prepare-tools.py` reconstructs tools into a new
private directory from those pins and an existing trusted DB snapshot. A DB
refresh is a new reviewed snapshot/policy identity, not a floating scan input.
Official tool contracts: [BuildKit rootless](https://github.com/moby/buildkit/blob/v0.34.1/docs/rootless.md),
[BuildKit source policy](https://github.com/moby/buildkit/blob/v0.34.1/sourcepolicy/pb/policy.proto),
[Trivy vulnerability scanning](https://trivy.dev/docs/latest/guide/scanner/vulnerability/).

The user-authorized isolated lab is explicit opt-in:

```sh
umask 077
M07_LAB_APPROVED=YES-I-AUTHORIZE-BUILD-LAB \
  python3 infra/build/lab.py --lab /var/lib/orchestrator-builder/m05-lab.<id> \
  --tools <private-tools-directory> --ingest-config <reviewed-scanner-config>
```

The harness builds fresh binaries/templates and separate state, temporarily
installs only its controlled upstream CA and loopback aliases, and restores them
in finally. It does not replace base configs, enable services or relax firewall
policy. `--debug` is development-only and cannot establish acceptance. See the
[milestone test plan](../../docs/project/PH1/P1M07/test-plan.md).
