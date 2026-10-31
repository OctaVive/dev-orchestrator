# PH1M09 remaining work and resume handoff

Updated: 2026-10-30. Workspace: `/root/tap`.

**M09 remains INCOMPLETE / NOT PASSED.** This is a working handoff, not an
acceptance certificate. Preserve all existing tracked and untracked changes;
do not reset or discard them. No commit or production deployment was made.

## User instructions that remain active

- Execute `prompts/PH1M09-next-window.md`, create a completion plan and implement it.
- Every required real acceptance constituent must pass before marking M09 passed.
- Keep monitoring storage. Retain evidence; never remove an active VM disk or
  unrelated project artifact. Do not mount guest-modified disks on management.
- Monitor weekly Codex usage. **At 4% remaining, save/update this handoff and its
  `.md5` checksum, terminate only owned lab runs safely, and stop task work.**
  Do not wait for the quota to reach zero. The user explicitly requested this stop.
- No subagents unless the user explicitly authorizes delegation.

## Current quota and storage monitoring

Latest observed weekly telemetry when this handoff was prepared: 75% used,
25% remaining (latest telemetry timestamp 2026-10-30T21:39:25.555Z). Read `/var/tmp/tap-m09/quota-latest.json` for the current sample.
This is the seven-day window (`window_minutes: 10080`), not a token budget.

Background watchers started during this task:

- `/var/tmp/tap-m09/quota-watch.py`: samples session quota every five seconds;
  writes `quota-latest.json`, `quota-watch.jsonl`, and `quota-stop.requested`
  when remaining quota reaches 4%. At that point it also refreshes this checksum.
  Its initial process runs for up to four hours. Check it is alive after resuming.
- `/var/tmp/tap-m09/storage-watch.py`: samples disk usage every 15 seconds;
  writes `storage-watch.jsonl`. Initial watcher lasts two hours from approximately
  19:55 UTC, so restart it if work continues after approximately 21:55 UTC.
  Stop marker: `/var/tmp/tap-m09/storage-watch.stop`.

Recent storage: about 15 GiB free on `/` and 1.8 GiB free on `/tmp`.
The Go cache was moved to `/var/tmp/tap-go-cache`; `/tmp/tap-go-cache` is a symlink
there. Continue using a private umask and short scratch paths:

```sh
umask 077
export TMPDIR=/var/tmp/tap-m09 GOCACHE=/tmp/tap-go-cache
/usr/local/go/bin/go test ./...
```

Do not launch another large build/scan lab with insufficient headroom. Actual M07
labs temporarily consume many GiB and enforce a separate management free-space
floor. Prefer at least 20 GiB free before those runs. The runtime process-pair
harness refuses startup below 8 GiB; continue monitoring peak usage afterward.

Only completed disposable development images were retired. Their hashes and
retention reasons are in
`/var/lib/orchestrator-builder/m09-tools/retired-development-images.json`.
Serial logs, stderr, result files, trusted source roots and evidence were retained.
The local helper `/var/tmp/tap-m09/retire-images.py` checks open process FDs and
requires the matching serial log before deleting an explicitly named lab image.

## Implementation now present

Read the C01–C08 completion sequence in `implementation-plan.md`, plus
`implementation-evidence.md`, `test-plan.md`, the runtime execution/deployment
agent specifications and `docs/architecture/docker-security.md`.

- `internal/runtimehost`, `cmd/runtime-host`: fixed root oneshot inside the runtime
  VM; finite operator app slots, durable reserve-before-provisioning, physical
  hard-sized per-app ext4 storage, parent memory/CPU/PID cgroups, separate rootless
  Docker daemons, root-owned enrollment and agent-ledger anchor. No generic RPC.
- `internal/runtimeisolation`, `runtimeprofile`, `cmd/runtime-runc`: independently
  measured boot/process/userns/map identity; inherited app namespace support
  only after trusted enrollment; nonroot IDs, zero capabilities, NNP, enforced
  AppArmor/seccomp, private namespaces, cgroups, readonly root and bounded tmpfs.
  Engine-managed etc bind files are made readonly.
- `internal/runtimemeasure`, `runtimenet`, `runtimeobservation`, and their commands:
  bounded root measurement Unix service; exact app/container ownership; fixed
  privilege-dropping health/relay helper; private network namespace and Unix
  relay, separate relay UID, tracked child/socket ownership and finite lifetime.
- `internal/runtimeengine`: app-scoped guarded factory, concrete measured
  enforcement, unknown-object refusal, immutable platform canary, candidate
  capacity accounting, private ingress, inspected typed lifecycle, supervisor.
- `internal/storage/runtime.go`, `migrations/004_runtime.sql`, `runtimeauthority`:
  durable explicit trusted approval/admission/current scan policy, worker leases,
  certificates/revocation, command queue, result acknowledgment and runtime
  artifact authorization. No HTTP approval/queue mutation endpoints.
- `runtimeagent`: ledger schema 3, migration from old schemas, immutable ledger
  identity, outbox, stored command specs, candidate budgets, finite restart
  allowances and stop/generation fences. Background current-authorization checks
  cancel long requests. Incidents block new execution but permit authorized
  exact stop/remove so recovery can proceed.
- `cmd/runtime-agent`, `cmd/runtime-controller`, `runtimeprocess`, `runtimerpc`:
  actual separate processes, outbound mTLS polling/artifact transfer, independent
  inventory signing, provisioned transport reload and revocation checks.
- Service templates are in `infra/runtime/services/`. They still require real
  acceptance and an accepted reproducible runtime VM/host profile.
- Volumes/secrets remain denied pending M10. Production routing belongs to M11;
  the M09 relay is a private connectivity fixture. Assignment/scheduling is M12.

## Important fixes discovered through actual VM execution

1. RootlessKit needs `--net=none`, port driver `none` and
   `DOCKERD_ROOTLESS_ROOTLESSKIT_DETACH_NETNS=false` for the pinned version.
2. The rootless hardener must verify inherited kernel namespaces/maps, rather
   than invent nested mappings or accept missing maps without enrollment.
3. Root cannot reliably statfs through an unprivileged FUSE root. Kernel mountinfo
   superblock options now supply actual tmpfs bounds.
4. Pinned runtime executables require explicit chmod 0755 after builds under
   umask 077. Docker also changes its data-root mode; provisioner restores 0700.
5. Classic Docker rejects the plain OCI archives emitted by M07. The runtime now
   uses Docker 29.5.0's containerd image store with native snapshotter. Inspect and
   create resolve the exact admitted OCI manifest digest. No tag/registry fallback
   or management OCI parsing was introduced. Repository-digest lists may be empty.
6. Runtime enrollment reads completed immutable M07 records after the old build
   lease expires, while preserving current scan/admission checks. It grants no
   new build authority. M07's live build fence was not weakened.
7. Concurrent authorization refreshes no longer expose a transient empty image
   resolver. Failed refreshes still invalidate its view. Controller grants use
   four seconds below the receiver's strict five-second ceiling to leave small
   independent VM clock offsets headroom.
8. `internal/cloner/context.go` incorrectly materialized Git content using private
   staging permissions (0600/0700), so Docker COPY produced executables unusable
   by nonroot workloads. Git content modes are now normalized to 0644/0755 while
   the context root stays private. This needs complete M06/M08 regression too.
9. `/run` tmpfs now belongs to the validated service UID/GID. The platform canary
   has 14 checks, including successful bounded writes to both `/tmp` and `/run`.
10. Relay tracking now includes exact container ID, so draining a non-ingress
    sibling does not fail or affect the deployment's actual ingress relay.
11. Cleanup now permits independently confirmed absent recorded objects, and
    DELETE acknowledgment alone is insufficient: exact GET 404 must precede
    forgetting a resource. Capacity release additionally checks for unknown
    engine objects. Add direct fault tests and execute real lost-response/crash
    variants for this most recent recovery change.

## Actual evidence achieved (development scope only)

Private lab root: `/var/lib/orchestrator-builder/m09-tools`.
Trusted never-booted runtime source root: `rootfs/`.
Trusted controller source root: `controller-rootfs/`.
Linux: 6.12.113+deb13-amd64; Docker/rootless extras: 29.5.0;
systemd: 257.13; QEMU: 10.0.13; API contract: 1.47.

- `profile-7.log`: narrow kernel profile diagnostic succeeded for both app engines.
- `host-6.log`: actual provisioner ran twice idempotently; both app backend/kernel
  measurements, private health, relay fetch and relay removal completed, rc=0.
- `host-11.log`: signed measured platform canary probes passed for both apps.
- `process-pair-10/`: real admitted single-service lifecycle passed between actual
  agent/controller executables in separate VMs over a private inherited socket
  pair, with no host NIC or route. Sequence: probe, create/readiness, inspect,
  logs, stop, inspect, remove, final signed clean probe. `result.json` has no
  errors, both QEMU exit codes zero and final clean probe verified.
- **`process-pair-12/`: the same complete sequence passed for the real two-service
  dependency fixture.** Web starts its HTTP server only after successfully
  fetching the dependency's health endpoint. This run includes the 14-check
  canary and nonroot-writable `/run`, relay sibling fix and new cleanup behavior.
- All earlier failed development runs/logs remain recorded. These are not hidden
  or promoted into passing full milestone gates.

Process VM teardown deliberately quits the exact owned disposable snapshot QEMU
processes after product stop/remove and the final signed clean probe. ACPI power
button delivery was ineffective without a guest power-event handler. The harness
records its teardown method and whether the final clean probe completed. A QEMU
exit alone never makes an incomplete lifecycle pass.

## Real M07/M08 handoff records and reproduction

The actual source build and scan run is not replaced by synthetic admissions.

- First functional single handoff: `m07-handoff-5/{metadata.db,handoff.json}`.
  Its actual pipeline run:
  `/var/lib/orchestrator-builder/m05-lab.4cac6wpp/m08.1793392379098667448`.
- Both current actual records:
  `m07-handoff-pair/m08-dockerfile/` and `m07-handoff-pair/m08-compose/`.
  Pipeline run:
  `/var/lib/orchestrator-builder/m05-lab.4cac6wpp/m08.1793394108463396945`.
  Both builds/scans admitted and both M08 plans normalized successfully; cleanup
  confirmed trust restoration, unchanged firewall and no remaining guest disks.
- The Compose plan has one built web image and a separately admitted dependency
  image. It preserves M08's single-build constraint. Separate real applications,
  deployments/repositories/branches avoid record identity collisions.
- `infra/runtime/experiments/merge-handoff.py` consolidates trusted metadata
  snapshots without changing admission/job/deployment/event IDs or payloads.
  Only local outbox integer surrogate sequence numbers can be reassigned.
  It checks every imported row's content and the foreign key graph.
- Actual opaque artifacts are in the pipeline run's `artifacts/` directory and
  copied opaquely to `controller-rootfs/var/lib/m09-process/artifacts/`.
- Lab exporter opt-in: `M09_HANDOFF_DIRECTORY`, with per-scenario private subdirs.
  Hook lives only in the real pipeline test/fixture. No production approval path.

Useful commands (fresh output directory each time):

```sh
umask 077
export TMPDIR=/var/tmp/tap-m09 GOCACHE=/tmp/tap-go-cache
python3 infra/runtime/experiments/process-pair.py \
  --runtime-root /var/lib/orchestrator-builder/m09-tools/rootfs \
  --controller-root /var/lib/orchestrator-builder/m09-tools/controller-rootfs \
  --output /var/lib/orchestrator-builder/m09-tools/process-pair-N \
  --kernel /boot/vmlinuz-6.12.113+deb13-amd64 \
  --initrd /boot/initrd.img-6.12.113+deb13-amd64
```

Compile changed executables into the trusted source root, chmod them 0755 and
update every `tools` digest in `rootfs/etc/tap-runtime/host.json` before generating
fresh images. Regenerate the platform canary archive/descriptor when its binary
changes. Never modify an image currently used by QEMU.

Current two-service slots: source app 333... reserves 64 MiB/100mCPU/32 PIDs;
app 222... reserves 512 MiB/1000mCPU/128 PIDs, fitting two 256 MiB/500mCPU/64-PID
services. Both include separate fixed daemon overhead and hard disk reservations.

Current transport fixture material: `process-trust-3/`; four-hour leaf certificates
under a six-hour lab CA. Generate new material with the lab `processlab prepare`
command if expired, copy private files into the proper trusted roots, preserve
UIDs 1000 (agent) and 1002 (controller), and regenerate images. Never log keys.

## Work still required before M09 can pass

1. Complete **real recovery/fault tests**: lost create/start/delete responses,
   kill agent at every durable-intent/resource/start/inspect/result/cleanup
   boundary; restart the agent on the same live VM/ledger; durable outbox retry;
   unknown engine objects retained; no duplicate effects or implicit adoption.
   Component fault tests for the GET-404 cleanup rule now pass; real VM fault
   injection remains outstanding.
2. Execute **real revocation/expiry** during operations and while idle: worker
   lease, certificate, approval, admission and current scan-policy changes;
   stop/quarantine owned workloads and drain ingress while retaining uncertainty.
   Exercise continuing authorization and finite restart allowance exhaustion,
   intentional stop fences and daemon/measurement-helper restart behavior.
3. Complete a **machine-enumerated R01–R10 constituent catalog and driver**.
   The current process-pair program is only a development happy-path driver.
   No constituent may be silently skipped, inferred from mocks or optionalized.
4. Execute real zero-mutation denial snapshots for every protocol/policy field,
   signature/key/worker/incarnation/app/expiry/generation/approval/cert/replay
   variant and concurrent duplicate race. Production agent remains outbound-only;
   use a distinct, fixed, private test fixture for injection, never generic exec.
5. Execute **network attacks with active positive controls**: actual management
   endpoint and inert host/metadata/external fixtures, IPv4/IPv6, cross-app,
   intra-app dependency, no public app ports, and confirmed relay removal. The
   platform canary's hardcoded blocked endpoints alone do not satisfy the full
   positive-control matrix.
6. Execute **resource exhaustion**: CPU, RAM/swap, PIDs, tmpfs and writable storage,
   image/unpacked cache, logs, deadlines and overlapping reservations. Demonstrate
   effective writable access before filling a quota; keep management responsive.
7. Execute actual **API/UI/account/credential/socket separation** and inventory
   permissions/mounts/processes, including Docker/libvirt/runtime credentials.
8. Deliver and test the **reproducible accepted runtime VM/host profile**. Current
   source roots use a development template hash and direct disposable QEMU lab
   launching. They are not an accepted production template or complete M04 host
   provisioning integration. Verify host-side VM cgroups/budgets/identity and
   preserve the separate management boundary; guest app limits alone are not
   complete host isolation acceptance.
9. Finish maintained-profile drift checks and actual failure variants. One pending
   improvement: verify managed `/etc/hosts`, `/etc/hostname`, `/etc/resolv.conf`
   readonly mount flags from kernel mountinfo, beyond hardener/configuration and
   nonroot write-denial checks. Treat any missing proof as non-ready.
10. Run the full M06/M07/M08 regression affected by Git permission normalization,
    plus full Go tests/vet, targeted races, bounded command fuzzing and reporter
    tests on final source. Freeze source/templates/policy, publish bounded safe
    evidence and refresh the source/evidence manifest and post-implementation test
    plan. Update required ledgers only from actual complete passing evidence.

The existing required ledger still has R01 FAIL and R02–R10 NOT_RUN. Its prose,
acceptance report and manifest mostly describe older increments and must be
updated carefully; do not erase failed evidence. The milestone reporter must
continue returning INCOMPLETE until every required constituent really passes.

## Immediate next implementation step

The six `Engine.Remove` component fault cases now pass under the race detector:
lost response after deletion, false success retaining the object, already absent,
inspection denied, foreign labels, and wrong app. Startup recovery now converts
pending commands to uncertain durable results, fences pending creates and retains
resources/capacity; its targeted recovery test passed. This recovery change still
needs real VM validation.

A fixed-enum disposable guest operator is partially implemented in
`infra/runtime/experiments/processlab/operator_linux.go`, with a bounded readonly
`Client.ObjectCounts` helper. The runtime guest script now invokes this operator.
**Do not run the changed pair harness until its host wiring is completed:** add a
private runtime serial control socket for guest `/dev/ttyS2`, hold the connection,
handle the controller's fixed restart request, and require actual changed agent
PIDs plus equal before/after object counts. Require final zero containers and
only the three builtin networks per app before disposable VM teardown. Record
proof in result JSON. Verify the new code compiles; rebuild trusted guest binaries
and refresh profile hashes. The last completed real VM run remains pair12, which
predates these recovery/operator changes. No QEMU process was running at save.

Then run the real same-ledger agent restart scenario, implement exact owned
abandoned-probe recovery, and extend bounded phase fault/revocation coverage.
Avoid unrelated product features or public control surfaces.

## Validation notes

Full Go tests/vet and targeted races/fuzz have passed at several development
checkpoints. New checks include durable candidate/restart budgets, cancellation
without engine callbacks, current grant refresh races and strict clock-offset
headroom, immutable admission binding, private Git content modes, and relay
sibling ownership. Re-run after the latest edits; old success is not a final
source freeze. Logs are under `/var/tmp/tap-m09/` (`full-tests-latest.log`,
`vet-latest.log`, `race-latest.log`, `fuzz-latest.log`, various trial logs).
