# PH1M06 isolated clone worker

The clone runner executes only inside a fresh pinned KVM guest. Management
validates typed input/results and persists metadata; it never invokes Git on
untrusted source or mounts a guest-modified disk. This folder does not enable
production services or implement BuildKit.

## Interfaces and limits

`contracts.CloneJob` binds job/deployment/lease IDs, attempt, generation,
deadline, template digest and clone policy hash. `ClonePolicy` uses exact
hostnames, which must also be allowed by the external M05 broker. Empty hosts
deny. Limits can be reduced or increased only within `CloneLimits.Validate`
maxima; repositories cannot select them.

| Resource | Default | Fixed maximum |
|---|---:|---:|
| Clone duration | 300 s | 600 s, also bounded by remaining lease |
| Advertisement encrypted transfer | 4 MiB | 16 MiB |
| Advertised heads | 4,096 | 16,384 |
| Total encrypted transfer, including advertisement | 256 MiB | 1 GiB |
| Objects | 100,000 | 200,000 |
| Single expanded object | 64 MiB | 128 MiB |
| Sum of expanded objects | 2 GiB | 4 GiB |
| Tree entries, including directories | 50,000 | 100,000 |
| Tree depth | 32 | 64 |
| Path bytes | 1,024 | 4,096 |
| Exported context bytes | 1 GiB | 2 GiB |

Git stdout limits derive from the operation/policy; stderr is capped at 64 KiB
per invocation and never forwarded to management. The local guest meter permits
four simultaneous connections to the fixed M05 listener only. Its byte count
includes TLS/framing/request overhead. The external broker's independent caps
may impose stricter limits. The reviewed fixture uses a 2,300 MiB private tmpfs
workspace, 512 guest PIDs and the existing M04 host CPU/RAM/disk/lifetime caps;
workspace exhaustion fails closed even below a configured context maximum.

SHA-1 repositories accessible without credentials are supported initially.
Authentication, SHA-256 repositories, gitlinks/submodules, `.gitmodules`, all
`.gitattributes`, `.lfsconfig`, LFS pointers and unsafe contexts are rejected.
Internal symlinks and executable file modes are preserved. Config files must be
regular tracked files inside the selected context. A moving branch either
produces the original resolved commit or a structured failure with that SHA;
the runner never silently builds its new tip.

## Immutable input and bounded output

The backend explicitly opts in with `clone_enabled: true` and `broker-v1`.
`Machine.Clone` is a host-internal authorized intent, not a public request or a
shell command. The Linux backend validates identity, template, expiry and the
broker's host allowlist before creating resources.

The job device consists of `TAPCLN01`, a four-byte big-endian JSON length, one
strict JSON object and zero sector padding. A sealed memfd is reopened read-only
and supplied through a QEMU FD set as `/dev/vdb`. There is no extra host input
file to recover or guest writable host share. Job fields are retained in the
private ownership journal; clone journals carry `CloneVersion: 1`, while old
no-clone journals remain readable. Unknown versions fail closed.

`/dev/ttyS1` emits `M06 <JSON>\n`: at most one resolution followed by one terminal
result. Each JSON payload is at most 4,096 bytes. The supervisor caps the entire
channel at 12,303 bytes, kills QEMU on overflow and fsyncs data into its existing
owned `.ready` inode. Readers verify journal/fence/inode/lease and active guest
status before decoding. Guest assertions are never proof that source is safe.

`clonejob.Driver` accepts an already-reserved fresh VM and authorized storage
intent. It persists resolution and terminal outcome transactionally before
returning a successful context handoff. The same guest retains the opaque
context ID and `/work/context-ready` for M07. Call `Release(machine, job)` after
use; failures clean up immediately, and independent hard expiry remains active.
Full controller scheduling/reservation integration remains M12. Existing
provisioner RPC shapes are unchanged.

## Metadata migration

Migration 002 adds clone attempts, append-only clone events, a separate clone
outbox and immutable SHA/binding constraints. The separate queue preserves the
original state-transition-only deployment event contract; future dispatchers
must consume both queues. SHA/result, audit and clone outbox commit atomically.

Fresh metadata databases bootstrap both migrations. Existing databases continue
to refuse automatic upgrades. Stop all metadata writers, build/review
`cmd/metadata-upgrade`, and run it with `-database <existing-db>` and
`-backup <new-snapshot>` in private directories. It creates a consistent SQLite
snapshot, checks integrity/history, fsyncs and prints its SHA-256 before
transactionally migrating. Preserve and independently verify that snapshot.
Rollback requires stopping writers and restoring the complete pre-upgrade
snapshot with its matching older binary; do not delete migration records or
manually downgrade live data.

## Disposable lab

Reuse a clean M05 isolated Debian KVM lab, with KVM/TUN/systemd/nftables, the
existing dedicated QEMU/broker accounts and at least 12 GiB free. Review the
scripts first. The user-authorized execution is explicitly opt-in:

```sh
umask 077
M06_LAB_APPROVED=YES-I-AUTHORIZE-CLONE-LAB \
  python3 infra/clone/lab.py --lab /var/lib/orchestrator-builder/m05-lab.<id>
```

The harness creates separate binaries, keys, config, ownership journals and a
reproducible clone fixture image; it never replaces base M04/M05 configuration
or enables services. The image contains public tools/CA only, with a package
manifest and source/binary hashes. Its trusted init drops to UID/GID 1000 before
running Git and injects poisoned Git settings plus execution sentinels for tests.
It verifies fixture context content, executable mode, safe link behavior and
absence of `.git` without executing source. Fixture markers use a fixed disk
tail; the host reads only that bounded marker, never a guest filesystem.

The controlled origin constructs known pack/object bytes without invoking Git
or parsing repositories on the host. It exposes synthetic public-class aliases
only on this VM's loopback, controlled DNS, an approved HTTPS origin and denied
destination canaries. A separate temporary upstream CA enters the isolated
host trust store. `finally` restores trust, aliases and fixture processes, and
checks unchanged base configs/firewall and absent working guest disks.
Packet captures and per-case results remain in the printed private evidence
directory. No production destination/TLS bypass exists.

`--cases <comma-separated-names>` is a development subset and cannot establish
acceptance. The full harness requires every corpus case and named lifecycle,
foreign-resource, crash, race and durable-adapter test to PASS with no SKIPs.
See the milestone's test plan and acceptance report for actual results.
