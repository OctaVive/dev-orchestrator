# Build and artifact admission contract (M07, version 1)

Status: implemented; acceptance evidence belongs to
[P1-M07](../PH1/P1M07/README.md).

## Build handoff

`contracts.CloneJob.Build` optionally predeclares `BuildSettings`: operator-owned
versioned build policy and a relative Dockerfile path. Its full serialized value
is part of the clone-attempt hash and private machine journal. Existing clone
jobs with no build settings retain M06 behavior.

`BuildJob` repeats the exact CloneJob, accepted SHA/context ID, settings, build
policy hash and expiry. Build policy binds the external M05 egress policy hash,
exact HTTPS upload origin, tool/database hashes, actual database UpdatedAt,
freshness, build/scan limits, artifact bounds and exact expiring exceptions.
No caller chooses argv, executable, host path, arbitrary environment or proxy.

`Store.BeginBuild` checks the matching successful clone attempt, immutable SHA,
context, version/generation/attempt and active lease. It commits BUILDING,
`build.started`, audit and both appropriate outbox records before dispatch.
Duplicate identical starts are idempotent only for the still-current attempt.
The backend repeats clone-result identity checks before authorizing execution.

The root-owned `.authorize` file is created by the VM supervisor and recorded by
device/inode/filesystem identity in its private journal. It accepts one bounded
strict JSON `BuildAuthorization` with the predeclared BuildJob and opaque upload
object ID/token. Unknown fields, different settings, wrong source/context,
conflicting replay and stale lease fail closed. Its final newline commits the
frame for delivery to raw ttyS1 input. Guest echo is disabled before cloning.
The file is never a generic command channel and is removed by owned cleanup.
Host time enforcement is armed before delivery and does not depend on the
controller or a responsive guest.

Guest clone outputs remain `M06 <CloneResult>\n`. After exactly one resolution
and one success, at most one `M07 <BuildResult>\n` may follow. BuildResult contains
job ID, policy hash, closed outcome and optional closed stage reason. Combined
serial output retains M06's 12,303-byte host cap; overflow terminates the VM.
Grant material is never emitted on the result channel.

## Upload and independent ingest

A separate artifact service issues a short-lived write-only grant bound to job,
deployment, attempt and generation. It reserves bytes before issue, allows one
committed opaque object and denies duplicate/concurrent writes to the grant.
Public TLS supports only PUT; private Unix control supplies issue/receipt/revoke/
promotion operations. Root-controlled private directories protect the socket.
Service restart invalidates grants, while preexisting opaque files remain
quarantined and count toward capacity. No upload token goes into metadata DBs.

The receipt binds a generated object ID, exact archive SHA-256, byte count and job
identity. `RecordBuildExport` CASes BUILDING to SCANNING and records that receipt
atomically with event/audit/outbox data. Archive SHA-256 is not the image digest.
The builder is destroyed before a fresh no-network ingest VM is created.

The scanner backend attaches a sealed length-prefixed `TAPBLD01` job device,
read-only exact artifact bytes and a separately pinned read-only database image.
Host code hashes opaque bytes but never interprets OCI or scanner content.
Ingest machine journals use `IngestVersion: 1`; unsupported versions and changed
job/receipt/ownership identities fail closed. Original build and ingest VM IDs
are distinct. Crash reconciliation inventories only exact matching build
bindings and cleans those scanner VMs before another scan starts.

Inside the VM, UID 1000 validates the OCI layout and digest graph without
extracting layers. It cannot write ttyS1. Trusted init kills all validator
processes, freezes the validated layout under root ownership and starts the
scanner phase as UID 1001 with separate scratch. Trivy reads the layout offline;
it cannot modify the original read-only upload or the frozen view. Malformed
archives use a fixed denial path without invoking the scanner.

`M07 <ArtifactResult>\n` contains only matching job/deployment/attempt/generation,
policy hash, archive/manifest/tool/database/report/SBOM digests, closed outcome
and bounded severity counts. Decoder/result capture caps are 8 KiB plus framing.
No guest-supplied path, raw finding, repository output or transport error is a
management command or event field.

## Admission, recovery and approval

Passing validation/scanning promotes the original opaque uploaded bytes into a
content-addressed store using fsync plus atomic publication. Only then does a
transaction persist the immutable artifact result and manifest digest with
`scan.admitted`, audit and build outbox. Deployment remains SCANNING. Admission
is eligibility for M12 approval, which must bind the current source, digest,
policy, ACL and M08 normalized spec; it is not permission to deploy.

`ResumeIngest` accepts only a durable exported receipt under the same current
identity. It cleans prior scanner VMs, verifies receipt identity, reruns scanning,
retries identical promotion and CASes admission. Completed admitted retries return
the same immutable result. A completed promotion without a committed admission
is an orphan, never an implicitly approved artifact. Service loss, cancellation,
stale generation, expired policy/lease and different content deny recovery.
Failure recording remains possible after expiry but can never grant admission.

Migration 003 adds build attempts, immutable build events/outbox and deployment
image-digest protection. Existing databases require the explicit verified-snapshot
upgrade workflow. Dispatchers consume build outbox separately from state and
clone queues, deduplicating immutable event IDs. Pending object cleanup,
reservations and uncertain ownership remain visible until confirmed; full
scheduling/reconciliation orchestration remains M12.

Numeric compatibility/resource policy and reproducible setup are in the
[build runbook](../../../infra/build/README.md) and
[ingest runbook](../../../infra/ingest/README.md).
