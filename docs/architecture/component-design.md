# Component design, secrets and persistent storage

| Component | Responsibility | Must not possess |
|---|---|---|
| Portal | Admin forms, progress, app catalog and frame shell | Engine access, service keys, Git tokens |
| API/auth | Sessions, RBAC, app ACL, metadata, validated intent | Docker/libvirt sockets |
| Controller | State transitions, policy compilation, leases, reconciliation | General shell/host API authority |
| Provisioner | Fixed build VM creation and destruction | User-controlled VM XML or management DB access |
| Builder | Clone/build one commit, bounded export | Management secrets, runtime storage, registry credentials |
| Ingest/registry | Quarantine, digest verification, immutable artifact serving | Arbitrary access to management services |
| Scanner | SBOM, vulnerability and image-config evaluation | Runtime/deployment credentials |
| Runtime agent | Validate spec, pull digest, create/stop apps, volume lifecycle | Other workers' credentials, general control-plane authority |
| Edge/relay | Enforce auth, exact routes, tunnel traffic | Docker socket, deploy API permissions |

## Protocol contracts

All internal protocols use TLS with pinned private CA identities and role/worker SAN checks. Prefer outbound runtime polling over opening management-to-agent control listeners. Short-lived certificates (initial target 24 hours), automated renewal, overlapping rotation and revocation denylist. Agent bootstrap uses single-use, expiring enrollment tokens through an operator-authenticated path. Loss of identity or control-plane auth must not create public routes. Existing HTTP authorization fails closed; WS sessions close when authorization lease expires.

Deployment spec: schema version, app/deployment/worker IDs, image digest(s), policy version/hash, UID/GID, bounded resources, named managed volumes, secret references, networks, health probe, allowed egress and generation. Never raw Compose, shell scripts, host paths or proxy directives. Sign controller commands or use equivalent authenticated durable envelopes; mTLS alone does not prevent replay of queued commands. Agent stores last accepted generation and idempotency result.

## Secret lifecycle

- Master encryption key resides outside SQLite under OS/service access controls, preferably TPM/external key service later; back it up separately. Envelope encryption with key version and authenticated context for TOTP, Git credentials and runtime secrets.
- Git read credentials are repository-scoped, short-lived where available. Credential broker handles authenticated approved-origin fetches; no token in clone URL, `.git/config`, CLI args, build context or logs. PH1 may prohibit private repos until broker path is proven.
- Runtime secrets are versioned references. Agent materializes per-app tmpfs files, read-only, least-readable UID, or narrowly scoped env only if needed. App processes inherently can read and exfiltrate their own secrets. Builds never receive runtime secrets.
- Build dependency credentials are unsupported initially. Later use mediated artifact mirrors; BuildKit secret mounts alone do not prevent malicious build scripts from reading/exfiltrating secrets.
- Strip `.git`, credential helpers and transient fetch files from build context. Never mount agent sockets or credential stores into apps.
- Logs: bound size/rate; remove known tokens before persistence; escape control sequences in UI; no debug body/header dumps. Redaction is best effort, not a guarantee against encoding. Confidential builds with unrestricted public egress are not supported.

## Persistent volumes

Each volume has immutable app and worker ownership, logical ID, quota, backup policy, mount target, UID/GID and lifecycle state. Agent resolves IDs to its managed root, rejects symlink/path traversal and validates mount targets. API never accepts host paths. No cross-app volume attachment, bind mounts or shared SQLite database volumes. No automatic anonymous volumes from image declarations.

Use quota-capable storage (validated filesystem project quotas or bounded per-app disks); Docker named volumes alone do not guarantee quotas. Reject requested persistence if quotas cannot be enforced. Rootless UID mappings and backup restore ownership must be tested. Managed volumes are outside container writable layers but inside runtime VM disks.

Deletion requires stop/drain, route removal and explicit separate volume-delete confirmation with retention window. Failed deployments remove ephemeral volumes only; never destroy existing app data. Orphan cleanup uses ownership metadata, grace period and audit, not name prefix alone.

## Backup contract

Metadata: SQLite online backup API, key material backed up separately, checksum, encryption and off-host retention. App data: application-native backup or quiesce before snapshot; no promise that copying a live SQLite file is consistent. Registry: retain digests referenced by current, candidate and rollback generations. Restore drill verifies DB integrity, identities rotated, volume ownership, routes still private, then app health. A backup without a tested restore does not satisfy recovery acceptance.
