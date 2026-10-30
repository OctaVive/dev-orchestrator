# Runtime execution protocol v3 (M09 implementation in progress)

The execution envelope is [runtime-v3.schema.json](../../../api/runtime-v3.schema.json).
M08 runtime spec v2 keeps its existing meaning. Legacy v1/v2 envelopes never
authorize execution. Runtime agents accept normalized JSON only.

Every command binds a UUID worker/incarnation, app/deployment, integer app
generation, UUID command ID, unique 32-byte lowercase-hex nonce, current policy
hash, spec hash, key ID and canonical UTC expiry within five minutes. Supported
operations are probe, prepare, create, inspect, logs, stop and remove. Prepare and
create embed the complete spec; inspect/logs/stop/remove reference the original
create command ID. A caller cannot select a Docker ID, host path, shell or API path.
Logs request at most 16 KiB of decoded bytes. Signature verification does not
replace trusted current admission, approval and worker lease checks.

## Signing and durable state

Signing bytes are `tap/runtime-command/v3` followed by NUL and Go encoding/json of
the declared Command struct with signature omitted. Struct field order follows
`internal/runtimeagent/command.go`; map keys are sorted by encoding/json. Array
order is preserved. Optional zero-valued target/spec/log_limit fields are omitted.
The complete embedded spec is signed, in addition to its M08 canonical spec hash.
No raw input bytes, alternate whitespace or arbitrary JSON maps are signed. JSON
unknown fields, duplicates, case aliases, noninteger numbers and trailing documents
are denied before authorization. Ed25519 signatures use strict padded base64.

The private agent SQLite database has a distinct application ID/version, WAL,
FULL synchronization, foreign keys and an exclusive process lock. Worker and
incarnation cannot change on reopen. Command/nonce uniqueness, request hashes,
app generation fences, stopped targets, engine object IDs and expected settings
are durable. No ledger compaction or automatic reset is implemented.

Identical completed retries return recorded bounded results without engine
mutation, after current validity/lease checks. Conflicting IDs/hashes or nonces
fail. Pending/uncertain operations never execute again automatically. Multiple
lifecycle commands can use the same deployment generation; a second create
identity for that generation cannot restart it. Cleanup of an older generation
requires a separately signed command bound to its exact original target.

An intent is committed before engine operations. There is no SQLite/Docker
transaction. A crash or lost create response can leave an object whose exact ID
was not recorded; this is an incident, not permission to adopt/delete by label.
Reservations must remain held until independently confirmed cleanup. Failed
create attempts request bounded cleanup of recorded owned resources and still
report uncertainty. Engine drift or foreign objects never grant deletion rights.

## Identity, capabilities and artifacts

Polling is outbound HTTPS with TLS 1.3, client certificates, normal server chain/
name validation, exact controller URI identity and SPKI pin, redirects/proxies
disabled, finite deadlines and one command per response. Certificate revocation
is checked during handshake and on every response, including reused connections.
Lease validation remains mandatory for execution. Rotation constructs a new
client with the explicitly provisioned overlapping trust/pin policy.

Capability inventories bind worker/incarnation, fresh challenge, template/policy
hashes, kernel/engine/API/daemon identity and every required control. Their
validity is at most one minute. Inventory signatures use the separate domain
`tap/runtime-inventory/v1` followed by NUL and JSON with signature omitted. They
are worker assertions, not hardware attestation. The engine requires a trusted
measured enforcement adapter; engine info flags alone cannot establish readiness.
There is currently no shipped production enforcement adapter.

The separate runtime artifact handler requires a verified mTLS runtime-agent URI
and trusted current authorization for the presented certificate fingerprint and every identity in RuntimeClaim. It serves
only an immutable opaque archive digest/byte count returned by that adapter;
there is no listing, range, caller path or reuse of builder upload grants. It
checks file mode/type, refuses symlinks, rehashes opaque bytes, bounds concurrent
streams and rechecks revocation before/during transfer. The runtime transport
spools and verifies full archive size/digest before the engine import. No OCI
parser is added to management. Current admission lookup and scan revocation must
be supplied through trusted durable adapters, never a guest/browser map.

## Current implementation limits

`internal/runtimeagent` supplies authorization and the durable ledger;
`internal/runtimeengine` supplies typed request construction, ownership/inspection,
image transfer integration and bounded lifecycle methods; `internal/runtimerpc`
supplies mTLS polling and artifact transfer. None is connected to a production
runtime daemon or management endpoint yet.

The engine adapter targets API 1.47; this is a wire contract, not an accepted
engine version. Real-engine compatibility is still pending. Nonempty persistent
volume/secret mounts fail before mutation until M10. Nonzero restart attempts
currently fail before image/network/container mutation; durable restart dispatch
is unfinished. Capacity, enforced network rules, measured canaries, runtime
service wiring and full recovery/quarantine integration remain unfinished.

Do not schedule workloads or claim M09 acceptance from the unit tests. The M09
acceptance report must include real rootless enforcement and all required cases.
