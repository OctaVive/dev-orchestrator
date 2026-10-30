# Version 1 protocol contracts

`openapi.yaml` describes implemented P1-M03 auth/setup/status routes and explicitly labels **future** deployment routes. Deployment, agent and login schemas are enforced by `internal/contracts`; common definitions resolve from embedded resources without network loaders. Schema IDs under `.invalid` are identifiers, not endpoints to fetch. The login schema is input-only, rejects role/session claims, and is used for login/setup; stronger new-password policy is enforced by the auth service.

## Data boundaries

P1-M04 adds `build-lease.schema.json` and a **separate** `provisioner.openapi.yaml`. Controller authority is mTLS URI SAN + explicit CA/leaf pin, never the portal session or a JSON identity field. The shipped command has no executable VM backend. Read [the remaining Linux gates](../docs/project/PH1/P1M04/build-provisioner.md) before treating any lease test as isolation evidence.

- Browser deployment intent never contains image approvals, raw Compose, Docker options, proxy config or host paths. Admin/CSRF/app ownership/allowed origin checks must precede enqueue in future handlers.
- A trusted controller produces normalized agent specs only after clone/build/scan/approval. The agent independently applies current policy. `restricted-v1` is immutable in meaning: private namespaces/network, no host publication, non-root, dropped capabilities, no-new-privileges, read-only root, bounded writable mounts/resources/logs and required seccomp. Do not add a caller-controlled opt-out field.
- Optional env and argv are application data, not control-plane configuration or host shell input. Runtime secret references and lifecycle commands beyond `deploy` will need separately reviewed versioned contracts; they are not currently accepted as unknown fields.
- Resource values are **upper schema ceilings**, not granted capacity. Operator/app quota, aggregate service totals and actual host capabilities may impose lower bounds. Approved registry and app-owned volume validation are additional semantic checks.

## Command signing and replay contract (implementation deferred to M09)

Use Ed25519 with a trusted controller signing key resolved by `key_id`; never accept a public key supplied inside a command. Sign RFC 8785 canonical JSON of the full command object **excluding only the top-level `signature` property**, prefixed with UTF-8 `dev-orchestrator/agent-command/v1\n`. All identity, action, generation, expiry, nonce, policy and service fields are covered. Signature is canonical padded standard Base64 of 64 bytes.

Before typed normalization, verify against the parsed original object with duplicate keys rejected. Do not normalize date-time strings, optional fields or number representations before signature verification. Version 1 accepts only decimal integer number tokens (no exponents/fractions) and limits generation to 2^53−1. Canonicalization implementation must pass RFC test vectors; JSON Marshal alone is not a substitute for JCS.

After signature/role/policy/worker checks, agent atomically reserves command ID and nonce and compares **per-app** monotonic generation in durable state. Same command ID/same payload may return its stored idempotency result; same ID/different payload is denied. Reserve before effects; reconcile uncertain engine results after crash before retry. Invalid signatures must never consume a valid generation. A valid signature is not sufficient to bypass current hard policy or volume ownership.

Current `DecodeAgentCommand` checks shape and basic context only. Its `LastGeneration` is a preliminary supplied per-app value, not durable replay protection; it intentionally cannot execute anything. Fixture signatures are all-zero bytes and must fail future signature verification tests.

Changing profile semantics, adding control authority or widening accepted values requires security review, migration/compatibility strategy and new negative tests. Unknown versions/fields fail closed.

M08 adds [agent envelope v2](agent-v2.schema.json), decoded by
`agentpolicy.Decode` with independent semantic policy and a trusted local
admission/ownership resolver. It binds source/context, normalized plan, per-service
image admissions and a canonical spec hash. This gate is not signature verification
or replay authorization; M09 must supply both before engine operations. The v1
agent decoder remains a shape-only legacy fixture contract. No public deployment
endpoint or agent execution endpoint is introduced by M08. See the
[configuration policy](../docs/project/specifications/configuration-policy.md).
