# Restricted clone-worker contract

PH1M06 implements a one-job clone operation inside a fresh pinned KVM VM.
Its versioned Go DTOs are in `internal/contracts/clone.go`; the detailed
[policy, transport and operator runbook](../../../infra/clone/README.md) records
numeric limits and supported features. Public deployment intent validation shares
the same URL/ref/path rules. Origin approval and external egress checks remain
mandatory after lexical validation.

## Intent and identity

An authorized controller supplies job ID, deployment ID, lease command ID,
attempt, generation, absolute expiry, template digest, approved clone policy and
its hash, canonical HTTPS repository URL, branch, config path and build context.
There are no caller-selected commands, host paths, credentials, Git environment
or executable/proxy arguments. Host approval restricts policy hosts to the
external broker's allowlist and binds the job to its assigned VM/template/lease.

`Machine.Clone` is host-internal. PH1M06 does not expand the public provisioner
RPC or implement the complete M12 scheduler. Scheduling must reserve resources
before invoking `clonejob.Driver.Execute`; uncertain cleanup retains that
reservation. Successful clone retains the same guest for M07, with independent
hard expiry still active. Its owner must call `Release(machine, job)` after use.

## Guest operation and handoff

The supervisor attaches a sealed read-only job device and captures a capped
serial result channel. Only the fixed unprivileged guest runner invokes Git.
It resolves `refs/heads/<branch>` to a full SHA-1 commit ID and emits resolution
before fetching that immutable ID. It never substitutes a new branch tip.
It validates all fetched objects/tree entries, rejects unsupported features,
and exports tracked files into a clean directory without checkout filters or
`.git`. Symlinks must remain contained after context rebasing; both direct and
directory-link cycles are denied.

The exported root is the selected subtree. Config paths are repository-relative
in the intent; M07 derives the config path relative to that root by removing
`build_context + "/"` when the context is not `.`. Config must be a tracked
regular file within that subtree. No guest path is accepted by management.

Results bind the complete identity tuple and contain only SHA/object format,
closed outcome, context ID and bounded statistics. Outcomes are `resolved`,
`success`, `error`, `denied`, `limit`, `timeout`, `cancelled`. At most a resolution
and one terminal frame are permitted; an early terminal failure has no SHA.
If a later fetch/export fails, retain the previously resolved SHA and return
no context ID. Raw repository diagnostics never become result/event fields.

Context identity binds the job, policy hash, SHA and selected subtree. The
guest-local `/work/context-ready` descriptor is consumed only in that same
disposable guest. Guest assertions do not establish source trust or replace
M07's independent artifact validation. No build starts before complete context
validation and durable resolution/result acceptance.

## Persistence and failure

`clone_attempts` binds deployment/attempt/generation, expected deployment version,
lease, expiry, policy/template identity and job hash. A result is accepted only
in matching `CLONING` state/version/generation/attempt before expiry. Identical
replies are idempotent; conflicting SHAs, stale identities, terminal changes and
late cancelled/expired replies deny. Deployment SHA remains immutable.

Resolution/result, deployment SHA/version, branch observation, append-only
clone event, audit and clone outbox write in one SQLite transaction. Clone
events use a dedicated outbox because the existing deployment event table only
accepts state-transition names. M12 dispatch must consume both queues; delivery
is at least once and consumers deduplicate by event ID.

The host driver independently applies the earliest caller deadline, clone-policy
timeout and job expiry, so a silent runner cannot extend cloning to the VM
lease maximum. A policy/caller deadline records `timeout`; explicit caller
cancellation records `cancelled`. Independent host VM expiry remains the
backstop if the controller itself is lost.

Failure/cancellation destroys the owned guest through the existing provisioner,
revokes its broker and fences delayed starts. Confirm guest, network and disk
removal before releasing reserved capacity. Expiry works independently of the
controller and guest/broker supervisors. Never reuse a failed workspace or a
guest that has parsed untrusted content for a different job.
