# P1-M06 implementation plan — bounded isolated Git clone

Status: **Implemented/tested; isolated-KVM acceptance PASS**. This document retains the
delivery contract and agreed decisions; see [implementation evidence](implementation-evidence.md)
and the [post-implementation test plan](test-plan.md).

## Outcome and scope

Fetch an approved HTTPS repository branch inside a fresh M04/M05 build VM, record its exact commit SHA, and export a bounded tracked build context without `.git`. The acceptance gate is **rebinding/helper/submodule/redirect corpus denied, SHA recorded**, including external SEC-07 evidence.

Prerequisite: [M05 acceptance](../P1M05/README.md). Preserve M04's V14/V15 SKIP qualifications. This milestone delivers clone execution and its narrow integration boundary; BuildKit, OCI ingestion/scanning (M07), Compose/Dockerfile normalization (M08), the complete controller (M12), and private Git credential mediation remain separate work. Initially support repositories accessible without credentials; reject authentication requirements without prompting or falling back to helpers.

Authoritative contracts: [Git/build pipeline](../../../architecture/git-deployment-pipeline.md), [worker lifecycle](../../specifications/deployment-agent.md), [test strategy](../../specifications/testing-strategy.md), and [phase plan](../../../plans/PH1/minimal.md).

## Foundation at implementation start

- `internal/contracts/validator.go` checks repository URL, branch and context path lexically. It explicitly does not enforce origin approval or network destinations. Reuse a shared validator at both request and runner boundaries rather than maintaining divergent rules.
- `internal/provisioner` and `internal/provisionerrpc` own bounded fixed-template VM leases and cleanup. `internal/egress` and `infra/egress` supply broker mediation and the real-host network harness. Neither constitutes a Git runner or a general guest command channel.
- `internal/storage/deployments.go` provides transactional deployment transitions/outbox events. `migrations/001_core.sql` already has `deployments.commit_sha` and `git_branches.last_observed_sha`, but the storage API and event payload do not record clone resolution.
- Current lab images are fixtures, not production clone-worker templates. Add a reproducible, pinned runner image and bounded job/result delivery before claiming end-to-end execution.

The sequence below records the agreed implementation targets; the evidence and runbook describe their delivered interfaces.

## Delivery sequence

### 1. Define the clone contract and policy

Add typed request/result and reason codes in `internal/contracts`, with strict bounded decoding and unknown-field rejection. Bind each invocation to job/deployment ID, attempt, generation, lease ID/deadline, template identity and approved policy hash. Inputs include the approved repository URL, branch, config path and build-context path; callers cannot supply command lines, environment, executable paths, proxy overrides or arbitrary Git options.

Require HTTPS, exact approved hostname and port 443; reject userinfo, queries, fragments, ambiguous encoding, IP literals and alternative Git transports. Validate branch syntax as a branch ref, resolve only `refs/heads/<branch>` and reject ambiguous/missing/duplicate responses. Never pass an input as an option or interpolate it into a shell. Share lexical validation with deployment requests and repeat policy checks in the guest.

Selected resource policy: conservative operator-configurable limits within fixed host maxima; retain the five-minute clone and 1 GiB context defaults. The remaining numeric defaults and maxima are frozen in the [runbook](../../../../infra/clone/README.md). Define operator-owned positive limits for advertisement bytes/ref count, transfer bytes, pack/object count and individual/expanded object size, tree depth, path length, tracked entries, context bytes and output/log bytes. Set the architectural defaults of five minutes and 1 GiB checkout; freeze the remaining numeric defaults and fixed maxima in a versioned policy before implementing execution. The effective deadline is the earliest clone deadline, cancellation or lease expiry. Account for `.git`, temporary packs and export staging within the guest disk envelope; shallow fetch alone is not a resource limit.

Result contains the full lowercase commit object ID and supported object format, policy/template identities, bounded context statistics, and structured outcome. Selected compatibility profile: support SHA-1 Git repositories initially and explicitly reject SHA-256 repositories. Validate the declared object format and full object ID; do not infer format solely from a string's length. Submodules, LFS-dependent content and required checkout filters remain unsupported. Host paths, raw Git diagnostics and repository file content are never result fields.

### 2. Deliver one job to a pinned guest

Add `cmd/clone-runner`, backed by `internal/cloner`, and a reproducible image recipe under `infra/builder`. Pin maintained Git and CA packages and record versions/image hashes. Start with an explicit empty environment, fresh private HOME/config/work directories, an unprivileged runner account and enforced guest process/storage limits. Retain host-enforced M04 quotas and hard expiry.

Selected transport: an immutable one-job input device and a dedicated bounded serial result channel. Specify and review device format, framing and capture limits before extending provisioning. Any extension must use host-owned descriptors, strict framing, job identity checks, output caps and lifecycle ownership; no generic exec RPC, host filesystem share, management network endpoint or command supplied by a caller. Keep existing no-network/probe templates usable and cleanup compatible. If serial output is introduced, explicitly replace M04's no-serial-log assumption with bounded capture; never enable an unbounded host log.

Pass only the public build CA, assigned broker endpoint and non-secret scoped job data. Proxy configuration comes from trusted policy. Do not attach runtime secrets or management credentials. Treat guest results as untrusted bounded assertions, never host commands or filesystem paths. A compromised guest cannot establish trustworthy source provenance by self-report; M07 and later approval checks retain their independent duties.

### 3. Resolve and fetch an immutable revision

Run all Git object/ref parsing inside the VM. Use a fixed Git executable with argv execution, no shell, prompts disabled, system/global config disabled, an empty controlled local config and hooks directory, credential helpers disabled, and transport allow rules permitting HTTPS only. Disable redirects, recursive submodules, LFS, automatic maintenance, replace objects and checkout filters. Ignore inherited Git, proxy and loader environment variables; set only reviewed values. Preserve TLS verification using the build CA and M05's upstream validation.

Bound remote advertisement before accepting the selected branch SHA. Persist that SHA through the integration adapter before context handoff. Fetch only the selected revision with shallow history, no tags and no submodule recursion. Verify the fetched object is a commit matching the recorded SHA; do not re-resolve the branch for checkout. If the server cannot provide that exact object, fail without silently fetching a new tip. A branch moving after resolution may only produce the already-recorded commit or a structured failure.

Cap process output as it streams, transferred bytes and elapsed time. Apply VM disk limits plus pack/object/tree inspection limits before export. Reject unsupported features rather than enabling helpers. Terminate the whole runner process group on failure/cancellation; hard VM expiry remains the external backstop.

### 4. Validate and export the tracked context

Inspect the fetched tree without a normal working-tree checkout or repository-controlled filters. Reject gitlinks/submodules, `.gitmodules`, LFS-required attributes/pointers and filter-dependent content according to a documented fail-closed feature policy. The initial policy rejects every `.gitattributes` file; it never executes a filter to discover whether it is needed. Hook/filter fixtures must demonstrate that no execution occurs.

Export tracked regular files and supported symlinks into a fresh private directory, excluding Git metadata and untracked files. Preserve only regular/executable mode and safe symlink semantics. Reject absolute/traversing paths, metadata aliases, duplicate/colliding paths, special file modes, excessive nesting and symlinks resolving outside the context. Check symlink chains/cycles and create entries through directory-relative operations that cannot follow repository-controlled links. Test filename bytes, case collisions and platform-specific aliases explicitly.

Require the selected context directory and config file to exist within the validated tree; the config must resolve to a bounded regular file. Keep all exported data inside the same disposable VM for M07. Return an opaque context identity bound to the job and SHA, never an export path to be extracted by management. No build starts before the complete context passes validation and the SHA is durably recorded.

### 5. Persist resolution and fence stale results

Extend the storage API to record a clone resolution only for the matching deployment in `CLONING`, expected version/generation/attempt and active lease binding. Atomically write the immutable deployment SHA and a bounded `clone.resolved` event/outbox entry. Selected persistence design: add a dedicated clone-attempt table through a migration, binding deployment, attempt, generation, VM lease, policy identity, resolved SHA and outcome. Preserve retry history and enforce uniqueness and stale-result fencing. Retain the existing deployment commit SHA as the accepted revision for downstream stages; update it and the attempt record/event/outbox atomically when accepting resolution. Updating branch observation must never rewrite an earlier deployment's SHA.

Same-identity/same-SHA retries are idempotent; conflicting SHAs, expired/cancelled attempts and late results fail closed. Test transaction rollback and crash/retry around resolution. Retain a successfully resolved SHA if later fetch/context validation fails, while recording the failure separately. Supply a narrow orchestration adapter/test driver now; leave full scheduling and state-machine automation to M12. An adapter must not transition to `BUILDING` until context success and durable resolution are both confirmed.

On cancellation, timeout or runner loss, revoke broker sessions and release the VM through the existing lifecycle. Preserve capacity reservations until owned-resource cleanup is confirmed. Failed or interrupted contexts are never reusable; retries receive fresh guests. Sanitize diagnostics to closed reason codes and bounded counters, excluding URLs with sensitive components, headers and raw repository-controlled stderr.

### 6. Package validation and evidence

Add inert fixture definitions/generators under `tests/fixtures/git` with an inventory identifying consumers and expected outcomes. Construct bounded known object/pack bytes without Git on the host; parse hostile Git and execute all workload probes only in budgeted disposable guests. Extend the M05 isolated-lab harness for actual Git clients and controlled HTTPS/DNS endpoints; do not substitute the existing network probe for clone acceptance.

Selected acceptance environment: reuse the M05 disposable KVM lab after verifying its current availability, isolation and baseline configuration. Extend its harness with Git-specific fixtures. This planning choice does not itself authorize host changes; preserve the lab workflow's explicit execution controls. If the lab is unavailable or no longer isolated, record the blocker and leave real-host acceptance pending.

Record a milestone test plan and actual evidence separately. Capture source revision, Git/runner/QEMU/kernel versions, template/policy hashes, commands, fixture IDs, exit statuses, bounded logs, packet/broker evidence and cleanup results. Update the milestone README, fixture inventory, LLD, requirement evidence, progress and status indexes only to the level established by those results.

## Required verification matrix

| Gate | Required checks and evidence |
|---|---|
| C01 — input policy | URL/ref/path fuzz and table tests; disallowed transports, option injection, encoding ambiguity, origin mismatch and malformed job envelopes denied. |
| C02 — Git isolation | Poisoned system/global config, environment, hooks, helpers, URL rewrites and credential prompts cannot affect execution; sentinel payloads never execute. |
| C03 — immutable SHA | Happy path records the full SHA; branch movement, missing commit, malformed/duplicate advertisement, mismatch, crash/retry and conflicting result cases fail or retain the original immutable binding. |
| C04 — unsupported features | Submodule/gitlink, recursive URL, LFS and smudge/filter corpus denied without secondary fetching or execution. |
| C05 — safe context | Ordinary and executable files export correctly; `.git` absent; path traversal, symlink escape/chains/cycles, special modes, collisions and config/context escapes denied. |
| C06 — budgets | Oversized advertisements, packs, expanded objects, deep trees, many files, disk exhaustion, stalled servers and log floods terminate within limits without uncontrolled host output. |
| C07 — SEC-07 | Actual Git through M05 mediation: rebinding, mixed A/AAAA, mapped IPv6, metadata/management targets, redirects including same-origin, TLS mismatch and direct network bypass denied with external broker/firewall evidence. Approved HTTPS clone succeeds. |
| C08 — lifecycle | Cancellation during resolve/fetch/export, lease expiry, runner crash, late result and controller loss cause bounded termination and confirmed cleanup; foreign-resource canary remains intact. |
| C09 — durable handoff | SHA/event/outbox atomicity, replay fencing, context failure after resolution and no build dispatch before accepted context are verified through storage/adapter integration tests. |

Use `go test ./...`, targeted race tests for new concurrent code, bounded fuzz runs for parsers and `go vet ./...` for software validation. Privileged execution/network cases require the isolated KVM harness and must report PASS/FAIL/SKIP/Not run separately. Guest Git integration tests run in the disposable guest, not by parsing hostile objects on the management host.

## Completion criteria

All C01–C09 checks must have recorded passing evidence for acceptance; missing real-host SEC-07 or lifecycle evidence leaves the milestone pending. The handoff to M07 consists of the versioned clone contract, reproducible pinned runner template, durable immutable SHA binding, validated same-guest context and cleanup/evidence procedure. Creating this plan does not change milestone implementation status.
