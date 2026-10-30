# P1-M08 implementation plan — strict configuration normalization and agent policy

Status: **Implemented/tested; isolated-KVM acceptance PASS**. See [implementation evidence](implementation-evidence.md), [post-implementation test plan](test-plan.md) and [acceptance report](testing/acceptance-report.md). This document records the delivery plan; exact shipped grammar/limits are in the shared configuration policy.

## Outcome and scope

Compile an accepted Dockerfile or basic Compose application into a bounded, deterministic, versioned deployment specification. Independently validate that specification at the controller and agent boundaries. Acceptance gate: **SEC-06; one Dockerfile and a two-service Compose fixture accepted**, with dangerous, ambiguous and unsupported inputs rejected.

Authoritative inputs: [runtime policy](../../../architecture/docker-security.md), [agent lifecycle](../../specifications/deployment-agent.md), [build/admission contract](../../specifications/build-ingest.md), [phase plan](../../../plans/PH1/minimal.md) and [testing strategy](../../specifications/testing-strategy.md). Formal prerequisite is M01; integrating the existing build path also depends on the delivered M06/M07 contracts.

M08 delivers policy/compiler code, guest integration, strict contracts, a controller finalization adapter and a callable agent-side policy gate. M09 supplies actual runtime capability checks, signature/replay enforcement and engine operations; M10 supplies volume/secret ownership and materialization; M12 supplies scheduling, approval and orchestration. M08 must not claim deployment, runtime isolation or completed command authorization.

## Foundation and implementation choices

- `internal/contracts` and `api/*.schema.json` already reject unknown JSON fields and bound deployment/agent inputs. `RuntimeSpec` fixes `restricted-v1`, but lacks entrypoint overrides, dependency order, service healthchecks, secret references and explicit spec identity.
- `internal/builder/runner.go:ValidateDockerfile` is an M07 fixture validator, not a general Dockerfile parser. M07's built-in frontend, source policy, offline RUN, rootless execution and external VM controls remain mandatory.
- The M07 clone/build handoff predeclares one Dockerfile before repository parsing and admits one image per build attempt. Do not imply that it already supports a Compose build graph or independently scanned external images.
- `tests/fixtures/compose/review-candidate.yaml` is a candidate, not an accepted fixture. Its database digest has no admission evidence. Existing hostile Compose fixtures are currently data only.
- Follow the existing five-service maximum. Initially allow **at most one locally built service** plus services referencing independently admitted immutable images. Multi-build Compose is explicitly unsupported in this policy version. This satisfies the two-service gate without expanding M07 into a multi-artifact scheduler.
- Use strict YAML AST parsing in the disposable guest; reject all aliases, anchors, merge keys, custom tags, duplicate keys and multiple documents. Do not invoke Compose CLI or inherit its environment, `.env`, includes or override discovery.
- Use a maintained Dockerfile parser compatible with the pinned built-in BuildKit frontend. Select and pin dependencies during implementation after checking upstream primary documentation and compatibility. No dependency/version selection is implied by this plan.
- Retain offline RUN and digest-pinned base images. Online package installation, tag resolution, build args, build secrets and additional build contexts remain unsupported initially.

These are proposed delivery defaults based on existing boundaries, not recorded user approvals. No product decision blocks writing this plan; expanding compatibility requires an explicit contract revision and tests.

## Delivery sequence

### 1. Freeze the grammar, budgets and versioned contracts

Add `docs/project/specifications/configuration-policy.md` with a field-by-field input grammar, defaults, rejection codes, precedence rules, canonical encoding and boundary ownership. Add `internal/policy` packages for typed normalization and independent validation; keep raw repository parsing in a guest-only package.

Define separate types for untrusted parse results, validated build plans and finalized runtime specs. A parse result may identify local build inputs or requested image digests; only finalization may produce deployable image references from trusted admission records. Never accept a browser or guest assertion as image admission.

Introduce a new schema version for the expanded normalized spec and agent envelope rather than silently changing the existing v1 wire meaning. Keep `restricted-v1` hard controls unchanged. Document whether legacy v1 decoding remains available for fixtures; no legacy path may bypass the new execution policy gate. Update schemas, Go DTOs, OpenAPI descriptions and fixture versions together.

Bind schema/policy version, canonical policy hash, app/deployment identity, source SHA/context identity, service-to-artifact mapping and canonical spec hash. Distinguish M07 build/scan policy hash from M08 normalization/runtime policy hash. Define exactly which signed envelope fields bind the spec hash for M09; hashing is not signature verification.

Proposed hard parser limits: 256 KiB Compose, 64 KiB per Dockerfile, depth 16, 10,000 YAML nodes, 5 services, 32 argv entries of at most 4 KiB, 32 environment entries per service and 256 KiB normalized output including all metadata. Preserve tighter existing command/schema bounds where applicable; calculate total encoded size before accepting rather than assuming per-field maxima fit. Set fixed parse CPU/time/memory/output limits within the existing VM envelope, initially 5 seconds, 128 MiB parser memory and 256 KiB result output. Externally bound the guest lifetime; guest process limits are defense in depth.

### 2. Implement strict guest parsing and repository path handling

Parse only the explicitly selected config at the accepted M06 SHA/context. Enforce bounds before allocation where possible and during token/AST traversal. Accept a single UTF-8 mapping document with string keys and explicit expected scalar types. Reject duplicate keys at every level, aliases/anchors/merges, unsafe tags, unknown fields, invalid scalar coercions, NUL and trailing documents.

Resolve config, context and Dockerfile paths against the exported repository with no absolute paths, traversal or symlink escape. Use descriptor-relative safe opens or an equivalent verified snapshot approach; a lexical path check followed by ordinary open is insufficient. Ensure bytes parsed are the bytes used for the build, including protection against concurrent mutation by repository processes. Exclude `.git`, platform files and secret material under the clone/context contract.

Never load host/guest environment, implicit `.env`, `env_file`, additional Compose files, includes or remote resources. Reject interpolation forms rather than leaving `${...}` unresolved; define literal-dollar handling explicitly. Emit closed reason codes and bounded structural field paths; never return raw YAML, scalar values, commands, environment values or parser exception text.

### 3. Compile the supported Compose and Dockerfile subset

Freeze an explicit allowlist for top-level `services` and managed volume declarations. Each service may select exactly one local build or admitted digest image. Local build accepts only a relative context and Dockerfile. Deny build/image ambiguity, remote contexts and unsupported build settings.

Support bounded argv arrays for command/entrypoint, explicit string environment maps, validated `expose`, managed volume references, bounded resources, finite restart behavior, bounded service healthchecks and acyclic dependency startup order. Specify the exact accepted syntax for every field before implementation; reject unsupported variants, including shell-form command/healthcheck, rather than silently dropping them. Compile all settings into typed fields with no Docker option passthrough.

Resolve repository volume names only through an explicit operator/controller supplied name-to-app-owned-ID mapping. Repository content cannot create host paths or choose external/driver options. Secret references come only from the trusted deployment input/ownership adapter; raw Compose secret file sources remain denied. Missing required ownership/admission adapters fail finalization closed.

Use one platform-managed app-private network with intra-app connectivity and default-deny external/cross-app access. Reject user network definitions, published `ports`, privileged/device/socket/host namespace options, capabilities, unsafe security options, arbitrary logging/sysctls and every unknown key, even when a forbidden option is `false` or empty. Preserve one explicitly selected ingress service/port and bounded private HTTP health path; do not infer ingress from the first service or make remote health requests.

Parse Dockerfile syntax structurally. Support a documented instruction/flag subset, local COPY, pinned FROM images and reviewed multi-stage references; distinguish local stage references from external COPY sources. Reject custom syntax/escape directives, remote ADD, unsupported RUN mounts/network/security flags, SSH/secrets/devices, external contexts and unpinned external image sources. Retain the M07 source policy and fixed frontend as separate enforcement layers. Do not rewrite arbitrary RUN code or claim static analysis contains it.

Finalize using verified image metadata: numeric non-root UID/GID, architecture, entrypoint/command semantics, exposed ports, environment and declared image volumes. Initially deny root/default/named users unless a trusted explicit non-root override is supported and tested; never guess a UID from an image label. Deny unmanaged image volumes. Distinguish absent command/entrypoint from an explicitly empty override so image defaults cannot change accidentally. Do not duplicate secret values into normalized specs or diagnostics.

### 4. Integrate a bounded pre-build normalization handoff

Extend the M06/M07 guest lifecycle with a narrowly typed configuration-analysis stage after durable clone acceptance and before build authorization. Predeclare config mode/path and normalization policy in the sealed initial job. The guest emits a bounded plan bound to job, attempt, generation, lease, SHA/context and policy. Controller validates it independently before authorizing the exact local build, if present.

This requires deliberate versioning of clone/build job, supervisor control and serial result framing: the current channel cap and one-Dockerfile predeclaration cannot carry an arbitrary plan. Specify frame caps, stage ordering and replay rules first. Preserve M06 standalone clone and M07 fixture workflows through explicit versions; unknown versions and conflicting duplicate plans fail closed. Do not introduce a generic exec or filesystem RPC.

Keep runtime environment and secret references outside the guest analysis/build job. Pass only repository parsing/build settings and nonsecret identities. Bind plan identity into build authorization and reject altered contexts, paths or settings. Recheck source/config identity before execution. A compromised guest can lie about the repository; the protocol fences trusted state and independently enforces the permitted spec, but does not prove source-to-image provenance.

For image-only services require an injected admission lookup for the exact digest, platform and current policy. If no trusted admission exists, reject with `image_admission_required`; do not pull, auto-approve or treat digest syntax as evidence. Acceptance prepares the external fixture image through M07's existing isolated admission path. General external-image acquisition remains a separate integration dependency.

### 5. Finalize and independently validate runtime policy

Add controller-side finalization consuming the validated plan, current deployment identity, admission records, verified image metadata, operator policy, volume/secret ownership handles and explicit ingress selection. Output a complete spec or a denial; partial results never become agent commands. Enforce per-service bounds plus overflow-safe aggregate app/capacity limits. Apply deterministic defaults; conflicting repository/request values reject rather than relying on undocumented precedence.

Add an agent-side validator accepting only strict normalized input and trusted local policy/context. Validate all semantic invariants again: unique services, admitted immutable references, UID/GID, ingress membership, mount restrictions, dependencies, health bounds, aggregate resources, schema/profile versions, policy/spec hashes and absence of unknown fields. Share immutable types and policy constants, but invoke validation independently; never trust a controller `validated` flag.

Define a typed required-runtime-controls contract for M09: drop ALL capabilities, no-new-privileges, read-only root, private namespaces, no host publication, maintained seccomp/MAC, bounded writable storage/logs/resources, app-private networking and finite lifecycle budgets. No caller-switchable bypass booleans. Direct agent calls that bypass repository parsing still require the full policy gate.

SEC-06 wording about controller/agent corpus rejection is satisfied through raw-input rejection at the guest boundary and rejection of equivalent forbidden/forged normalized data at both later boundaries. The runtime agent never parses raw Compose. M09 must place signature/replay/ownership authorization before engine mutation and inspect actual engine constraints afterward.

Freeze canonical bytes using a documented deterministic typed encoding: sorted services/maps and semantically unordered collections, stable dependency representation, integer-only resource quantities, explicit default/omission rules and no transient timestamps in content identity. Preserve ordering where meaningful, especially argv. Test golden encodings across processes and map insertion orders. Unknown policy, stale minimum version or hash mismatch denies.

### 6. Package evidence and downstream handoff

Add accepted single-Dockerfile and two-service fixtures plus hostile corpora under `tests/fixtures/{dockerfile,compose}`. Add guest acceptance driver/template changes and a milestone test plan/report. Run hostile parsing/fuzzing only inside disposable budgeted guests; controller/agent fuzzing uses normalized bounded data, never raw repository parsers on management.

Persist immutable normalized bytes/hashes and source/artifact references through a narrow storage adapter if needed by the integration driver. First inspect existing deployment storage; any schema extension uses a forward migration and the existing explicit snapshot/upgrade workflow. Do not transition to APPROVED or add controller scheduling in M08. M12 later atomically binds approval to source, every admitted service digest, current policy, ownership and normalized spec.

Update the milestone README, LLD, shared specifications and requirement evidence to the level actually demonstrated. Preserve M04 V14/V15 historical SKIPs and existing M07 evidence; new protocol/template versions require their own regression evidence. Record exact parser/frontend/template versions, policy hashes, corpus IDs, commands, outcomes and cleanup inventory. Missing lab access leaves guest acceptance pending.

## Required verification matrix

| Gate | Required evidence |
|---|---|
| C01 — accepted inputs | One Dockerfile and two-service Compose produce expected deterministic specs; the built service and external fixture image each have exact M07 admission evidence. Five services accepted within budget, sixth denied; second local build denied. |
| C02 — strict YAML | Duplicate/nested duplicate keys, aliases/anchors/merges, tags, multidocument input, invalid UTF-8/types, unknown fields, interpolation and implicit environment/files denied. Size/depth/node/output/time limits enforced. |
| C03 — SEC-06 forbidden options | Existing corpus plus ports, bind/socket mounts, devices, namespace sharing, privileged/capability/security options, external networks/volumes, includes/extensions/hooks and forbidden false/empty fields denied. Equivalent forged normalized data denied at controller and agent. |
| C04 — Dockerfile/context | Accepted pinned single/multi-stage fixtures; frontend directives, remote sources, unpinned images, external contexts, unsafe flags, traversal, symlink races and changed config/context denied. M07 source policy still denies bypasses. |
| C05 — normalization | Stable golden bytes/hashes, preserved argv semantics, explicit defaults, unique names, ingress selection, acyclic dependencies, finite health/restart bounds, resource overflow/aggregate limits and conflicting inputs. |
| C06 — artifact and ownership binding | Tags, wrong digest/platform/policy/source, missing/stale admission, wrong-app volume/secret references, unmanaged image volumes and unsupported users denied; no secret values reach guest/spec/logs. |
| C07 — independent agent policy | Direct malformed/unknown-version/unknown-field specs, changed hashes, stale policy and structurally valid semantic violations rejected without relying on prior controller validation. No engine execution required to test this gate. |
| C08 — guest protocol and lifecycle | Correct stage ordering; wrong job/lease/generation/context, replay, conflicting plan, expired authorization, frame flood/truncation, cancellation and guest loss denied; external expiry and owned cleanup confirmed. |
| C09 — isolation and diagnostics | Raw parsers execute only in disposable guests; parser bombs leave management operable. Sentinel secrets/commands/environment values absent from errors/events/results. No raw Compose or generic command crosses to agent. |
| C10 — regression and handoff | Existing schema/clone/build tests pass; changed job/framing/template path exercised through actual clone → normalize → build → ingest acceptance. M09 policy/control checklist and M12 approval-binding contract documented; runtime enforcement marked pending. |

Software checks: `go test ./...`, `go vet ./...`, targeted race tests for changed concurrent protocol adapters and bounded normalized-decoder fuzzing. Run raw YAML/Dockerfile fuzzing and malicious fixtures inside disposable guests with explicit budgets. Engine enforcement is M09 evidence, not established by mocks or M08 policy tests.

## Completion

Complete only when C01–C10 have recorded passing evidence, including SEC-06 boundary tests and the isolated guest integration. Deliver strict versioned schemas, the supported-subset contract, bounded guest normalizer, controller finalizer, independent agent policy validator, canonical policy/spec identity, fixtures and acceptance report. A written plan does not change milestone status from Planned.
