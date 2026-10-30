# Configuration policy and normalized agent contract (M08)

Version: configuration grammar 1, clone/build job 2, runtime spec/agent envelope 2.
Status: implemented and accepted on the tested isolated host; [M08 acceptance evidence](../PH1/P1M08/testing/acceptance-report.md) is authoritative.

Repository parsing executes only inside disposable build guests. Management and
runtime agents accept strict bounded normalized JSON, never YAML or Dockerfile
bytes. No Compose CLI, environment expansion, implicit `.env`, includes or override
files are used. The policy implementation is `internal/policy`; guest parsers are
`internal/configguest`; the independent agent entry is `agentpolicy.Decode`.

## Exact supported grammar

Compose has one top-level `services` mapping and optional `volumes` mapping.
Each top-level volume name maps to an empty mapping. Maximum five services and
one locally built service; additional services require admitted digest images.
Service names use the existing lowercase platform name syntax. Unknown fields,
including forbidden fields set to false, null or empty values, are denied.
YAML anchors, aliases, merge keys, explicit tags, duplicate keys, multiple documents,
non-string keys, nulls, floats, invalid UTF-8, NUL and dollar characters are denied.
There is no interpolation or literal-dollar escape in grammar 1.

| Service field | Accepted syntax and compilation |
|---|---|
| `image` | Fully qualified immutable `registry/path@sha256:<64 lowercase hex>`; exact trusted admission required later. Mutually exclusive with build. |
| `build` | Mapping with explicit `context` and `dockerfile` relative paths; relative to the selected Compose file’s directory and strictly inside the exported context. No build args, secrets, SSH, remote contexts or extra flags. |
| `command`, `entrypoint` | Nonempty arrays of at most 32 strings, each at most 4096 bytes. Ordering preserved. Omitted values inherit verified image defaults. Empty overrides and shell-form strings denied. |
| `environment` | Mapping of at most 32 explicit string values, at most 4096 bytes each. Valid variable names; ORCH_/DOCKER_/BUILDKIT_ prefixes reserved case-insensitively. Repository values override image defaults. Trusted runtime input is merged only at finalization; a different value conflicting with a repository value denies. No host values are imported. |
| `expose` | At most 16 distinct quoted decimal TCP port strings, range 1–65535. Metadata only; publishes no host port. |
| `depends_on` | Array of distinct service names; no self references or cycles. Startup order only; long-form conditions/lifecycle hooks unsupported. |
| `volumes` | At most 8 long-form `{type: volume, source: <declared name>, target: /data[/...], read_only: <bool>}` records. Omitted read_only defaults false. Controller resolves names to app-owned IDs. No overlapping targets or duplicate source IDs. |
| `deploy` | Only `resources.limits` with optional `cpus` decimal string (0.1–4, up to three decimal places), `memory` integer M/G string (binary MiB/GiB, 16 MiB–8 GiB), and integer `pids` (16–512). Other deploy keys denied. Omitted values inherit defaults. Tmpfs/storage/log budgets are fixed platform defaults. |
| `restart` | Omitted/`"no"` means zero retries; `on-failure:1`, `on-failure:2`, `on-failure:3` set finite retry counts. Other values denied. |
| `healthcheck` | Mapping with `test: [CMD, executable, ...]`, `interval`/`timeout` whole-second strings such as `30s`/`5s`, integer `retries`. Bounds in seconds: interval 1–300, timeout 1–30 and no larger than interval; retries 1–10. Runs solely as workload code inside its container. CMD-SHELL denied. |

Ingress is an explicit trusted finalizer input selecting one service and a port
present in its expose list, with a bounded relative HTTP health path. No URL is
fetched during normalization. Dockerfile mode names the service `web` and defaults
its container ingress metadata to port 8080; the finalizer must explicitly select
that service/port. Other Dockerfile-mode ingress ports require a future input
contract revision rather than inference from untrusted image metadata.

All other Compose keys are unsupported, including ports, privileged, devices,
capabilities, security options, namespace/network modes, custom networks, binds,
external volumes, sysctls, logging drivers, profiles, extensions, secrets/configs
from files, env_file, includes, hooks and container names. Requests for runtime
secret references are supplied separately by trusted controller context and checked
through an ownership adapter, never read from repository files or sent to builds.
Secrets are bounded immutable references mounted under `/run/secrets/`; M10 owns
materialization. Missing ownership/admission adapters deny finalization.

Dockerfile grammar uses BuildKit v0.34.1's parser and pinned built-in frontend.
FROM accepts scratch, earlier stages or fully qualified digest-pinned images;
reviewed multi-stage COPY --from accepts earlier local stage names/numbers only.
COPY, RUN, USER, WORKDIR, ENV, EXPOSE, CMD, ENTRYPOINT and LABEL are supported.
CMD/ENTRYPOINT require JSON argv form. Flags are denied except local-stage
COPY --from. ADD, ARG, ONBUILD, VOLUME, custom syntax/escape/check directives,
heredocs and other instructions are unsupported. Comments and standard line
continuations are accepted. RUN remains arbitrary guest code, with network
forced off by BuildKit and external VM/egress isolation retained.

## Bounds, defaults and identity

Compose: 256 KiB; Dockerfile: 64 KiB; AST depth: 16; AST nodes: 10,000;
Dockerfile instructions: 1024; plan/spec/agent envelope: 64 KiB encoded total.
The tighter aggregate output cap wins over per-field allowances. Parser subprocess:
5-second wall deadline, 128 MiB cgroup memory, no swap, 1 CPU, 32 PIDs, bounded stdout
and discarded stderr. GOMEMLIMIT is additionally 96 MiB. Parent cancellation kills
the child. These guest controls supplement externally enforced VM limits and expiry;
a compromised guest root is not constrained by guest cgroups as a host boundary.

Per-service defaults: 1000 CPU millis, 512 MiB RAM, 128 PIDs, 64 MiB tmpfs,
64 MiB writable storage budget, 20 MiB logs, zero restart attempts. App maxima:
4000 CPU millis, 8 GiB RAM, 512 PIDs, 1280 MiB tmpfs, 10 GiB writable storage,
100 MiB logs. Validate each service before adding totals to avoid overflow.
Requests outside bounds reject; values are never silently clamped.

`policy.Hash()` identifies this grammar/default/control contract. It is distinct
from the existing clone and M07 build/scan policy hashes. Canonical plans sort
services, dependency sets, port sets and mount targets; maps use Go's sorted-key
JSON encoding. Argv order is significant. Canonical specs additionally sort volume
and secret targets. Explicit defaults are materialized; optional empty collections
are omitted. Numeric quantities are integers. Policy/spec hashes are SHA-256 over
fixed UTF-8 JSON bytes without a trailing newline. Golden tests bind the encoding.
Identity includes app/deployment, immutable SHA/context ID, plan hash and each
service's admitted image identity. No transient time goes into the spec hash.

## Handoff, image evidence and authorization

Clone/build version 1 remains the M06/M07 fixture protocol. Configuration jobs
require clone/build version 2 and sealed `configuration` settings. The integrated
path predeclares the expected local Dockerfile in BuildSettings; both controller
and provisioner reject a selected plan build path that differs. Image-only plans
can be finalized using admission adapters but have no local M07 build operation.
M12 owns orchestration of that path.

The guest parses after clone/export and attaches the bounded plan to the final
clone success. Controller policy validation precedes durable acceptance. The
private clone-attempt record holds the plan; audit/events/outbox hold clone identity
and plan hash without repository environment/argv values. Existing M06/M07 serial
prefixes remain; the body version selects the contract. Result cap is 69,632 bytes,
serial cap is three times (result cap + 5); oversize/incomplete/conflicting frames
retain fail-closed behavior. The sealed clone job remains capped at 16 KiB.

`BuildJob.PlanHash` binds the accepted plan. BeginBuild checks the durable matching
clone, source/context, generation/attempt/lease and canonical plan hash before its
transactional BUILDING transition. Provisioner repeats matching plan/path checks.
Guest reanalysis compares the hash immediately before building. Paths use os.Root,
reject observed symlink components and open final files with NOFOLLOW/NONBLOCK.
No repository process executes before analysis; build contexts are local BuildKit
inputs. Reanalysis detects changed bytes; it is not proof of source provenance
when guest compromise is assumed.

Isolated OCI validation now records bounded image metadata (numeric user,
linux/amd64, argv defaults, environment, exposed TCP ports) in Verified and the
immutable ArtifactResult. Config metadata is digest-graph verified; never parse
OCI on management. Metadata is capped at 4096 bytes, preserving bounded result
framing; root/default/named user, root group and unmanaged image volumes deny.
M08 FromArtifact requires a durable caller-supplied job/result and exact image
digest. Local build finalization additionally checks the admission’s SHA, context and deployment against the current clone. Resolver implementations must check current admission/scan policy and
revocation; caller maps supplied by a browser or guest are not trusted adapters.

Runtime spec v2 and `api/agent-v2.schema.json` preserve the meaning of restricted-v1.
Agent decoding checks schema, exact fields, shape, worker, expiry/generation
prechecks, canonical hash and semantic policy using its own trusted resolver.
The v1 decoder remains shape-only and must never be used as an execution gate.
M09 must verify signatures and atomically check durable replay state and current
approval before mutation. The signature must bind all v2 envelope fields except
signature itself, including worker/command/generation/expiry/nonce/key and spec_hash;
spec_hash binds the complete spec. M08 does not implement signing or execution.

Required M09 engine controls are non-root numeric UID/GID with no supplementary
host groups, drop ALL capabilities, no-new-privileges, read-only root, private
namespaces, maintained seccomp/MAC, bounded storage/tmpfs/logs/CPU/RAM/PIDs, no host
publication, app-private networking with default-deny external/cross-app traffic,
and finite restart/health budgets. Unsupported enforcement refuses deployment.
M09 must compare actual engine state to this intended state after create.
M12 approval must bind source, every service admission/digest, normalized spec hash,
current policy and ownership; admission/normalization never independently approves.

Closed failures include configuration_policy_denied, image_admission_required, configuration_read_denied, dockerfile_syntax_denied and fixed parser stage denial codes;
existing strict JSON errors remain value-free. Raw parser/tool errors and runtime
values are excluded from diagnostics. This milestone adds no management endpoint,
generic exec API, scheduling or automatic approval.
