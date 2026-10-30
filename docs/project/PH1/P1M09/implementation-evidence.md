# P1-M09 implementation evidence — incomplete increment

Status: **In progress; NOT PASSED**. [Acceptance report](testing/acceptance-report.md)
and [test plan](test-plan.md) distinguish passing software from unfinished runtime
acceptance. [Source hashes](testing/evidence-manifest.json) identify this working
tree increment; HEAD alone does not identify the uncommitted implementation.

## Delivered code

- `internal/runtimeagent`: strict v3 operation envelope, domain-separated Ed25519
  signatures and inventory signing, independent policy/approval/lease checks,
  durable SQLite nonce/request/generation/ownership state, exclusive process lock,
  bounded status/logs and conservative uncertain-intent handling. Invalid inputs
  do not enter the fake engine in software tests; real-engine denials remain pending.
- `internal/runtimeengine`: bounded Unix-socket Engine API 1.47 adapter, fixed
  resource/security options, complete typed setting comparisons, private candidate
  creation/start/inspection, owned stop/remove, bounded Docker log-frame decoding
  and immutable archive spool/reverification before import. Missing enforcement
  refuses readiness. Actual engine compatibility and cleanup recovery remain pending.
- `internal/runtimerpc`: outbound mTLS polling/artifact fetch with chain/name/URI/
  SPKI checks, no proxy/redirect, certificate validity/revocation on reused
  responses, strict bounded command bodies and complete artifact digest checking.
- `internal/artifacts/runtime.go`: separate runtime download handler requiring
  current authorization for certificate fingerprint, worker/incarnation, app/
  deployment, generation, admission, image and policy/spec binding. No listing,
  arbitrary path, symlink following or upload-grant reuse. Concrete current-state
  authorization and listener wiring remain to be implemented.
- `api/runtime-v3.schema.json` and the [execution contract](../../specifications/runtime-execution.md):
  explicit new execution protocol; legacy envelopes remain non-executing.
- `internal/runtimeprofile` / `cmd/runtime-runc`: experimental fixed OCI MAC
  supplement requiring private user namespaces and non-host-root mappings. It is
  not selected by the engine adapter and has not passed the complete VM fixture.
- `infra/runtime`: credential-free feasibility probe/profile, development download
  pins, reporter and reporter unit test. This is not a finished acceptance harness
  or a production bootstrap/template builder.

## Scope limits

No automatic approval, scheduler, public route activation, volume/secret
materialization, generic shell/exec/engine forwarding API or production deployment
is introduced. The core can be exercised through its Go interfaces; it is not yet
a deployable agent service. Required measured helpers are absent, so the normal
Engine readiness path refuses deployment. The milestone stays incomplete until
its entire required runtime matrix passes.
