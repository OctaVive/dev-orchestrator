# P1-M07 implementation plan — rootless build and isolated artifact admission

Status: **Implemented/tested; isolated-KVM acceptance PASS**. See [implementation evidence](implementation-evidence.md), [post-implementation test plan](test-plan.md) and [acceptance report](testing/acceptance-report.md). This document retains the approved delivery contract; exact delivered pins and limits are in the runbooks.

## Outcome and boundaries

Turn M06's accepted same-guest context into a bounded OCI image, independently verify its complete digest graph and baseline scan policy in isolation, and persist an immutable admission record. Acceptance gate: **digest matches, budgets kill guest, hostile archives quarantined**. Cover SEC-08 resource enforcement and SEC-10 secret-free diagnostics.

Prerequisite: [M06 evidence](../P1M06/implementation-evidence.md). Preserve M04 V14/V15 historical SKIPs and the scope of the tested isolated host. Authoritative contracts: [pipeline](../../../architecture/git-deployment-pipeline.md), [worker lifecycle](../../specifications/deployment-agent.md), [clone runner](../../specifications/clone-runner.md) and [phase plan](../../../plans/PH1/minimal.md).

This milestone delivers a narrow build/ingest adapter and acceptance driver. Compose/Dockerfile normalization and the complete runtime spec belong to M08; runtime image delivery belongs to M09; scheduling, automatic approval and the complete controller belong to M12. M07 admission makes an artifact eligible for later approval, never independently deployable. The later approval binds commit, image digest, policy and normalized spec.

## Foundation at implementation start

- `internal/clonejob.Driver.Execute` durably accepts clone success and retains the VM for M07. Failure paths release it. `Store.CloneReady` supplies the authoritative handoff; a guest context assertion alone is insufficient.
- `internal/provisioner/linux_clone_linux.go` supplies a sealed read-only job device and bounded serial result capture. There is no build dispatch channel. Do not pretend that the clone result channel can carry arbitrary commands or OCI bytes.
- M04's `build-small-v1` profile already defines 2 vCPU, 4 GiB guest RAM, 10 GiB virtual disk and 512 guest PIDs, with external CPU/RAM/disk controls and independent expiry. Guest PIDs remain defense in depth against a compromised guest root.
- M05 provides broker-only build networking. Registry/token-service origins and actual BuildKit/package-manager clients still need compatibility and bypass verification.
- Storage already has deployment SHA/digest fields, transactional state/event/outbox operations and migration 002 clone attempts. It has no build-attempt, upload, scan or artifact admission ledger. Existing event constraints must be extended deliberately, following M06's migration pattern.
- The clone lab image is a fixture, not a rootless BuildKit/scanner template. No current code establishes OCI validation, vulnerability scanning or artifact promotion.

## Approved decisions

The user selected **A / A / A** on 2026-10-30:

- **Conservative compatibility:** one `linux/amd64` image, OCI export, gzip or uncompressed layers. Multi-platform images and additional layer formats remain unsupported initially.
- **Strict vulnerability admission:** block HIGH and CRITICAL findings, including findings without fixes. Only explicit, expiring operator exceptions permit admission. Missing/stale database or incomplete scan coverage fails closed.
- **Implementation-owned technical defaults:** inspect host capacity, select maintained pinned BuildKit/scanner versions, freeze conservative numeric limits, and use a separate ingest service with isolated scanner VMs. Verify rootless feasibility before implementing execution. These routine technical selections do not require another design approval round.

The first implementation work package must record exact tool/template/database identities, numeric limits and topology in the shared contracts/runbooks, and demonstrate rootless BuildKit with the required sandbox and resource controls. These details are now recorded in the runbooks/tool pins and acceptance evidence; approval of this approach is not evidence that feasibility or capacity has already been verified. If feasibility fails, revise the design without weakening the isolation requirements.

## Initial design decisions

Use fresh dedicated ingest/scanner VMs separate from builders and management. The management host handles opaque bounded upload bytes and trusted metadata; OCI/archive/image and scanner report parsing happens in the ingest isolation boundary. Host-side hashing and size accounting of opaque bytes are permitted. Never extract repository artifacts on management or mount host directories/engine sockets into workers.

Initially accept one `linux/amd64` image, OCI layout export, SHA-256 descriptors and a single image manifest. Accept uncompressed or gzip OCI layers under explicit expanded limits. Reject multi-platform indexes, foreign/external layers, descriptor URLs, unsupported media types, nested artifact types and build attestations until deliberately supported. The layout's root index may identify exactly that one manifest. Distinguish upload-archive SHA-256 from the image manifest digest; only the verified manifest digest becomes `deployments.image_digest`.

Use a pinned built-in Dockerfile frontend and a narrow typed build request. Deny repository-selected remote frontends, remote contexts/ADD sources, insecure/host-network entitlements, SSH/secret forwarding, custom daemon options, devices and shared caches. M07 uses operator-owned validated build settings and controlled fixtures; it does not expose arbitrary repository configuration before M08 provides the policy producer. Do not rely on lexical Dockerfile checks as the security boundary: fixed BuildKit settings, frontend capability checks and external networking must enforce the restrictions.

No implementation version is selected by this document. During implementation, verify maintained BuildKit/scanner releases and official OCI contracts, then pin binary/package/template/database hashes and capture compatibility evidence. Do not silently use floating tool versions or vulnerability feeds.

## Delivery sequence

### 1. Freeze contracts, policy and budgets

Add strict versioned build job/result, upload grant/receipt, scan request/result and admitted-artifact contracts under `internal/contracts`, with schema size bounds, unknown-field rejection and closed reason codes. Bind job, deployment, app, attempt, generation, lease, template, accepted clone/context identity, immutable SHA, build policy and deadlines. Bind scanner policy/tool/database identities and artifact digest into every scan/admission record. Inputs contain no shell, executable, host path or arbitrary environment.

Preserve architecture defaults: build 20 minutes; scan 5 minutes; overall attempt 40 minutes; 2 vCPU/4 GiB RAM/10 GiB disk/512 guest PIDs. Effective deadlines are the earliest stage deadline, remaining overall budget, cancellation or lease expiry. Reject a handoff without enough remaining lifetime; never extend an expired lease. Check the existing maximum lifetime and resource reservation arithmetic before enabling a combined clone/build template.

Before parser/executor work, freeze a versioned numeric policy for archive/upload bytes, concurrent uploads, archive entries/path depth/path length, descriptor count/JSON size, per-layer and aggregate compressed/expanded bytes, expansion ratio, extracted inode count, scanner memory/disk/PIDs/output/report sizes and quarantine capacity/retention. Use conservative operator-owned values within fixed maxima; repositories cannot raise them. Account for context, BuildKit scratch/cache, export, quarantine, scanner scratch and promotion copies independently. Reserve ingest capacity before issuing a grant, and apply independent host limits to ingest VMs as well as builders.

### 2. Implement durable same-guest build authorization

Add `internal/buildjob` and a narrow provisioner build backend rather than a generic exec RPC. Extend the immutable initial job device with the validated build settings, then use a bounded dedicated control frame to authorize that exact predeclared build only after `CloneReady` succeeds durably. Define framing, input/output caps and job/lease identity checks in a shared build contract before changing QEMU plumbing. Frames cannot change argv, context paths or policy. Maintain the standalone clone/probe templates and cleanup behavior.

A pinned combined clone/build runner waits after clone success. Management verifies the active lease, context identity, stored SHA, attempt/generation and policy, atomically records build start, and delivers the matching authorization. A crash after recording but before dispatch retries the same authorization; duplicate dispatch cannot start a second build. Late authorization, wrong context and stale generation fail closed. A compromised guest can run arbitrary computation early; this handshake fences trusted workflow state, not guest honesty.

Add `cmd/build-runner`/`internal/builder` or an equivalently narrow combined runner. Run BuildKit as a dedicated unprivileged user with user namespaces, reviewed subordinate mappings, private socket/storage, controlled environment and enforced guest cgroups. Require working sandbox/seccomp and capability probes; fail closed if rootless prerequisites are absent. Do not enable `--oci-worker-no-process-sandbox` to make the fixture work. Pin frontend and base images by digest where controlled inputs supply them; verify pulled content. Use a fresh local cache destroyed with the VM.

### 3. Build and export under external enforcement

Build only the accepted same-guest context without `.git`, using argv APIs and trusted fixed options. Keep runtime secrets, management credentials and registry push credentials absent. Route BuildKit pulls and build-step HTTPS through M05 mediation; enumerate registry authentication origins explicitly. Handle proxy trust in both the BuildKit daemon and build-step sandbox. Never disable TLS verification to solve compatibility issues.

Bound stdout/stderr as they stream; expose structured status/counters rather than raw repository-controlled logs. Private grant tokens and headers must never enter build environments or diagnostics. A guest-scoped upload grant is obtainable by guest root and therefore grants only bounded write access to that job's quarantine, never admission or reads.

Export a complete OCI layout into bounded guest storage. Report the proposed manifest digest and archive size/hash, treating all as untrusted assertions. Timeout, cancellation, log flood, CPU/RAM/disk exhaustion or process loss terminates the build and triggers external VM cleanup. Independent host expiry remains effective when the runner/controller hangs. No local-build fallback.

### 4. Add bounded job uploads and isolated OCI validation

Provide a job-specific authenticated upload endpoint outside the management API surface. Grants are short-lived, attempt/generation-bound and limited to a single committed object with fixed byte/concurrency quotas; store token hashes and revoke on cancellation/expiry. Stream bytes into opaque server-generated quarantine object IDs. Reject oversized/chunked overflow, slow uploads and cross-job/replayed grants without buffering whole bodies. Interrupted uploads remain quarantined and non-readable by runtime. Support idempotent completion only for the identical object identity and hash; uncertain retries get a fresh explicitly issued grant.

Attach the completed opaque artifact read-only to a fresh ingest VM through owned devices. No filesystem share or builder-controlled path. Validate tar headers and canonical paths, duplicates/aliases, unsupported PAX/GNU/sparse forms, entry types and all numeric limits before materializing layout blobs into private disposable scratch. Reject outer-layout symlinks/hardlinks/devices/FIFOs and path escape. Enforce decompression limits while streaming, including concatenated streams and truncation.

Validate `oci-layout`, root index, manifest, configuration and every referenced blob: media type, exact size and SHA-256, supported platform, graph completeness, bounded graph traversal and no unexpected/unreferenced content. Independently recompute each layer's uncompressed `diff_id` and config correspondence. Validate layer entry paths, link targets, whiteouts and overlay semantics before scanning; legitimate safe image links require different rules from the outer layout. Reject escaping links, special devices and unsupported semantics. Never boot or run image entrypoints during validation or scanning.

Mismatch, malformed content or incomplete upload produces a closed denial code and quarantine record. A guest-reported digest never overrides independently verified content. Malformed archives do not reach the scanner.

### 5. Scan and admit the exact verified image

Implement a typed isolated scanner adapter with pinned executable/template and an immutable preloaded vulnerability database. Generate a bounded SBOM and evaluate image/runtime metadata plus a baseline vulnerability policy. Specify policy thresholds, treatment of unfixed findings and explicit expiring operator exceptions before admitting the first image; approved initial policy denies all detected HIGH/CRITICAL findings, including unfixed findings, without an explicit expiring operator exception. Missing/stale database, unknown scan coverage, unsupported image, scanner crash/timeout, invalid report or failed metadata policy denies admission. The database age threshold is versioned policy.

Scanner execution has no internet, engine socket, runtime secrets or management access. Feed only the verified digest-bound layout; restrict scanner scratch separately. Parse reports inside isolation and emit only bounded normalized metadata, report/SBOM hashes and counts. Treat parser/scanner compromise as possible and retain external quotas. Separate validation and scanner processes/identities, with immutable verified input and no scanner writes to admitted blobs.

Promote only the original immutable verified bytes, referenced by opaque object ID and independently checked hashes, into content-addressed artifact storage. Rehash opaque bytes at transfer boundaries; ensure the admitted manifest graph corresponds to those bytes. Never promote scanner-modified scratch or trust a new path returned by a guest. Admission requires all verification and scan results under the current expected policy; passing a scan does not prove an image benign or prove a compromised builder used the claimed source.

### 6. Persist, fence and reconcile the workflow

Add a forward migration for build attempts, uploads/quarantine, artifact descriptors and scan/admission evidence. Preserve append-only attempt history and references needed for later approvals. Follow the existing explicit offline snapshot/upgrade procedure rather than enabling automatic schema upgrades.

Add storage methods that CAS expected state/version/generation/attempt and active lease. Atomically record build completion and entry to SCANNING with audit/outbox metadata. Persist verified digest and successful admission only for the matching scan and current policy. Do not transition to APPROVED in M07: provide an immutable admission handle for M12's approval logic. Keep failed uploads/scan outcomes separate from deployable artifacts.

Same identity/same content retries are idempotent; different content, stale lease, conflicting digest and late scan success are rejected. Test crashes at upload completion, verification, scan recording and promotion. Use durable pending/promotion states and reconciliation because blob movement and SQLite cannot share a transaction; an orphan object is never implicitly admitted. Recheck digest/policy/admission on later reads. Retention must preserve referenced admitted artifacts; full inventory/retention features remain P1-R04.

Cancellation revokes grants and broker access, fences further writes/results, stops both VMs and cleans owned scratch/network/devices. Preserve reservations until confirmed cleanup; leave visible incidents and bounded retries for uncertain ownership. Quarantine has finite operator-controlled retention and a hard capacity limit that stops admission of new jobs before exhaustion. Never delete foreign resources.

### 7. Package acceptance and handoff evidence

Add `infra/build` and `infra/ingest` recipes/runbooks, hostile OCI fixture inventory under `tests/fixtures`, a milestone test plan and isolated KVM acceptance harness extending the M05/M06 lab. Use known-byte inert fixture generators; execute malicious archive parsing, BuildKit builds and scanner fixtures only inside budgeted guests. Record exact source/tool/kernel/QEMU/template/policy/database hashes, fixture IDs, commands, exit statuses, external resource/packet evidence, state/event records and cleanup inventories.

Update the milestone README, shared build/ingest contracts, LLD, requirement evidence and project status only to the level actually demonstrated. Report PASS/FAIL/SKIP/Not run distinctly. A lab availability or rootless prerequisite failure leaves real-host acceptance pending.

## Required verification matrix

| Gate | Required evidence |
|---|---|
| B01 — contracts/handoff | Strict decoding, oversized/unknown fields, wrong SHA/context/template, expired lease, duplicate dispatch, durable clone requirement and stale-generation denial. |
| B02 — rootless execution | Actual UID/mappings, sandbox/cgroups/seccomp, pinned frontend, denied entitlements/remote sources, no host socket/mount, no shared cache; unsupported hosts fail closed. |
| B03 — digest identity | Known image succeeds; manifest/config/blob/size/diff-ID mismatch, wrong platform, unsupported graph/algorithm, missing/extra blobs and archive-vs-image hash confusion denied. |
| B04 — hostile archives | Traversal/absolute paths, duplicate aliases, links/devices, malformed headers/JSON, whiteout escapes, sparse files, truncated/concatenated compressed data, bombs, graph/count/inode/depth limits remain quarantined. |
| B05 — budgets/SEC-08 | Build CPU/RAM/disk/PID/log/time and ingest expansion/scanner quotas; hung/compromised runner and stopped controller; external expiry kills guests and management remains operable. Guest PID checks are not claimed as a host security boundary. |
| B06 — upload isolation | Cross-job grant, replay, expiry, concurrency, slow/chunked/oversize upload, cancellation, token leakage, quarantine capacity and partial-object cleanup. |
| B07 — scanner/admission | Known clean/denied images, threshold/exception cases, stale/missing DB, unsupported coverage, crash/timeout/report flood, malformed report, SBOM binding and immutable verified-input/promotion checks. |
| B08 — network/SEC-10 | Actual image pulls and build-step dependencies through broker; redirects/rebinding/metadata/direct-DNS/raw-IP bypass denied externally; sentinel secrets/tokens absent from results, DB events, logs and reports. |
| B09 — persistence/recovery | Transaction rollback, crash windows, idempotency/conflicting digest, stale results/policy, cancellation vs promotion, orphan reconciliation, no APPROVED/deployable result from partial/denied work. |
| B10 — lifecycle | Fresh ingest isolation, build/scan cancellation and VM loss, revocation, confirmed owned cleanup, retained capacity on cleanup failure and foreign-resource canaries. |

Software checks: `go test ./...`, `go vet ./...`, targeted race tests for new concurrent adapters/upload handling and bounded fuzzing of framing/metadata decoders. Hostile OCI parser fuzzing runs in disposable isolation. Real BuildKit, scanner, network and resource tests require the isolated KVM harness; software tests alone do not satisfy acceptance.

## Completion and downstream contract

Complete only after B01–B10 have passing recorded evidence, including externally observed budget termination and hostile archive quarantine. Deliver the pinned combined runner and ingest/scanner templates, strict contracts and numeric policies, durable admission ledger, opaque digest-bound artifact handle, cleanup/recovery procedure and acceptance evidence. M08 consumes the build-policy boundary; M09 consumes approved digest retrieval later; M12 consumes the build/scan adapter and admission record. Completion is recorded in the linked acceptance evidence; historical M04 qualifications and downstream milestone gates remain unchanged.
