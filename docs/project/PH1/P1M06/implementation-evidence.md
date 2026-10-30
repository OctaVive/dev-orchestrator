# P1-M06 implementation and validation evidence

Status: **Implemented/tested; isolated-KVM acceptance PASS** on 2026-10-30. All
83 cases in the post-implementation [test plan](test-plan.md) passed; see the
[acceptance report](testing/acceptance-report.md) and [per-case ledger](testing/acceptance-results.json).

## Delivered implementation

- Strict versioned clone input/result/device contracts, shared lexical input
  validation, exact origin policy, SHA-1 support and conservative bounded limits.
- Unprivileged guest-only runner with fresh HOME/config, fixed argv/environment,
  HTTPS-only transport, disabled prompts/helpers/hooks/filters/submodules,
  shallow exact-SHA fetch and no branch-tip substitution.
- Aggregate encrypted-transfer meter, streaming process output caps, process
  group cancellation and inherited independent host quotas/expiry.
- Object/tree inspection and safe tracked export without `.git`, preserving
  executable bits/internal symlinks, rejecting direct/directory cycles and
  links that escape after context rebasing. No build is executed by M06.
- Sealed read-only job device, capped serial results in the existing owned
  readiness inode, versioned clone journals, identity/inode/active-lease checks,
  ownership-aware cleanup and delayed-start fencing.
- Migration 002, durable clone-attempt records, immutable deployment SHA,
  transactional clone events/audit/outbox, idempotency and stale-result fencing.
  Explicit offline snapshot-and-upgrade tool; automatic upgrades remain denied.
- Narrow storage/provisioner driver with an independent host clone-policy
  deadline, durable timeout recording and same-guest M07 context handoff contract.
  Full scheduling/reservations/state-controller integration remains M12.
- Reproducible clone fixture image, known-byte smart Git/DNS/HTTPS fixtures,
  execution sentinels, context checks, captures, lifecycle/crash/foreign canaries
  and durable adapter tests on the existing disposable M05 KVM lab.

## Security findings resolved during validation

The progress-flood fixture exposed a streaming cap bypass: embedding
`bytes.Buffer` promoted `ReadFrom`, allowing `io.Copy` to bypass a custom `Write`
limit. Named buffers now expose only capped writes in both the clone runner and
provisioner diagnostics. Streaming regression tests exercise that path.

The resolver-failure fixture exposed DNS search-suffix fallback. The broker now
looks up absolute origin names and uses strict resolver-error handling. The
fixture deliberately offers a public answer for unexpected suffixes; final
acceptance must record zero such queries and no successful failed-DNS clone.

Directory symlinks require a cycle check over containment plus resolved link
edges; checking each target alone misses cycles between directories. Selected
subtrees are also revalidated after rebasing, so a link leaving and reentering
the original subtree cannot change meaning or escape the exported root.

## Evidence and scope

Final evidence: `m06.1793358439686004579`, software evidence:
`m06-software.1793358514384227456`, and M05 regression:
`controlled.1793357364025456883`, all under
`/var/lib/orchestrator-builder/m05-lab.4cac6wpp/`. The report records commands,
versions, source/binary/image hashes and actual case results. Source remained
unchanged through the final host run.

Software validation recorded 320 test/subtest PASS results plus passing vet,
builds, syntax and bounded fuzz checks. All 51 actual Git cases and required
lifecycle/adapter tests passed with no infrastructure SKIPs. Captures reported
zero loss, escaped guest frames or protected-destination frames; canaries reported
zero forbidden arrivals and zero search-suffix DNS queries. Final inventory
confirmed all 67 owned jobs fenced and cleaned up. Temporary trust/aliases/fixture
processes were removed; base configs and host firewall structure were preserved.

Earlier failures remain retained as development evidence; no failed or skipped
case is relabeled PASS.

The [shared contract](../../specifications/clone-runner.md) and
[runbook](../../../../infra/clone/README.md) define compatibility, numeric limits,
transport and migration behavior. Acceptance is scoped to the tested isolated
host/template. Private Git credentials, production rollout, host patch compliance,
BuildKit, ingestion and later release gates remain separate. M04 V14/V15 retain
their historical SKIP outcomes.
