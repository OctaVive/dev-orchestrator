# P1-M07 implementation and validation evidence

Status: **Implemented/tested; isolated-KVM acceptance PASS** on 2026-10-30.
All 146 required ledger cases passed. See the
[acceptance report](testing/acceptance-report.md),
[per-case results](testing/acceptance-results.json) and
[post-implementation test plan](test-plan.md).

Delivered: versioned predeclared build contracts; durable M06 handoff and raw
bounded authorization; pinned rootless BuildKit with process sandboxing and
source/network policy; independent host stage deadline; separate opaque upload
service; fresh isolated UID-separated OCI validation/scanning; pinned offline
Trivy/database; immutable digest admission and migration 003; separate build
outbox, recovery and owned cleanup; reproducible recipes and hostile fixtures.

The actual pipeline cloned and built source, pulled a pinned controlled image,
ran a sandboxed command, uploaded opaque bytes, validated the complete OCI graph,
scanned it in another VM, promoted original immutable bytes and committed an
admission record while remaining SCANNING. Timeout/cancellation/controller-loss,
scanner expiry and CPU/log/disk/memory/PID cases passed with external controls.

Final evidence is `m07.1793368911214050600` under the existing isolated M05 lab.
The report records 387 software test/subtest passes, static/race/fuzz checks,
complete guest and KVM results, exact source/tool/template/database identities,
zero capture drops/forbidden arrivals and confirmed cleanup/restored host state.
Earlier failures are retained as development evidence. The supervisor CAP_KILL
fix is documented because independent deadline enforcement must survive the
QEMU UID drop.

The [shared contract](../../specifications/build-ingest.md),
[build runbook](../../../../infra/build/README.md) and
[ingest runbook](../../../../infra/ingest/README.md) define compatibility,
resource maxima, private service interfaces, migration and recovery behavior.
No production rollout or application deployment is implied. M04 V14/V15 remain
historically SKIP; later normalization/runtime/controller/release gates remain.
