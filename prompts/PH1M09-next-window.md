Continue implementing PH1M09 in /root/tap. Do the work, not another planning-only turn. The user requires a post-implementation test plan and every required acceptance case executed as PASS before PH1M09 is marked passed. No further user input is currently needed.

Read first:
- docs/project/PH1/P1M09/implementation-plan.md — especially “Recovery sequence after the incomplete implementation increment” at line 121.
- docs/project/PH1/P1M09/implementation-evidence.md
- docs/project/PH1/P1M09/test-plan.md
- docs/project/PH1/P1M09/testing/acceptance-report.md
- docs/project/specifications/runtime-execution.md
- docs/project/specifications/deployment-agent.md
- docs/architecture/docker-security.md
- docs/project/specifications/configuration-policy.md

Current status:
PH1M09 is INCOMPLETE / NOT PASSED. Substantial code is uncommitted. Preserve existing work; inspect git status/diff first. Do not reset, discard, or assume these files are unrelated changes.

Implemented foundation:
- Follow-up backend increment: durable pre-provision app reservations and measured bindings, schema-1-to-2 migration, app-scoped guarded engine factory, concrete Linux backend identity observer, and signed app/backend inventory v2. Read testing/backend-factory/ and the new implementation-evidence section. The factory selects existing backends; bounded daemon provisioning/reconciliation and the full Enforcement adapter remain unfinished.
- internal/runtimeagent: signed v3 commands, policy/approval/lease interfaces, durable SQLite replay/generation/ownership ledger, bounded results/logs, capability inventory.
- internal/runtimeengine: typed Docker API 1.47 client, candidate lifecycle, inspected constraints, ownership, log framing, artifact delivery/spooling.
- internal/runtimerpc: outbound mTLS polling and artifact download.
- internal/artifacts/runtime.go: scoped runtime artifact download handler.
- api/runtime-v3.schema.json.
- internal/runtimeprofile and cmd/runtime-runc: experimental OCI hardening supplement, not integrated or accepted.
- infra/runtime: experimental lab material and fail-closed reporting.

Earlier software baseline: full Go tests and vet passed; targeted race checks passed; 137 named tests/subtests across five changed packages passed; normalized-command fuzzing passed. These are component tests, many using simulated engines, NOT runtime acceptance. Required ledger currently has R01 FAIL and R02–R10 NOT_RUN.

Critical findings and chosen direction:
1. Shared rootless Docker engine:
   Actual kernel measurements showed two fixture apps shared the same user namespace. Both were unconfined despite requesting apparmor=tap-runtime.
2. App-scoped rootless engines plus a minimal fixed MAC supplement:
   A real disposable KVM experiment showed distinct user namespaces for app A and app B, both different from the VM’s initial namespace, and tap-runtime (enforce) for both.
   This proves only the namespace/MAC feasibility subset, NOT complete readiness or acceptance.

Evidence:
- docs/project/PH1/P1M09/testing/isolation-direction.json
- docs/project/PH1/P1M09/testing/runtime-diagnostic.json
- infra/runtime/experiments/README.md
- infra/runtime/experiments/namespace-guest.sh
- infra/runtime/experiments/per-app-guest.sh
- infra/runtime/experiments/mac-runc-prototype.go.txt

Important correction:
Missing user namespace entries or UID/GID mapping arrays in an OCI bundle do NOT alone prove missing effective kernel isolation. Stock rootless Docker can inherit its daemon’s user namespace. The current strict hardener rejects those missing fields. Production verification must measure actual namespaces/maps and demonstrate trusted app ownership and separation from other apps and the VM’s initial namespace. Do not simply remove checks or weaken isolation.
An earlier attempt to invent nested UID mappings failed with EPERM; do not repeat that blind rewriting approach.

Implementation recovery order:
1. Build a bounded app-scoped backend factory with durable worker/app ownership of engine socket, data root, daemon incarnation, namespace identity, and capacity reservations. Account for per-daemon overhead and duplicated image storage. Command payloads must never select paths, sockets, engine options, or generic commands.
2. Implement measured enforcement: actual namespace/UID/GID checks, maintained enforced MAC/seccomp, cgroups, network default deny, disk/tmpfs/log quotas, capacity and private relay fixture. Every required control must work before readiness can be true.
3. Wire a real runtime-agent process and concrete trusted current approval/admission/lease adapters, then run one stateless admitted image through mTLS polling and signed create → inspected readiness → stop → remove.
4. Complete crash recovery, drift/quarantine, revocation, concurrency, resource/network attacks and the complete acceptance driver. Freeze final source/templates and execute every required case before PASS.

Interface gaps to examine (the backend-factory increment resolves selection/binding only):
- App-scoped Factory now constructs a guarded client from durable bindings. Integrate real bounded daemon provisioning and reconciliation; never route service execution directly through a shared Engine.
- Engine.Probe now receives the authenticated command; capability inventory v2 binds app/backend hash. Preserve this binding in production enforcement and controller verification.
- Inventory v1 is rejected; v2 app/backend signatures and VerifyFor are implemented. Concrete report signing and service wiring remain unfinished.
- Engine configuration currently selects runc and expects engine-reported AppArmorProfile; the tested fixed MAC supplement can enforce MAC while Docker’s inspect field stays empty. Require independent measured verification, never an “ignore MAC” bypass.
- Enforcement remains an interface with no production implementation.
- Approval/lease/admission integration and agent service wiring remain unfinished.
- Nonempty persistent volume/secret references are denied pending M10.
- Nonzero workload restart attempts are currently denied; durable restart handling is unfinished.

Scope boundaries:
M10 owns persistent volume/secret materialization.
M11 owns production authenticated routing; M09 still requires a private relay connectivity fixture.
M12 owns scheduling/product approval decisions; M09 nevertheless needs concrete trusted adapters for integration.
No generic exec, shell, arbitrary Docker API forwarding or host filesystem RPC.

Lab:
- Full host access and network were enabled in the previous window; inspect current permissions.
- KVM and TUN devices are available.
- Private development directory: /var/lib/orchestrator-builder/m09-tools/
- Trusted never-booted root tree: .../rootfs/
- Docker/rootless extras 29.5.0 development downloads are pinned in infra/runtime/tools.lock.json.
- Guest has systemd/cgroup v2, rootless runtime UID/GID 1000, subordinate IDs, AppArmor and trusted static BusyBox fixtures.
- Per-app experiment uses separate rootlesskit state directories, sockets, data roots, exec roots, pidfiles and systemd user units for app-a/app-b.
- Root tree currently contains experiment binaries/services; do not mistake it for an accepted release template.
- Experiments used fresh raw images, snapshot writes, no NIC, external timeouts, 2 CPUs and 1536 MiB RAM.
- No QEMU guests were running at the last check.
- Never mount guest-modified disks on management or modify a backing image while QEMU uses it.
- Hostile workloads belong only in isolated lab VMs.

Verification:
Current backend increment has full tests (23 packages), 159 named component cases/subcases in the five runtime/artifact packages, five-package race checks, vet and bounded command fuzzing PASS. The actual Go observer passed the identity-only disposable VM diagnostic on two real app daemons, with eight altered-binding denials and ledger reopen. This is not R01 or full runtime acceptance. Use TMPDIR=/var/tmp/tap-m09 (private and short): /tmp currently lacks enough free space for artifact reservation tests, and the long m09-tools temporary directory exceeds Unix socket fixture path limits.
Use umask 077; existing metadata tests require private parent directories.
Use GOCACHE=/tmp/tap-go-cache and /usr/local/go/bin/go.
Appropriate checks include go test ./..., go vet ./..., targeted race tests and bounded normalized-command fuzzing.
Existing guest-only/historical optional SKIPs do not count as M09 acceptance.
Source changes invalidate old acceptance evidence. Update source/evidence hashes and retain failed development runs.

Milestone reporter:
python3 infra/runtime/report.py \
  --ledger docs/project/PH1/P1M09/testing/required-cases.json \
  --manifest docs/project/PH1/P1M09/testing/evidence-manifest.json

It currently correctly returns INCOMPLETE, exit 1. Its synthetic unit fixture PASS is not acceptance evidence.

Work autonomously and communicate meaningful progress. Do not ask for permission already implied by implementing/testing this milestone. Do not spawn sub-agents unless applicable instructions explicitly authorize them. Keep M09 incomplete until every required real-runtime case passes; do not present more unit tests as a substitute.
