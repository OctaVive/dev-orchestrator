# P1-M05 real-host execution and acceptance

Use an approved disposable Linux KVM VM. Review the [operator runbook](../../../../../infra/egress/README.md), [complete matrix](../test-plan.md) and [LLD](../../../../../LLD-documents/PH1/p1-m05.md) first. Preserve M04 V14/V15 SKIP. Running tests outside a restricted development sandbox may be necessary: a missing device in a sandbox is not evidence that the host lacks it.

## Reproducible automated smoke/fault suite

After reviewing the script and authorizing its scoped installation, run as root:

```sh
M05_LAB_APPROVED=YES-I-AUTHORIZE-REAL-NETWORK \
  python3 infra/egress/m05-lab.py --configure-and-test \
  --origin example.com --resolver 1.1.1.1
```

Choose an explicitly approved public origin and a dedicated resolver reachable over TCP/53. The example uses a public smoke origin; it is not a controlled acceptance canary. Preflight checks KVM/TUN/tools, supported virtualization, path ownership, resolver reachability and disk space. The script installs no packages and never replaces M04 configuration or service binaries. It creates a dedicated broker account if absent, root-private lab state/CA/image artifacts, separately scoped binaries, and `/run/netns` if needed. Nothing enables production services or executes a repository. The fixed guest disk reserves 10 GiB; the fixture image is under 1 GiB.

The script prints its private evidence directory under `/var/lib/orchestrator-builder/m05-lab.*`. Keep that directory, build log, hashes, root-owned journals and reports outside the repository. Private CA keys and ownership proofs must not be copied into public evidence. Binaries under `/usr/local/libexec/<lab-name>` are deliberately executable by the dedicated broker UID; private inputs are supplied via file descriptors.

The suite executes real installed provisioner/test binaries:

| Test | Operation |
|---|---|
| `TestRealBrokerNetworkLifecycle` | Actual QEMU guest-root proxy/direct/spoof probes, readiness, cancellation, confirmed resource removal and delayed-start denial |
| `TestRealBrokerIndependentExpiry` | Pause both supervisors with SIGSTOP; require PID-1 hard expiry to remove guest, broker sessions/cgroups and namespace without API/controller/guard progress |
| `TestRealBrokerSetupCrashRecovery` | Abrupt subprocess death at intent, namespace creation, identity persistence, TAP setup, firewall install, link enable and broker start |
| `TestRealBrokerForeignNetworkPreserved` | Replace an owned namespace with a foreign inode and namespace firewall canary; require cleanup failure and unchanged canary |

The namespace-creation crash deliberately has no persisted ownership inode. The test confirms cleanup refuses it, then uses its separately recorded private creation witness for explicit lab recovery. Production has no witness override or environment-activated fault mode. Checkpoints are unexported package fields assigned by the test binary only. A successful cleanup returns all three M04 cleanup flags; otherwise retain capacity and investigate.

To rebuild/retest a previous **clean** scoped lab without another image build:

```sh
M05_LAB_APPROVED=YES-I-AUTHORIZE-REAL-NETWORK \
  python3 infra/egress/m05-lab.py --retest /var/lib/orchestrator-builder/m05-lab.<id>
```

Retest refuses remaining raw disks or namespaces, preserves prior results and records new binary hashes and a distinct log/report. Do not manually remove uncertain state to force this check to pass.

## Controlled internal capture-based acceptance (executed)

The user authorized internal fixtures in the isolated VM. The complete N01–N13
run is recorded as PASS in the [acceptance report](acceptance-report.md).
Reproduce that controlled suite after preparing a clean scoped base lab:

```sh
M05_LAB_APPROVED=YES-I-AUTHORIZE-REAL-NETWORK \
  python3 infra/egress/controlled-lab.py \
  --lab /var/lib/orchestrator-builder/m05-lab.<id>
```

This harness temporarily assigns synthetic public-class loopback aliases and
installs a separate lab upstream CA, runs controlled DNS/HTTPS fixtures, captures
at the guest/host/other-job boundaries with loss checks, and verifies destination
canaries. It exercises the software without destination/TLS bypasses. It also
runs active-transfer cancellation/expiry, setup crashes, invalid policy recovery,
foreign-resource preservation and cancellation races. A fixed Go guest fixture
adds UDP/IPv6/RA, nested tunnel, SNI, authority reuse and resource probes.

Review the [runbook](../../../../../infra/egress/README.md#fully-controlled-internal-acceptance)
for precise temporary changes and restoration. Check `cleanup.json`: trust must
be restored, owned loopback aliases/fixture processes removed, and host firewall
structure unchanged. The installed tests verify owned VM/broker/disk/namespace
cleanup. Private evidence, pristine images and audit tombstones remain.

## Capture-based procedure for operator-selected endpoints

Record the source revision/content hashes, binary hashes, template digest, policy/CA hashes, kernel/QEMU/systemd/nftables/resolver versions, operator, UTC times, topology and baseline inventory. Capture host firewall rules and foreign namespace/rule canaries before starting. Keep raw captures privately; only sanitized outcomes go into milestone evidence.

1. Use controlled public HTTPS endpoints with valid upstream certificates and canary request logs. The origin must be explicitly allowed. Supply endpoints that return ordinary 200, every redirect class and an upgrade, plus a separately approved hostname with invalid TLS. Do not weaken production certificate or address checks.
2. Use a dedicated controlled DNS resolver without internal zones to return public-only, mixed IPv4/IPv6, mapped, public-to-private rebinding, empty, slow and failed answers for approved names. Log every query and attempted destination connection. Repeat through fresh CONNECT sessions to test re-resolution.
3. Acquire a five-minute lease using the existing mTLS provisioner contract. Discover the namespace from its root-only journal without exporting the ownership proof. Capture simultaneously on `tap0` inside that namespace, the broker uplink and relevant host interfaces. Select exact known capture filters and owned output paths; never flush firewall rules.
4. Run guest-root probes with changed proxy variables, IP/MAC/routes and IPv6/RA frames. Verify both client outcomes and destination non-arrival. `guest-probes.sh` provides initial HTTP/TCP observations but does not cover UDP/RA/QUIC or every address class. Extend the credential-free fixture for those matrix cases and record its new digest.
5. Use controlled internal/metadata/public-management-alias and other-job canaries. Explicitly configure infrastructure deny CIDRs, including public management aliases. Each denied probe needs an unambiguous non-secret marker and destination evidence; timeouts alone do not pass N02–N08.
6. Kill broker and resolver independently during active transfers, and test invalid/missing policy and stale policy hash. Require no fallback and no new guest admission. Check malformed CONNECT, TLS/SNI mismatch, HTTP authority changes, nested tunnels, oversized/slow headers, concurrency and byte-rate/total limits.
7. Run API/controller/guard losses separately and the automated paused-supervisor expiry check. Exercise the unmodified cancellation API while creation is at each stage. Confirm no delayed start succeeds after fencing. Preserve foreign canaries, unknown-version journals and uncertain reservations.
8. Cancel all leases. Confirm owned guest/broker cgroups, namespace/TAP/rules, raw disks and active sessions are absent. Existing root-owned journals/tombstones, pristine images, evidence and reviewed binaries may remain. Compare foreign inventories and host firewall baseline; nothing should have been flushed or replaced.

Map each result to N01–N13 as PASS, FAIL, SKIP or Not run. Acceptance requires all required cases and controlled evidence. A smoke PASS, an automated crash PASS, or a rendered firewall is insufficient to declare all SEC-07 requirements accepted. Retain the approved-origin exfiltration and client-compatibility limits in the sign-off.
