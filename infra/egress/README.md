# PH1M05 external build egress

The Linux provisioner implements explicit `broker-v1` networking. Omit
`network_mode` (or use `none`) to preserve no-NIC execution. Nothing in this
folder enables a host or authorizes repository execution.

## Topology

Each lease owns a network namespace containing only `tap0`, the fixed broker
address `192.0.2.1/30`, and two nftables tables. The guest uses
`192.0.2.2/30`, MAC `02:00:00:00:00:02`, and proxy
`http://192.0.2.1:8443`. There is **no veth, bridge, NAT or uplink**. Host IP
forwarding and host firewall changes are unnecessary.

The root broker supervisor opens its listening socket in that namespace,
restores its original namespace and passes the socket plus read-only policy/CA
file descriptors to an unprivileged `orchestrator-egress` child. The child's
new upstream sockets use the host network namespace. It inspects TLS; guest
CONNECT, SNI and HTTP authority must match an approved hostname on port 443.
The public build CA must already be in the pinned guest template. The private
key never enters the guest.

## Reviewed installation on a disposable Debian KVM lab

First satisfy the [M04 setup](../builder/README.md), including template pinning,
cgroup v2, storage/account ownership and independent expiry. Keep M04 V14/V15
SKIP in the historical record. Install maintained `iproute2` and `nftables`
through the approved host package process. Canonical executables must exist at
`/usr/bin/ip` and `/usr/sbin/nft`, with trusted root-owned ancestors. `/dev/net/tun`
and `/dev/kvm` are mandatory. Prepare root-owned `/run/netns` (mode 0755) and
ensure the host policy permits namespace creation and namespace-local netdev
nft hooks. No fallback is provided.

Build and review:

```sh
go build -o /tmp/egress-broker ./cmd/egress-broker
go build -o /tmp/orchestrator-provisioner ./cmd/provisioner
go test -c -o /tmp/provisioner.test ./internal/provisioner
```

Install reviewed binaries under root-owned, non-writable-by-others paths. Create
a dedicated non-login `orchestrator-egress` system account and group, separate
from `orchestrator-qemu`, with UID/GID at least 100. Keep all management files
private to their existing service users. Create
`/etc/orchestrator-builder/egress` as root mode 0700. Store the policy, dedicated
build-only CA certificate and private key there as root mode 0600. The child
receives only already-open read-only descriptors; it needs no directory access.
CA material must be created and retained outside this repository. Never reuse
a production/user/application CA. Enroll its public certificate in the pinned
credential-free template and record that template's digest before admission.

Start with `policy.example.json`; its empty allowlist denies all origins. Add
only controlled approved DNS names, required public infrastructure deny ranges,
and bounded resource settings. Select a dedicated, operator-trusted resolver
with no internal zones; configure its literal IP and TCP port 53. Guest DNS is
unavailable. A dedicated resolver is part of the isolation prerequisites, not
something created by the provisioner.

The backend JSON keeps all M04 fields and adds:

```json
{
  "network_mode": "broker-v1",
  "egress_policy": "/etc/orchestrator-builder/egress/policy.json",
  "egress_policy_hash": "<canonical policy hash>",
  "egress_ca": "/etc/orchestrator-builder/egress/ca.pem",
  "egress_key": "/etc/orchestrator-builder/egress/ca-key.pem",
  "egress_ca_hash": "<SHA-256 of DER CA certificate>",
  "egress_resolver": "<dedicated-resolver-IP>:53",
  "broker_executable": "/usr/local/libexec/egress-broker",
  "broker_uid": 992,
  "broker_gid": 992
}
```

Use the actual dedicated account IDs. Obtain canonical hashes from the broker's
read-only inspection command:

```sh
/tmp/egress-broker -inspect -policy /path/to/policy.json -ca-cert /path/to/ca.pem
```

This command does not load a private key, create a listener or start a lease.
The policy hash covers the decoded typed policy, including list order and
nil/empty distinctions. Do not use a raw file checksum as `egress_policy_hash`.
Update all pins in the root-only `backend.json` before restarting the API.

The existing API/guard services launch owned transient `orchestrator-broker-<job>.service`
units automatically. Their generated properties are in
`internal/provisioner/linux_network_linux.go`: Type=notify, no restart,
control-group termination, exact remaining lease RuntimeMaxSec, startup timeout,
private devices, filesystem protection, 256 MiB memory, 32 tasks, 256 FDs,
restricted address families and bounded journal rate. The root supervisor has
only SETUID/SETGID/SYS_ADMIN capabilities. Its child has a dedicated UID, no
supplementary groups, no ambient capabilities, no management environment, and
NoNewPrivileges. The QEMU supervisor separately gains namespace/TAP setup
capabilities; QEMU still runs unprivileged with only disk and TAP descriptors.

For later clients set `HTTPS_PROXY=http://192.0.2.1:8443` and install the public
CA through the template's normal trust-store mechanism. Curl fixtures use
`--cacert /build-ca.pem`. There is no DNS, DHCP, direct HTTP, QUIC or ingest
endpoint. The broker intentionally permits one HTTP/1.1 request per CONNECT
and rejects redirects, upgrades, arbitrary tunnels and Connection headers.

## Fixture and execution

Build a new, never-booted M04 fixture using the additional `egress` mode on the
approved image-building lab only:

```sh
sudo env M04_IMAGE_BUILD=YES-I-AUTHORIZE-LOOP-IMAGE \
  M05_CA_CERT=/path/to/public-build-ca.pem \
  M05_PROBE_HOST=controlled.example.org M05_CONTROL_IP=203.1.2.3 \
  bash infra/builder/build-lab-fixture.sh egress
```

Use a real controlled public IPv4, not the illustrative value above. Its server
must return 200 at `/` (the probe appends a non-secret `m05` query marker). The fixture
copies only the public CA, curl/ip and their shared libraries plus the guest
probe script. Record kernel, tool/library versions, script and image hashes.
It contains no repository, credential or private CA. Pin the resulting image
and a distinct template ID in the backend. Do not mount a guest-modified copy.

Run the opt-in lifecycle test using a reviewed, installed test binary:

```sh
sudo env M04_DISPOSABLE_HOST=YES-I-AUTHORIZE-REAL-KVM \
  M05_DISPOSABLE_HOST=YES-I-AUTHORIZE-REAL-NETWORK \
  M04_HOST_CONFIG=/var/lib/orchestrator-builder/host/backend.json \
  /path/to/reviewed/provisioner.test -test.v -test.run '^TestRealBrokerNetworkLifecycle$'
```

This tests actual namespace/broker/QEMU startup, waits for the fixed guest probe report, then checks cancellation, owned removal and a delayed-start fence. It is **not the full acceptance matrix**. For complete capture-based evidence, use a five-minute mTLS lease through the existing provisioner interface, wait
for `M05-NETWORK-DONE` using the M04 bounded raw disk evidence procedure, and
cancel through the controller. Do not copy example ownership proofs or fabricate
host journals. Take packet captures and destination canary observations at the
same time. `guest-probes.sh` records client observations, not acceptance passes.
The report uses M04's fixed bounded tail export region; collect it before
cleanup deletes the raw disk. Never extract or mount that disk.

Execute [N01–N13](../../docs/project/PH1/P1M05/test-plan.md) and record every
result using the [lab procedure](../../docs/project/PH1/P1M05/testing/real-host.md).

## Cancellation, recovery and rollback

Cancel through the provisioner, not by deleting files. Cleanup fences the
journal, stops QEMU, confirms its cgroup empty, stops the owned broker, confirms
its cgroup empty, verifies namespace device/inode identity and deletes exactly
that namespace. Namespace-local TAP/rules disappear with it. Cleanup never
flushes a host firewall, deletes a bridge or removes another namespace.

An independent CLOCK_BOOTTIME systemd timer kills the exact VM and broker units
at expiry, then fences/removes the namespace. RuntimeMaxSec and the child's
absolute deadline are additional limits. The guard constructor can recover old
leases despite missing/invalid/expired egress policy or CA; new admission still
requires a valid preflight. A policy/CA change never silently rebinds a lease.

On uncertain ownership, the manifest and ledger reservation remain. A crash
between namespace creation and inode persistence intentionally needs operator
investigation. Record the job, host journal, namespace inventory and unit
ownership descriptions; recover only with verified evidence. Never clear a
reservation or guess ownership from a resource name. Preserve unknown-version
journals and foreign collisions.

Before rollback, drain/cancel all leases and verify broker/QEMU cgroups and
owned namespaces are absent. Switch the backend to `network_mode: none`,
remove the egress-specific fields, and restart the existing services. Keep
journals/tombstones. An older binary cannot safely clean version-1 networked
journals: use the new binary to complete cleanup before downgrading. Retire
build-only CA keys using the organization's key procedure. Do not remove or
change host firewall rules as part of rollback.

## Fully controlled internal acceptance

The additional harness requires an explicitly approved isolated VM because it
temporarily changes that VM's loopback addresses and upstream trust store:

```sh
M05_LAB_APPROVED=YES-I-AUTHORIZE-REAL-NETWORK \
  python3 infra/egress/controlled-lab.py \
  --lab /var/lib/orchestrator-builder/m05-lab.<id>
```

Create the scoped base lab with `m05-lab.py` first. The controlled harness
refuses remaining working disks/namespaces and foreign alias/trust collisions.
It builds a credential-free guest and fixed raw/protocol probe binary, creates
synthetic public-class local aliases 11.0.0.1–3 and 2003::11, and binds a
fixture-only authoritative TCP resolver to 127.0.0.55:53. Do not run it on a
production/shared host: those public-class addresses are test aliases, not
assigned external destinations.

A separate temporary upstream CA enters the isolated host's trust store only
for this run. The build CA remains separate and only its public certificate
enters the guest. Production broker IP/TLS verification stays enabled; test
fixtures have no production configuration override. Python fixture services
provide positive HTTPS, wrong certificates, redirects, upgrades, mixed/mapped
and rebinding answers, actual resolver stop/restart, protected canary logs and
stream interruption evidence.

The installed Go test binary captures AF_PACKET pcaps at the guest TAP, selected
host paths and an independent other-job TAP; capture packet loss is checked.
Guest root sends valid raw UDP/IPv6/RA fixtures and HTTP/tunnel/resource probes.
The suite also exercises paused-supervisor active-stream expiry, cancellation,
seven abrupt setup deaths, foreign namespace/firewall preservation, invalid
policy recovery and a creation/cancellation race. No package installation or
host firewall change is required; the capture code is test-only.

All logs/pcaps/keys stay in root-private lab evidence directories. `finally`
stops fixture processes, removes owned aliases and the temporary trust source,
and checks the restored trust bundle and unchanged host firewall structure.
VM/broker/TAP/disk cleanup remains the provisioner's responsibility and is
asserted by the tests. Pristine templates, binaries, audit tombstones and
private reports remain for review. Inspect `run.log`, `evidence.json`,
`capture-summary.json`, `other-job-summary.json` and `cleanup.json`.

The [recorded acceptance](../../docs/project/PH1/P1M05/testing/acceptance-report.md)
passed this controlled suite. Repeat it for any changed host/template/policy
before relying on that environment. Historical failed development probes are
retained; they are not overwritten or counted as passes.
