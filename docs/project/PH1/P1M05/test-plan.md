# P1-M05 test plan — controlled build egress

Status: **Executed: software checks and controlled N01–N13 KVM acceptance PASS**. See [implementation evidence](implementation-evidence.md) and the [acceptance report](testing/acceptance-report.md) for actual results.

## Objective and prerequisites

Prove SEC-07 at the external network boundary: approved HTTPS works through the broker while guest-root attempts cannot reach direct internet, host/management, metadata or other jobs. Application URL validation and mock tests alone are insufficient.

Use an approved disposable Linux KVM host with nftables, packet capture, a dedicated resolver, controlled HTTPS destinations and a credential-free pinned test guest. Keep captures and private CA material outside the repository. Record the baseline host firewall and foreign-resource canaries before testing. Do not run hostile workloads on an unapproved/shared host or shared CI.

Preserve M04 V14/V15 SKIP in all reports. Inspect actual lab network/patch posture before execution; unresolved prerequisites block the affected tests without changing historical M04 results.

## Automated software checks

| ID | Scenario | Required result |
|---|---|---|
| U01 | Empty, malformed, unknown-version and ambiguous policy | Reject invalid policy; empty allowlist permits no origins |
| U02 | Hostname normalization, encoded authorities, userinfo, IP literals, alternate ports | Only unambiguous approved hostname:443 accepted |
| U03 | IPv4/IPv6 special-use, mapped, metadata and explicit management ranges | All denied; reviewed public controls allowed |
| U04 | Mixed A/AAAA, DNS failure, rebinding and changed subsequent answers | Reject any denied answer; dial only pinned validated addresses |
| U05 | CONNECT/SNI/HTTP authority mismatch and upstream certificate failures | Deny without upstream data disclosure |
| U06 | Redirect, upgrade, nested tunnel and authority-changing reuse | Deny; no cross-authority connection reuse |
| U07 | Expired/revoked/wrong-job identity and active session expiry | No admission; active sessions close at lease deadline |
| U08 | Slow clients, oversized headers and concurrency/bandwidth limits | Bounded resource use and deterministic failure |
| U09 | Credential/query/body fixtures in errors and logs | Sensitive fixture values absent from persisted diagnostics |
| U10 | Legacy/unknown manifests and cleanup ownership mismatch | Legacy no-NIC cleanup works; unknown/foreign resources preserved |

Run `go test ./...`, `go vet ./...`, applicable race tests and builds. Run Linux-specific provisioner regression tests on Linux, especially descriptor inheritance, QEMU privilege restrictions and independent deadlines. Add fuzz coverage for policy/authority parsing and address classification.

## Real-host execution matrix

Capture simultaneously at the guest boundary, broker uplink and relevant host interfaces. Use destination canaries to confirm non-arrival; a client timeout alone is not proof. Give each probe a unique non-secret marker.

| ID | Procedure | Required evidence/result |
|---|---|---|
| N01 | Fetch controlled approved HTTPS through proxy; repeat for unapproved origin | Approved response succeeds with valid TLS; unapproved origin denied |
| N02 | From guest root bypass proxy using direct public IPv4/IPv6 sockets | No packets arrive at destination; no direct routed path |
| N03 | Probe loopback, private, link-local, reserved, multicast, metadata and configured infrastructure targets, including public management aliases | No protected destination receives traffic, through broker or directly |
| N04 | Attempt UDP/TCP DNS, alternate resolver, DoH to an unapproved origin and UDP/QUIC | No alternate destination or transport bypass; approved-origin access remains an explicit residual risk |
| N05 | Change guest IP/MAC/routes, send IPv6/RA traffic and target another guest identity | No spoofing, cross-job or host-service access |
| N06 | Controlled DNS changes public to private; return mixed A/AAAA and mapped addresses | Denied answers never dialed; validated connection remains pinned |
| N07 | Present invalid upstream TLS, mismatched SNI/authority and redirects to approved/private targets | All rejected; redirect target receives no request |
| N08 | Attempt protocol upgrades, arbitrary CONNECT and nested tunnels | No unrestricted tunnel established |
| N09 | Kill broker/resolver; restart with invalid/missing policy | Guest gets no fallback access; no admission with invalid policy |
| N10 | Cancel/expire job with active transfer; kill controller/API/guard separately | External deadline terminates VM/session and prevents delayed start |
| N11 | Interrupt each setup stage, restart provisioner and reconcile | No open networking window; owned remnants removed or capacity visibly reserved |
| N12 | Race creation/cancellation; place foreign network/rule canaries | Start fenced; foreign resources unchanged; uncertain cleanup retains reservation |
| N13 | Final inventory and baseline comparison | No owned VM, disk, TAP, namespace, rule or live broker session remains |

Run N02–N08 with guest root privileges and altered proxy environment variables. Exercise genuine networked guests, not only host-originated probes. Keep test-only destination overrides confined to isolated fixtures and unavailable in production configuration.

## Evidence and acceptance

For every ID record PASS, FAIL, SKIP or Not run, command/probe identifier, expected/observed result and evidence location. Capture commit/binary hashes, template digest, policy hash, kernel/QEMU/nftables/resolver versions, execution time, operator and topology. Sanitize summaries; retain raw captures privately.

M05 acceptance requires all required software and real-host cases to pass. Failure or missing network evidence leaves acceptance pending. Record any cleanup uncertainty as a blocking incident with capacity retained. Do not equate a successful fetch, rendered firewall configuration or mock assertion with isolation evidence.

The acceptance report must preserve residual limits: approved public endpoints may receive exfiltrated data, inspection changes client compatibility, and M06/later build gates remain outstanding. Update status indexes only after recording the actual result.
