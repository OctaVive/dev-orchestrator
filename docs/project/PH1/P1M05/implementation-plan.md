# P1-M05 implementation plan — controlled build egress

Status: **Planned; implementation not started**. This document is for review.

## Outcome and boundaries

Implement an external HTTPS inspecting broker and host-enforced guest networking. Disposable build guests may reach approved public HTTPS origins through the broker; direct internet, DNS, internal services and metadata remain blocked.

Preserve [M04's qualified PASS](../P1M04/testing/acceptance-report.md), including V14/V15 SKIP. M05 requires its own real-host network evidence and does not authorize repository builds before M06. Private Git credentials, clone execution, BuildKit and artifact ingestion remain later work.

## Policy and interfaces

- Define a versioned, operator-owned policy with exact approved hostnames on port 443, infrastructure deny ranges and bounded connection/resource limits. Default allowlist is empty.
- Bind guest network identity to its lease, policy hash and expiry through host-controlled state. Guest headers cannot select a different job.
- Keep networking configuration host-local; preserve current provisioner RPC request shapes. Extend durable host manifests with network ownership and policy identity.
- Validate configuration before creating resources. Missing capabilities or unsupported configuration fail closed.

## HTTPS broker

- Add a separate Go service outside guests, without management credentials or provisioner control access.
- Use the reviewed inspecting-proxy approach: a dedicated build-only CA whose public certificate is installed in the pinned guest template. Signing keys remain outside guests.
- Accept only approved hostname authorities on port 443. Require CONNECT authority, guest TLS SNI and HTTP authority to match; independently validate upstream certificates and hostname.
- Resolve through a dedicated resolver with no internal zones. Validate every A/AAAA answer, reject mixed allowed/denied results and dial a validated IP without resolving again.
- Deny IP literals, special-use addresses, mapped IPv6, metadata and configured infrastructure addresses using a reviewed classification table and regression fixtures.
- Reject upstream redirects, upgrades and arbitrary tunnels. Never reuse upstream connections across authorities.
- Bound headers, concurrency, bandwidth and connection duration by operator policy and remaining lease time. Expiry/revocation closes active sessions. Resolver or policy failures deny access.
- Log bounded decision metadata and reason codes, excluding request bodies, headers, credentials and query-bearing URLs.

## Host networking and lifecycle

- Add explicit broker-network mode to the Linux backend; preserve no-NIC mode and disabled execution defaults.
- Create an owned per-job network namespace and TAP. Pass an already-open TAP descriptor to unprivileged QEMU without network-administration capability.
- Use routed isolation and atomic nftables rules allowing only the assigned guest identity to the broker's exact listener. Deny host services, other guests, direct forwarding, DNS, UDP/QUIC and guest IPv6 traffic.
- Use fixed addressing without DHCP or guest DNS. The broker can reach validated public IPv4/IPv6 destinations; native guest IPv6 stays disabled and filtered.
- Install enforcement before QEMU starts. Persist ownership before creation, fence delayed starts and include all network resources and broker sessions in cancellation, independent expiry and crash reconciliation.
- Confirm network cleanup before releasing capacity. Preserve foreign resources; retain reservations on uncertain ownership or removal.
- Leave artifact-ingest access disabled until its authenticated endpoint is implemented.

## Packaging and delivery order

1. Define policy, host-manifest compatibility and broker interfaces; implement policy/address validation and tests.
2. Implement broker mediation, resolver integration, lease enforcement and service isolation.
3. Integrate TAP/network setup, QEMU descriptor handling, nftables enforcement and lifecycle recovery.
4. Supply service definitions, policy/firewall examples and a reproducible network-test guest with the public build CA. Document standard proxy settings for later clients.
5. Document preflight, operator-reviewed installation and rollback restricted to owned resources; never flush the host firewall.
6. Execute the [test plan](test-plan.md), record actual evidence and update milestone documentation, LLD and status indexes to match results.

Existing no-network manifests remain cleanable; networked manifests require their recorded ownership and policy identity. Unknown manifest versions fail closed rather than guessing resource ownership.

## Acceptance and assumptions

Use an approved disposable Linux KVM lab for hostile tests. Unsupported dependencies fail closed. Required network evidence must pass before M05 acceptance; missing evidence leaves acceptance pending. M05 does not retroactively pass M04's skipped checks or establish host patch compliance.

Authoritative constraints: [Git/build pipeline](../../../architecture/git-deployment-pipeline.md), [build lifecycle](../../specifications/deployment-agent.md) and [test strategy](../../specifications/testing-strategy.md).
