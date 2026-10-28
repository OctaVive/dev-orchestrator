# P1-M05 acceptance record — PASS in the isolated KVM lab

Decision: **PASS**, 2026-10-28. Implementation, software checks and the controlled
internal N01–N13 acceptance run completed. This is milestone acceptance on the
tested VM/template, not production rollout or PH1 release approval. M04 V14/V15
remain **SKIP**, without being retroactively counted as passes.

The user explicitly authorized creating internal controlled fixtures in this
isolated VM. The resulting topology uses synthetic public-class IPv4/IPv6
loopback aliases, a local controlled resolver and separate temporary upstream
CA. Production address checks and TLS validation stayed enabled. A real QEMU/KVM
guest ran the hostile probes; no simulator or production destination override
was used. An additional isolated namespace/TAP represented another job.

Private evidence root:

`/var/lib/orchestrator-builder/m05-lab.4cac6wpp/controlled.1793215611889984415/`

Canary event interval: **2026-10-28 19:27:19–19:29:03 UTC**. Installed tests ran
as root under the authorized lab harness. `run.log`, `evidence.json`,
`capture-summary.json`, `other-job-summary.json`, `canary.jsonl`, `guest.pcap`,
`host.pcap`, `other-job.pcap`, `cleanup.json` and `final-inventory.json` retain
the actual observations, versions, ownership checks and content hashes.

## Environment and identities

| Item | Recorded value |
|---|---|
| Kernel | 6.12.113+deb13-amd64 |
| QEMU | 10.0.13, Debian 1:10.0.13+ds-0+deb13u1 |
| systemd | 257.13-1~deb13u1 |
| nftables | 1.1.3 |
| iproute2 | 6.15.0; libbpf 1.5.0 |
| Go | 1.27.3 linux/amd64 |
| KVM API | 12 |
| Controlled DNS | 127.0.0.55:53, TCP, fixture-authoritative answers |
| Allowed HTTPS canaries | 11.0.0.1 and 2003::11, scoped loopback aliases |
| Protected canaries | 127.0.0.77 and 11.0.0.3; private/rebind and explicit infrastructure denial |
| Bad certificate canary | 11.0.0.2; trusted issuer but wrong hostname |

| Pin | SHA-256 |
|---|---|
| Guest template | `2560078a952f7d4dc4f5e4f895a271ba9ca2ab516d7cbe3a4539f8006070bb30` |
| Policy | `753d23f4ef928503ffc9fa0e5cb8b399a56136ee0a5640e4f0262eda0b70bdd6` |
| Public build CA | `c933dc1a838a50c6a5a3a073dbc38637c12a8ec667a105c48c7a1997eacd9122` |
| Broker binary | `f3093e501e20042f29b28ccf6543df3435e00851d8d12cd207ff8811a77f24f9` |
| Provisioner binary | `2310c3a50c1daa9257e94792cf5ee3b526f3f8e645c463104683a54cc04a5f5a` |
| Installed test binary | `72316ca463273fb782aa626a6f14af30f03cd70983d721cb79e7f9bb35be66f6` |

## Real-host matrix

| ID | Actual exercised behavior and evidence | Result |
|---|---|---|
| N01 | Approved IPv4/IPv6 HTTPS succeeded through the inspecting broker; unapproved origins denied. Guest report, DNS/HTTPS canaries and both captures agree. | PASS |
| N02 | Guest-root direct public IPv4/IPv6 TCP probes, including raw packets and explicit guest default route, did not escape. Guest/host captures and counters, zero capture loss. | PASS |
| N03 | Direct/proxy loopback/private/shared/metadata probes, private DNS answer and public infrastructure CIDR denial; protected destination captures/logs had zero arrivals. Software special-use regression fixtures cover the address table. | PASS |
| N04 | TCP DNS, alternate HTTPS port, unapproved DoH, raw UDP DNS and UDP/443 bypass probes were denied. UDP canary logs had zero arrivals; no guest frame escaped to host. | PASS |
| N05 | Changed guest IP/MAC denied; restoring identity restored HTTPS. Raw IPv6/RA traffic dropped. Independent other-job TAP capture had zero frames and zero capture loss. | PASS |
| N06 | Actual controlled resolver returned mixed A/AAAA, mapped AAAA, public then private rebinding and SERVFAIL. Prime fetch succeeded; later/denied targets received no request or connection. | PASS |
| N07 | Actual upstream hostname certificate failure, guest SNI mismatch, HTTP authority mismatch and redirect denied. No redirect/private target received a request. | PASS |
| N08 | Unapproved/IP CONNECT, nested CONNECT, request/response upgrades and authority-changing pipelined reuse denied. First allowed reuse-control response succeeded; no second/private request arrived. | PASS |
| N09 | Resolver listener actually shut down/restarted: no fallback, then recovery. Broker service stopped: subsequent guest request denied. Invalid/missing/unknown/stale policies rejected before resource creation; guard still restarted for recovery. | PASS |
| N10 | Active streaming transfer cancelled and independently expired. Both supervisors SIGSTOPed during expiry; PID-1 deadline killed descendants, fenced start and removed namespace. Canaries recorded stream interruption. Controller/API/guard were not needed for these leases. | PASS |
| N11 | Abrupt provisioner subprocess exit at seven setup boundaries; reconciliation cleaned confirmed resources. Missing namespace identity retained cleanup failure until explicit lab witness recovery. | PASS |
| N12 | Creation/cancellation race settled with a durable fence and no delayed resource. Replacement foreign namespace/inode and firewall canary survived attempted cleanup unchanged. | PASS |
| N13 | 55 lab jobs inventoried: no active owned VM/broker unit or populated cgroup, no working disk/namespace/session. Temporary resolver/HTTPS fixture, aliases and trust removed; host firewall and original M04 configuration unchanged. | PASS |

Packet evidence: guest **1,801** frames, host **1,476** selected frames, **zero
capture drops** on both, other-job **zero** frames and capture drops. Rules
recorded **62 ingress drops**. Controlled logs contained **92 events** and
**zero forbidden arrivals**. Resource probes also passed oversized-header,
response-byte-budget, concurrent-session and slow-header checks. Software race,
vet and three parser/address fuzz smoke checks passed; see [full implementation
evidence](../implementation-evidence.md) for commands and development failures.

## Qualification and handoff

The synthetic addresses were bound only inside the authorized isolated VM;
this run does not assert that those addresses are available or approved on any
production network. Host trust was extended only for this controlled run, then
restored byte-for-byte. Build and upstream CAs were separate. Root-private keys,
raw captures and ownership proofs are not checked into the repository.

Approved public origins can receive exfiltrated build data. TLS inspection and
single-request tunnels affect client compatibility. Production admission still
requires the pinned template/CA, dedicated resolver, explicit policy, supported
host capabilities and operator deployment of this configuration. No-NIC mode
remains the default. M06 repository execution and all subsequent phase gates
remain separate; this result does not authorize private credentials, BuildKit,
artifact ingest or production deployment.
