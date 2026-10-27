# PH1 capability and security evidence checklist

P1-M01–P1-M04-core inventory. A checked contract/storage/auth/lifecycle assertion is not an infrastructure guarantee. Credential-free real KVM fixtures and test-only API/guard processes have been executed; no real repositories or application containers were used. P1-M04 is recorded as PASS*: V14 and V15 marked as SKIP. Skips are not passes; see the [acceptance record](../testing/P1-M04-acceptance-report.md).

## Required isolation capabilities

| Capability | External evidence needed | Task / release behavior |
|---|---|---|
| Linux KVM and fixed clean template | Real guest boot, pinned-template rejection, fresh disks and no host shares tested | M04 PASS*; V14/V15 SKIP; execution remains explicitly configured |
| Host-enforced CPU/RAM/disk/time budget | Exhaust guest, management stays operable, hard expiry works | M04/M07; no local-build fallback |
| Build egress broker only | Packet capture/probes for direct IP/DNS/IPv6/metadata/host reachability | M05; block real Git builds |
| Rebinding/redirect/dependency isolation | Live malicious resolver and dependency fixtures | M05/M06; URL validation insufficient |
| Quarantined OCI ingest/scanning | Digest, archive expansion and scanner-isolation tests | M07; unapproved artifacts never deploy |
| Rootless cgroup/MAC/seccomp support | Engine inspection and resource attack fixtures | M09; refuse unsupported profile |
| App-private network and no host ports | Cross-app/host scans plus relay connectivity | M09/M11; private engine alone insufficient |
| Volume quotas/ownership | Wrong-app attach denied, symlink race and quota exhaustion | M10; named volumes alone insufficient |
| mTLS + command signature/replay ledger | M04 controller mTLS/URI/pin/expiry and durable command/nonce checks tested; real host adapter tested; runtime signature ledger remains pending | M04 Linux gate/M09; neither shape-only runtime envelopes nor model tests authorize execution |
| Authenticated gateway | Direct URL, HTTP/WS/stream auth, forged header and outage tests | M03/M11; fail closed |
| Cleanup independent of API | Real controller/API/guard-loss expiry, frozen supervisor, crash recovery and final inventory passed | M04 PASS* (V14/V15 SKIP)/M12; retain reservation on uncertain cleanup |

## Requirement-to-test map

| Release test | Current evidence | Remaining dependency |
|---|---|---|
| SEC-01 anonymous API/setup | Actual password/session endpoint tests; setup separate loopback listener, one-time DB marker; unauthenticated management namespace denied | M14 complete future endpoint inventory; MFA if required day one |
| SEC-02 user cannot deploy | Actual role-gated management request tests, forged headers denied, current DB role rechecked | No deployment handler exists yet; M12/M14 must preserve role checks on real job submission |
| SEC-03 no app ports | No engine exists; not evaluated | M09/M11 port scan |
| SEC-04 gateway ACL | Principal grant helper only | M11 real requests |
| SEC-05 no management socket | No engine integration; architectural restriction | M09 process/mount inventory |
| SEC-06 Compose dangerous fields | Agent-spec unknown fields rejected, YAML is unparsed | M08 strict Compose parser + agent policy |
| SEC-07 SSRF/egress | Lexical URL protocol/path tests only | M05/M06 external enforcement |
| SEC-08 resource limits | Fixed build profile and admission gates tested; no real host quota enforcement yet | M04/M07/M09 actual enforcement |
| SEC-09 volume/credential isolation | Mount shape/nonoverlap tests only | M10 ownership/quota/storage proof |
| SEC-10 secrets absent from logs | Decoder/auth errors sanitized; password hashes/token hashes verified in DB; auth audit contains no request secrets; raw session token only in secure cookie | Remaining M04–M14 logging/build output paths |
| SEC-11 cleanup | Actual lease DB with test-only VM model exercises expiry/retry/failure reservation; no real execution resources created | M04/M12 actual timeout/crash inventory |
| SEC-12 timed revoke | Logout/disabled account/auth epoch/current roles enforced on next management request; DB outage denies | App gateway/WS/SSE timed lease closure in PH2/PH3 |
| SEC-13 proxy rollback | Not implemented | M11 |
| SEC-14 backup restore | DB integrity/reopen and abrupt-process WAL recovery tests; not backup/restore | M14 smoke; PH5 complete drill; existing-data upgrades blocked pending backup workflow |
| SEC-15 iframe origin isolation | No frontend yet | PH2 |
| SEC-16 replay/wrong worker | Worker/expiry/generation prechecks, not signature/ledger | M09 |
| SEC-17 concurrency | SQLite state/event/audit/outbox atomicity, idempotency, cross-handle CAS and process crash tests | M12 full deploy/cancel/route-generation race tests |
| SEC-18 MFA recovery | Not implemented | PH3, earlier if day-one requirement |

Operator decisions still required: production hardware/distribution (Q01), day-one MFA (Q02), rootless network and storage enforcement (Q05), scan thresholds (Q07), app backup policy (Q09). Do not mark PH1 complete until its actual release gates pass.
