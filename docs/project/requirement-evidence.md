# PH1 capability and security evidence checklist

P1-M01–P1-M08-core inventory. A checked contract/storage/auth/lifecycle assertion is not an infrastructure guarantee. Credential-free real KVM fixtures, controlled Git repositories and test-only API/guard processes have been executed; hostile Git/OCI parsing and rootless image builds ran only inside guests. M07 admitted a scanned image but did not deploy an application. P1-M04 is recorded as PASS*: V14 and V15 marked as SKIP. Skips are not passes; see the [acceptance record](PH1/P1M04/testing/acceptance-report.md).

## Required isolation capabilities

| Capability | External evidence needed | Task / release behavior |
|---|---|---|
| Linux KVM and fixed clean template | Real guest boot, pinned-template rejection, fresh disks and no host shares tested | M04 PASS*; V14/V15 SKIP; execution remains explicitly configured |
| Host-enforced CPU/RAM/disk/time budget | Exhaust guest, management stays operable, hard expiry works | M04 qualified evidence plus [M07 budget/controller-loss KVM PASS](PH1/P1M07/testing/acceptance-report.md); no local-build fallback |
| Build egress broker only | Packet capture/probes for direct IP/DNS/IPv6/metadata/host reachability | M05/M06 isolated-KVM acceptance PASS; M07 pinned-image pull/upload and offline RUN acceptance PASS |
| Rebinding/redirect/dependency isolation | Live malicious resolver and dependency fixtures | M05/M06 controlled DNS/redirect/Git enforcement PASS; M07 inherited remote-source and build isolation PASS; online package installation unsupported initially |
| Quarantined OCI ingest/scanning | Digest, archive expansion and scanner-isolation tests | [M07 isolated-KVM corpus/scanner/digest PASS](PH1/P1M07/testing/acceptance-report.md); admission remains separate from approval/deployment |
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
| SEC-06 Compose dangerous fields | [M08 isolated-KVM acceptance PASS](PH1/P1M08/testing/acceptance-report.md): strict guest YAML/Dockerfile corpus and fuzzing, forbidden-field denials, controller/agent normalized policy and actual one/two-service specs | M14 end-to-end release regression; actual engine constraints remain M09 |
| SEC-07 SSRF/egress | [M05 isolated-KVM N01–N13 PASS](PH1/P1M05/testing/acceptance-report.md): inspecting broker, IPv4/IPv6/direct/DNS/metadata filtering, rebinding, captures and zero forbidden canary arrivals | [M06 Git/client integration PASS](PH1/P1M06/testing/acceptance-report.md); M14 end-to-end acceptance remains |
| SEC-08 resource limits | M04 fixed-profile caps, M06 clone bounds and M07 real build/scan budgets, controller loss and resource exhaustion PASS | M09 runtime enforcement |
| SEC-09 volume/credential isolation | Mount shape/nonoverlap tests only | M10 ownership/quota/storage proof |
| SEC-10 secrets absent from logs | Decoder/auth errors sanitized; password hashes/token hashes verified in DB; auth audit contains no request secrets; raw session token only in secure cookie | M06 closed clone outcomes, bounded diagnostics and suppressed raw Git output and execution sentinels PASS; M07 closed build/scan outcomes, private scoped upload grants and bounded report metadata PASS; M08 repository/image metadata redaction and runtime/build-input separation PASS; remaining M09–M14 runtime paths |
| SEC-11 cleanup | M04 qualified evidence plus M05/M06/M07 real cancel/expiry, worker loss, crash boundaries, foreign ownership, race fencing and clean final inventories | M12 complete deployment reconciliation; M04 V14/V15 remain SKIP |
| SEC-12 timed revoke | Logout/disabled account/auth epoch/current roles enforced on next management request; DB outage denies | App gateway/WS/SSE timed lease closure in PH2/PH3 |
| SEC-13 proxy rollback | Not implemented | M11 |
| SEC-14 backup restore | DB integrity/reopen/WAL recovery plus M06 explicit verified-snapshot schema upgrade tests | M14 smoke; PH5 complete restore drill; automatic existing-data upgrades remain blocked |
| SEC-15 iframe origin isolation | No frontend yet | PH2 |
| SEC-16 replay/wrong worker | Worker/expiry/generation prechecks, not signature/ledger | M09 |
| SEC-17 concurrency | SQLite state/event/audit/outbox atomicity, idempotency, cross-handle CAS and process crash tests | M12 full deploy/cancel/route-generation race tests |
| SEC-18 MFA recovery | Not implemented | PH3, earlier if day-one requirement |

Operator decisions still required: production hardware/distribution (Q01), day-one MFA (Q02), rootless network and storage enforcement (Q05), production scan-policy rollout (Q07; M07 strict HIGH/CRITICAL baseline selected and tested), app backup policy (Q09). Do not mark PH1 complete until its actual release gates pass.
