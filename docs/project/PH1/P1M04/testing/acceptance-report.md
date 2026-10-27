# P1-M04 acceptance record — PASS*

**Decision: PASS\*.**

\* V14 and V15 marked as SKIP.

Qualified status recorded at the operator's explicit request on 2026-10-27.
The skipped cases retain SKIP results; neither is counted as a passed check.

| Required evidence | Recorded result |
|---|---|
| Software tests, vet, race detection and builds | PASS |
| Repeated concurrency cases, fuzz smoke and permission probes | PASS |
| Four automated real-host cases | PASS; exit 0, no SKIP |
| V01–V13 | PASS; rerun after the filesystem-identity fix |
| V14 — Time/ledger faults | SKIP; operator-requested deferral |
| V15 — Network/patch posture | SKIP; operator-requested deferral; security findings retained |
| V16 — Final inventory | PASS; historical disk recovered with its original audit record preserved; final inventory clean |
| Aggregate M04 status | PASS*; qualification above remains part of the status |

Evidence is retained privately outside this repository:

- Current fix, binary hashes, verification and final inventory: `/home/mitchel/v16-fix.cTsJqG/report.md`.
- Original matrix execution and skip decisions: `/home/mitchel/m04-acceptance.U8l1UP/report.md`.
- Pre-recovery investigation: `/home/mitchel/v16-investigation.1DzvUv/report.md`.

No ownership proofs, private test keys or raw evidence are copied into this record.
This status update does not enable services, M05 networking or untrusted builds.
