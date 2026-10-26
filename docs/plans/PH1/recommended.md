# PH1 — Recommended secure core

## Objective / scope / architecture

Add operational reliability and safe private-source handling to the minimal VM-separated core. Includes Git credential mediation, durable service enrollment/rotation and tested metadata recovery; not broader Compose compatibility. Inherits every P1-M control and task; no alternative weak build path.

Dependencies: PH1 minimal complete; Q04/Q09 decisions. Proposed components/files: `internal/{secrets,gitfetch,audit,jobs}`, `cmd/artifact-ingest`, `infra/registry`, `tests/security/{credentials,recovery,identity}`, `tools/restore` and operator docs.

## Tasks

| ID | Deliverable | Depends | Size | Acceptance |
|---|---|---|---|---|
| P1-R01 | Versioned encrypted credential references and scoped broker API | P1-M14 | M | Credential never returned by generic reads; AEAD context tests |
| P1-R02 | HTTPS Git broker with exact-origin credential injection | R01 | L | Private clone succeeds; redirect/cross-origin/argv/log leakage tests fail safe |
| P1-R03 | Worker enrollment, short-lived certificates and rotation/revocation | P1-M14 | M | Wrong-role/expired cert denied; running control actions cannot renew revoked worker |
| P1-R04 | Artifact retention and digest/provenance inventory | P1-M14 | M | Referenced current/rollback blobs never garbage-collected; quarantine not deployable |
| P1-R05 | SQLite online backup, key export procedure and isolated restore drill | R01 | M | Integrity/ownership verified; restored routes initially denied |
| P1-R06 | Controller crash matrix, cleanup incident dashboard and queue backpressure | R03,R04,R05 | M | Crash at each state reconciles; capacity not reused before cleanup confirmation |

Parallel: R01/R03/R04; R02/R05 after R01. R06 integrates all. Each task includes adapter contract tests; private repo feature remains disabled until R02 evidence exists.

## Security / testing / acceptance

Run minimal suite plus private-origin rebinding/redirect credential tests, cert rotation with dropped network, DB online backup under log flood and expired build sweep during API outage. No Git tokens in clone URLs, context, guest filesystem, argv or persisted logs. Broker does not enable internal-network repositories. Scoped short-lived Git credentials preferred; no long-lived token ever delivered to builder.

Complexity: high, ~3–5 additional engineer-weeks. Risks: broker protocol complexity, encrypted key recovery failure, credential-dependent provider behavior. Definition of done: all P1-M gates plus R01–R06 pass; private Git either fully brokered or visibly unsupported; restore and revocation evidence archived, documentation matches actual capability.
