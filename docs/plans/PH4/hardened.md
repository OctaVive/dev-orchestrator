# PH4 — Hardened update supply chain

## Objective / scope / architecture

Extend PH4 minimal/recommended with controller-origin provenance, optional trusted signer policy and controlled promotion. Separate artifact approval from transport, while keeping one lightweight controller. Signed artifacts are evidence of origin, not proof of harmlessness.

Dependencies: P4-R05; signing key custody and external registry trust policy approved. Files: `internal/{registry,policy,jobs}`, `policy/supply-chain`, provenance schemas, `tests/security/provenance`, operator promotion/revocation docs.

| ID | Task/output | Depends | Size | Acceptance |
|---|---|---|---|---|
| P4-H01 | Controller-produced provenance schema and signing adapter | P4-R05 | M | SHA/digest/template/policy/scanner fields signed; builder cannot forge approval |
| P4-H02 | Agent verification of signature, digest and current revocation policy | H01 | M | Substitution/wrong audience/stale policy signatures denied |
| P4-H03 | Optional staged promotion and expiring second approval | H02 | M | Staging artifact exactly equals promoted digest; no rebuild substitution |
| P4-H04 | Supply-chain compromise and data-compatible rollback exercise | H03 | L | Compromised signer revoked, affected routes/jobs identified, unsafe rollback blocked |

Sequential H01→H02→H03→H04; independent negative provenance fixtures may be written after H01 contract. Long-term external key service integrates through defined adapter, never exposed to build guest.

Security/tests: verify all service digests for Compose, not only primary image; controller signs only after isolated ingest/scan and immutable approval; enforce key revocation at dispatch/runtime. Test replay of signed old policy, altered manifest graph, registry tag mutation and truncated provenance.

Complexity high, ~2–5 additional weeks. Risks: signing key compromise, operational approval friction, trusted-but-malicious upstream code. Acceptance/done: approved digest identity survives build-to-runtime chain, revocation drill succeeds and no critical provenance bypass remains. Do not claim reproducible builds unless independently implemented and measured.
