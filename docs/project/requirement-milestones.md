# Requirement-to-milestone map

The [requirements](requirements.md) define scope and release boundaries. The [phase plans](../plans/master-roadmap.md) define task scope and acceptance gates. Links below identify delivery ownership; they do not assert completion. See [progress](progress.md) and the [evidence checklist](requirement-evidence.md) for current results and limitations.

## Product and boundary requirements

| Requirement | Delivery milestones | Acceptance evidence |
|---|---|---|
| Domain/protocol contracts and security fixture inventory | [P1-M01](PH1/P1M01/README.md) | Schema rejection tests and capability checklist |
| Durable SQLite metadata, state and audit | [P1-M02](PH1/P1M02/README.md), [P1-M12](PH1/P1M12/README.md) | Integrity, crash-atomicity and controller transition tests |
| Admin login and backend permissions | [P1-M03](PH1/P1M03/README.md), [P1-M11](PH1/P1M11/README.md), [P1-M13](PH1/P1M13/README.md) | Auth API, gateway denial and UI/API role checks |
| Untrusted Git/build isolation and immutable artifacts | [P1-M04](PH1/P1M04/README.md) -> [P1-M05](PH1/P1M05/README.md) -> [P1-M06](PH1/P1M06/README.md) -> [P1-M07](PH1/P1M07/README.md) | Real guest lifecycle, egress, malicious Git and ingest/scanning tests |
| Restricted Dockerfile/Compose runtime with no management socket or public app ports | [P1-M08](PH1/P1M08/README.md), [P1-M09](PH1/P1M09/README.md), [P1-M11](PH1/P1M11/README.md) | Policy corpus, engine inspection, resource and network probes |
| App-owned bounded storage and secret references | [P1-M10](PH1/P1M10/README.md) | Wrong-app attachment, quota and secret-isolation checks |
| Deploy, health-check, publish, cancel and reconcile | [P1-M12](PH1/P1M12/README.md), [P1-M13](PH1/P1M13/README.md) | Auditable end-to-end workflows and cleanup evidence |
| Secure-core release and operator setup/backup smoke | [P1-M14](PH1/P1M14/README.md) | Full PH1 release harness; no unresolved blockers |
| Embedded app origins, browser behavior and stream revocation | [PH2 plan](../plans/PH2/minimal.md) | Browser isolation and WS/SSE tests |
| Full MFA, user enrollment and ACL administration | [PH3 plan](../plans/PH3/minimal.md) | MFA/recovery, permission and timed-revoke tests; move forward if required day one |
| Git updates and safe rollback | [PH4 plan](../plans/PH4/minimal.md) | Update races, health and data-safe rollback tests |
| Full recovery and adversarial assurance | [PH5 plan](../plans/PH5/minimal.md) | Restore drills and security review |

## Security requirement traceability

SEC IDs are the existing release-test identifiers from the [evidence checklist](requirement-evidence.md#requirement-to-test-map); this table assigns milestones without redefining those tests. Recommended/hardened phase tasks still apply where required by the selected track.

| Requirement | PH1 milestones | Later-phase dependency |
|---|---|---|
| [SEC-01](requirement-evidence.md#requirement-to-test-map) | [P1-M03](PH1/P1M03/README.md), [P1-M14](PH1/P1M14/README.md) | -> |
| [SEC-02](requirement-evidence.md#requirement-to-test-map) | [P1-M03](PH1/P1M03/README.md), [P1-M12](PH1/P1M12/README.md), [P1-M13](PH1/P1M13/README.md), [P1-M14](PH1/P1M14/README.md) | -> |
| [SEC-03](requirement-evidence.md#requirement-to-test-map) | [P1-M09](PH1/P1M09/README.md), [P1-M11](PH1/P1M11/README.md), [P1-M14](PH1/P1M14/README.md) | -> |
| [SEC-04](requirement-evidence.md#requirement-to-test-map) | [P1-M11](PH1/P1M11/README.md), [P1-M14](PH1/P1M14/README.md) | -> |
| [SEC-05](requirement-evidence.md#requirement-to-test-map) | [P1-M09](PH1/P1M09/README.md), [P1-M14](PH1/P1M14/README.md) | -> |
| [SEC-06](requirement-evidence.md#requirement-to-test-map) | [P1-M08](PH1/P1M08/README.md), [P1-M14](PH1/P1M14/README.md) | -> |
| [SEC-07](requirement-evidence.md#requirement-to-test-map) | [P1-M05](PH1/P1M05/README.md), [P1-M06](PH1/P1M06/README.md), [P1-M14](PH1/P1M14/README.md) | -> |
| [SEC-08](requirement-evidence.md#requirement-to-test-map) | [P1-M04](PH1/P1M04/README.md), [P1-M07](PH1/P1M07/README.md), [P1-M09](PH1/P1M09/README.md), [P1-M14](PH1/P1M14/README.md) | -> |
| [SEC-09](requirement-evidence.md#requirement-to-test-map) | [P1-M10](PH1/P1M10/README.md), [P1-M14](PH1/P1M14/README.md) | -> |
| [SEC-10](requirement-evidence.md#requirement-to-test-map) | [P1-M03](PH1/P1M03/README.md), [P1-M04](PH1/P1M04/README.md), [P1-M07](PH1/P1M07/README.md), [P1-M10](PH1/P1M10/README.md), [P1-M14](PH1/P1M14/README.md) | -> |
| [SEC-11](requirement-evidence.md#requirement-to-test-map) | [P1-M04](PH1/P1M04/README.md), [P1-M12](PH1/P1M12/README.md), [P1-M14](PH1/P1M14/README.md) | -> |
| [SEC-12](requirement-evidence.md#requirement-to-test-map) | [P1-M03](PH1/P1M03/README.md), [P1-M11](PH1/P1M11/README.md) | [PH2](../plans/PH2/minimal.md) / [PH3](../plans/PH3/minimal.md): timed stream revocation |
| [SEC-13](requirement-evidence.md#requirement-to-test-map) | [P1-M11](PH1/P1M11/README.md), [P1-M14](PH1/P1M14/README.md) | -> |
| [SEC-14](requirement-evidence.md#requirement-to-test-map) | [P1-M14](PH1/P1M14/README.md) | [PH5](../plans/PH5/minimal.md): complete restore drill |
| [SEC-15](requirement-evidence.md#requirement-to-test-map) | No PH1 implementation claim | [PH2](../plans/PH2/minimal.md): browser origin isolation |
| [SEC-16](requirement-evidence.md#requirement-to-test-map) | [P1-M09](PH1/P1M09/README.md), [P1-M14](PH1/P1M14/README.md) | -> |
| [SEC-17](requirement-evidence.md#requirement-to-test-map) | [P1-M02](PH1/P1M02/README.md), [P1-M12](PH1/P1M12/README.md), [P1-M14](PH1/P1M14/README.md) | -> |
| [SEC-18](requirement-evidence.md#requirement-to-test-map) | No PH1 implementation claim | [PH3](../plans/PH3/minimal.md): MFA and recovery; earlier if required day one |
