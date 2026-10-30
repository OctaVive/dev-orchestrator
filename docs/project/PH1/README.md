# PH1 milestones

Folder names use `P1M01` through `P1M14`; canonical task IDs remain `P1-M01` through `P1-M14`. The [phase plan](../../plans/PH1/minimal.md) defines scope, dependencies and acceptance gates. [Requirement mapping](../requirement-milestones.md) connects requirements to delivery and evidence.

| Milestone | Deliverable | Status |
|---|---|---|
| [P1-M01](P1M01/README.md) | Scaffold domain/protocol contracts and fixture inventory; document capability checklist | Implemented/tested |
| [P1-M02](P1M02/README.md) | Initial SQLite migrations, version lock and state/outbox transaction adapter | Implemented/tested |
| [P1-M03](P1M03/README.md) | Bootstrap admin, Argon2id, sessions, CSRF and role middleware | Implemented/tested |
| [P1-M04](P1M04/README.md) | Fixed VM template/provisioner contract and hard-expiry lifecycle | Implemented/tested*; V14 and V15 SKIP |
| [P1-M05](P1M05/README.md) | External build egress broker and firewall template | Implemented/tested; controlled isolated-KVM N01–N13 PASS |
| [P1-M06](P1M06/README.md) | Clone runner with HTTPS/ref/context limits and malicious Git fixtures | Implemented/tested; isolated-KVM M06 acceptance PASS |
| [P1-M07](P1M07/README.md) | Rootless BuildKit export and isolated ingest/scanner adapter | Implemented/tested; isolated-KVM M07 acceptance PASS |
| [P1-M08](P1M08/README.md) | Strict Compose/Dockerfile normalization and agent policy contract | Implemented/tested; isolated-KVM M08 acceptance PASS |
| [P1-M09](P1M09/README.md) | Runtime capability probe and typed agent create/inspect/stop | In progress; NOT PASSED |
| [P1-M10](P1M10/README.md) | Managed volume ownership/quota and secret-reference adapter | Planned |
| [P1-M11](P1M11/README.md) | HTTP auth gateway, private relay path and atomic exact-host route activation | Planned |
| [P1-M12](P1M12/README.md) | Job controller main state machine, cancellation and orphan reconciliation | Planned |
| [P1-M13](P1M13/README.md) | Login/sidebar/admin deploy wizard, timeline and text-only bounded logs | Planned |
| [P1-M14](P1M14/README.md) | Secure-core acceptance harness and operator setup/backup smoke runbook | Planned |
