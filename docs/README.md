# Secure-by-default embedded container orchestrator

Project delivery: [requirements -> milestones -> implementation and evidence](project/README.md).

Status: architecture proposal with PH1 implementation started. [Implementation progress](project/progress.md) distinguishes implemented contracts from pending security gates. These plans do not authorize infrastructure changes by themselves.

## Location and evidence

The initial planning tree was staged under `C:\Users\mitchel\.opencode\plan` while Plan mode was active and is now present in this repository. Initial inspection found only an empty `plans/` directory and no application stack. At implementation start, this documentation tree was already present and was preserved. Paths in implementation plans describe future components; consult implementation progress for files actually created.

## Decisions at a glance

- PH1: management VM, separate runtime VM with a narrowly scoped agent, and disposable KVM build VMs. All can initially share one Linux hypervisor. No privileged DinD.
- Build VM performs cloning and builds with rootless BuildKit. Runtime VM uses rootless Docker where tested requirements are enforceable; otherwise deployment is blocked, not silently weakened.
- Go services, React/TypeScript portal, SQLite metadata, NGINX gateway, private OCI registry, KVM provisioning (implemented Linux backend uses direct QEMU/systemd instead of proposed libvirt). A small product, not a general-purpose scheduler.
- Apps use distinct origins, preferably a separate registrable domain from the portal, displayed in sandboxed iframes. Unsupported apps open in a protected new tab or are rejected; headers are not stripped to force embedding.
- Security baseline applies to all plan variants. PH3 adds complete MFA/ACL workflows; PH1 is admin-only with password login, default-deny gateway authorization and schemas prepared for MFA/ACL.

## Reading map / generated documentation

### Architecture

- [Requirements and assumptions](project/requirements.md)
- [Five architecture alternatives](architecture/architecture-options.md)
- [Weighted comparison](architecture/architecture-comparison.md)
- [Recommended architecture and boundaries](architecture/recommended-architecture.md)
- [Component contracts, storage and secrets](architecture/component-design.md)
- [Embedded applications and browser flows](architecture/embedded-applications.md)
- [Authentication and ACL](architecture/authentication-authorization.md)
- [Networking and proxy comparison](architecture/networking.md)
- [Dockerfile, Compose and runtime policies](architecture/docker-security.md)
- [Clone/build pipeline and state machine](architecture/git-deployment-pipeline.md)
- [SQLite schema and ERD](architecture/data-model.md)
- [Threat model and residual risk](architecture/threat-model.md)
- [Architecture decisions](architecture/architecture-decisions.md)

### Plans

- [Master roadmap and execution rules](plans/master-roadmap.md)
- PH1: [minimal](plans/PH1/minimal.md), [recommended](plans/PH1/recommended.md), [hardened](plans/PH1/hardened.md)
- PH2: [minimal](plans/PH2/minimal.md), [recommended](plans/PH2/recommended.md), [hardened](plans/PH2/hardened.md)
- PH3: [minimal](plans/PH3/minimal.md), [recommended](plans/PH3/recommended.md), [hardened](plans/PH3/hardened.md)
- PH4: [minimal](plans/PH4/minimal.md), [recommended](plans/PH4/recommended.md), [hardened](plans/PH4/hardened.md)
- PH5: [minimal](plans/PH5/minimal.md), [recommended](plans/PH5/recommended.md), [hardened](plans/PH5/hardened.md)

### Implementation specifications

- [Project structure](project/specifications/project-structure.md)
- [API](project/specifications/api-design.md)
- [Frontend](project/specifications/frontend-design.md)
- [Agent and VM lifecycle](project/specifications/deployment-agent.md)
- [Reverse proxy](project/specifications/reverse-proxy.md)
- [Testing](project/specifications/testing-strategy.md)
- [Development environment](project/specifications/development-environment.md)
- [PH1 implementation progress](project/progress.md)
- [PH1 capability and evidence checklist](project/requirement-evidence.md)
- [SQLite storage and migration contract](project/PH1/P1M02/sqlite-storage.md)
- [Authentication API and operator setup](project/PH1/P1M03/auth-core.md)
- [Build provisioner core and remaining Linux gates](project/PH1/P1M04/build-provisioner.md)
- [M04 Debian-based Linux VM check-off test plan](project/PH1/P1M04/testing/linux-checklist.md)
- [M04 mandatory real-host execution](project/PH1/P1M04/testing/real-host.md)
- [M04 acceptance record — must execute before PASS](project/PH1/P1M04/testing/acceptance-report.md)
- [Open questions](decisions/open-questions.md)
- [Exception policy](decisions/security-exceptions.md)

**P1-M01–P1-M03: Implemented/tested. P1-M04: Implemented/tested\*.**

\* V14 and V15 marked as SKIP; V01–V13 and V16 passed. The qualified acceptance decision is recorded separately in the [acceptance record](project/PH1/P1M04/testing/acceptance-report.md). M05 egress isolation and the later clone/build/runtime milestones remain to be implemented.
