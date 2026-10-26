# Secure-by-default embedded container orchestrator

Status: architecture proposal with PH1 implementation started. [Implementation progress](implementation/ph1-progress.md) distinguishes implemented contracts from pending security gates. These plans do not authorize infrastructure changes by themselves.

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

- [Requirements and assumptions](architecture/requirements.md)
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

- [Project structure](implementation/project-structure.md)
- [API](implementation/api-design.md)
- [Frontend](implementation/frontend-design.md)
- [Agent and VM lifecycle](implementation/deployment-agent.md)
- [Reverse proxy](implementation/reverse-proxy.md)
- [Testing](implementation/testing-strategy.md)
- [Development environment](implementation/development-environment.md)
- [PH1 implementation progress](implementation/ph1-progress.md)
- [PH1 capability and evidence checklist](implementation/ph1-capability-checklist.md)
- [SQLite storage and migration contract](implementation/sqlite-storage.md)
- [Authentication API and operator setup](implementation/auth-core.md)
- [Build provisioner core and remaining Linux gates](implementation/build-provisioner.md)
- [M04 Debian-based Linux VM check-off test plan](testing/P1-M04-linux-checklist.md)
- [M04 mandatory real-host execution](testing/P1-M04-real-host.md)
- [M04 acceptance record — must execute before PASS](testing/P1-M04-acceptance-report.md)
- [Open questions](decisions/open-questions.md)
- [Exception policy](decisions/security-exceptions.md)

**P1-M01–P1-M03** have implemented foundations; **P1-M04 Linux code is implemented but acceptance is NOT PASSED**. Mandatory Linux tests must execute successfully before M04 PASS. Prove provisioning and the later egress controls before accepting real repositories.
