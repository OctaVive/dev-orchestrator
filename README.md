# Trusted Application Platform

Project delivery: [requirements -> milestones -> implementation and evidence](docs/project/README.md).

All phases and completion percentages: [master project status](PROJECT-STATUS.md).

Security-first, self-hosted Git-to-container application portal. Administrators deploy Dockerfile or supported Compose applications; application access must pass through an authenticated, authorized gateway.

## Implementation status

**PH1 in progress: P1-M01–P1-M07 are implemented, with M04 validation qualifications.** A TLS-only JSON API and explicitly configured isolated Git-to-image build/admission pipeline are present. GUI, runtime deployment and the complete application controller remain planned.

**P1-M04: Implemented/tested\*.** \* V14 and V15 marked as SKIP. V01–V13 and V16 passed the real-host checks; the skipped cases are not passes. Explicit QEMU/KVM/systemd backend includes pinned raw images, resource limits, no-NIC guests, independent deadlines and ownership-safe cleanup. Execution defaults to disabled; no simulator or unsafe fallback. See the [acceptance record](docs/project/PH1/P1M04/testing/acceptance-report.md) and [real-host procedure](docs/project/PH1/P1M04/testing/real-host.md) for results and the qualified status. See [implementation status](docs/project/PH1/P1M04/build-provisioner.md).

**P1-M05: Implemented/tested; isolated-KVM acceptance PASS.** External inspecting HTTPS broker, pinned policy/CA, isolated namespace/TAP, QEMU descriptors, cancellation, independent expiry and recovery are present. Controlled N01–N13 KVM tests passed with packet captures and destination canaries. No-NIC mode stays the default. See the [LLD](LLD-documents/PH1/p1-m05.md) and [validation evidence](docs/project/PH1/P1M05/implementation-evidence.md).

**P1-M06/M07: Implemented/tested; isolated-KVM acceptance PASS.** Restricted Git clone, rootless BuildKit, separate opaque quarantine service, independent OCI validation/scanning and immutable artifact admission are present. M07 passed all 146 required ledger cases, including budget failures and controller loss; admission does not approve or deploy an application. See [M07 evidence](docs/project/PH1/P1M07/testing/acceptance-report.md).

Testing after cloning onto a Debian-based Linux VM: [M04 check-off test plan](docs/project/PH1/P1M04/testing/linux-checklist.md).

Implemented:

- Versioned deployment-request and runtime-agent JSON Schema contracts.
- Bounded JSON decoding that rejects unknown/duplicate fields, invalid UTF-8, excessive nesting and trailing JSON.
- Typed domain models, legal state transitions and default-deny role/application authorization helpers.
- Structural request validation and expiring, worker-bound agent envelope validation.
- Mutation tests and a security fixture inventory/capability checklist.
- Local SQLite schema bootstrap, checksummed migrations, startup locking and integrity/FK checks.
- Atomic deployment-state/event/audit/outbox transactions, idempotent submission and version/generation checks.
- Real database concurrency, failure rollback and subprocess crash-recovery tests.
- Separate operator-only first-admin setup, Argon2id passwords, hashed server-side sessions, CSRF, rate limits and backend role checks.
- TLS-only API entrypoint (`cmd/api`) and real local HTTPS authentication tests.
- Independent fixed-template build-lease contract, replay/idempotency ledger, expiry/cleanup state machine, mTLS boundary and tested real QEMU/KVM/systemd backend.

Not implemented: full TOTP/user/ACL administration, existing-data migration upgrades/backup workflow, agent signature verification/replay storage, Compose parsing, Git cloning, image scanning, Docker execution, UI and application proxy. API authentication is **not application gateway authorization, SSRF protection or proof of runtime isolation**. No real deployment is enabled.

## Development

Install a supported Go 1.27 toolchain, then:

```text
go mod download
go test ./...
go vet ./...
go test -cover ./...
```

No Docker or infrastructure is needed for these tests. They use temporary SQLite files, fixed test-binary subprocesses, real Argon2id (64 MiB per operation) and temporary localhost TLS listeners, never repository commands. Dependencies are pinned; schemas/migrations are embedded and tests never fetch schema URLs at runtime.

API configuration and secure first-admin setup: [auth-core runbook](docs/project/PH1/P1M03/auth-core.md). It requires explicit TLS files, a private metadata directory and an expiring out-of-band setup token; no insecure/default login is provided.

Architecture: [docs/README.md](docs/README.md). Implementation evidence and next steps: [docs/project/progress.md](docs/project/progress.md). Real execution requires approved Linux KVM infrastructure and external isolation tests first.
