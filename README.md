# Trusted Application PLatform

Security-first, self-hosted Git-to-container application portal. Administrators deploy Dockerfile or supported Compose applications; application access must pass through an authenticated, authorized gateway.

## Implementation status

**PH1 in progress: P1-M01 contracts, P1-M02 SQLite persistence and P1-M03 authentication API.** A TLS-only JSON API can now be run explicitly; there is no GUI or working deployment platform yet. No Docker integration, repository execution or Git cloning exists.

**P1-M04 Linux backend implemented; acceptance NOT PASSED.** Explicit QEMU/KVM/systemd backend includes pinned raw images, resource limits, no-NIC guests, independent deadlines and ownership-safe cleanup. Execution defaults to disabled; no simulator or unsafe fallback. The [mandatory real-host procedure](docs/testing/P1-M04-real-host.md) **must execute successfully before M04 PASS**. See [implementation status](docs/implementation/build-provisioner.md).

Testing after cloning onto a Debian-based Linux VM: [M04 check-off test plan](docs/testing/P1-M04-linux-checklist.md).

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
- Independent fixed-template build-lease contract, replay/idempotency ledger, expiry/cleanup state machine and mTLS service boundary (test-only VM simulator; no real backend).

Not implemented: full TOTP/user/ACL administration, existing-data migration upgrades/backup workflow, agent signature verification/replay storage, Compose parsing, Git/network isolation, image scanning, Docker execution, UI and application proxy. API authentication is **not application gateway authorization, SSRF protection or proof of runtime isolation**. No real deployment is enabled.

## Development

Install a supported Go 1.27 toolchain, then:

```text
go mod download
go test ./...
go vet ./...
go test -cover ./...
```

No Docker or infrastructure is needed for these tests. They use temporary SQLite files, fixed test-binary subprocesses, real Argon2id (64 MiB per operation) and temporary localhost TLS listeners, never repository commands. Dependencies are pinned; schemas/migrations are embedded and tests never fetch schema URLs at runtime.

API configuration and secure first-admin setup: [auth-core runbook](docs/implementation/auth-core.md). It requires explicit TLS files, a private metadata directory and an expiring out-of-band setup token; no insecure/default login is provided.

Architecture: [docs/README.md](docs/README.md). Implementation evidence and next steps: [docs/implementation/ph1-progress.md](docs/implementation/ph1-progress.md). Real execution requires approved Linux KVM infrastructure and external isolation tests first.
