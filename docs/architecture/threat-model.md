# Threat model and residual risks

Assets: management credentials, sessions/TOTP keys, deployment authority, private source, app secrets/data, registry integrity, availability, audit evidence and browser origin integrity. Adversaries: unauthenticated internet client; regular user; malicious repository maintainer/dependency; compromised app; compromised worker; malicious administrator; local host operator. An administrator can intentionally deploy harmful code; hard platform boundaries still apply. Host-root/operator compromise is outside protection guarantees and must be disclosed.

| Attack | Enforced mitigation | Test / residual |
|---|---|---|
| Git URL to metadata, local file/helper command | HTTPS-only parser, no helper protocols, external egress deny | SSRF corpus across IPv4/IPv6; parser bugs remain |
| DNS rebinding/redirect to private service | Connection-time DNS/IP pinning and per-hop check, host firewall | Rebinding resolver fixture, mixed answers, redirect chains |
| Dependency script uses raw sockets/DoH | Guest no direct network, broker-only path | Malicious RUN fixtures; allowed public hosts can still receive data |
| Dockerfile/BuildKit escape | Disposable guest, rootless build, no sensitive mounts | Simulated guest compromise; hypervisor escape remains |
| Archive/parser/scanner exploit | Bounded isolated ingest/scanner, immutable export | Tar bombs/path traversal; parser vulnerabilities remain |
| Compose host mount/socket/privileged | Strict subset, independent agent policy | Mutated YAML, unknown keys, direct-agent calls |
| Container escape | Rootless runtime in separate VM, patching, seccomp/MAC | Kernel exposure remains; all apps in worker at risk |
| Cross-app network/data access | Isolated networks, volume ownership/quota enforcement | A-to-B probes and wrong-volume attach tests |
| Malicious iframe/XSS | Distinct app origin/domain, CSP/sandbox, no shared tokens | Browser attack fixture; user phishing remains possible |
| ACL bypass/direct URL/forged identity | Gateway checks each request, strips headers, exact routes | Role matrix and IDOR; app-internal permissions separate |
| Stale WS after revocation | Relay authorization lease and bounded closure | Timed revoke tests under partitions; ≤10 s exposure |
| Job replay/race/route misbinding | Generation, app IDs, idempotency and expiring command | Cancel-at-switch, replay after restart, wrong worker |
| Secret output/exfiltration | No long-lived build secrets, controlled broker, runtime separation | Redaction cannot defeat arbitrary encoding; app can leak own secrets |
| Resource exhaustion | VM/host quotas, reserved capacity, bounded logs/queues | Disk/CPU/PID/slowloris tests; shared-host DoS still possible |
| Auth DB theft | Argon2id, hashed sessions, encrypted TOTP with external key | Running management host compromise defeats this separation |
| Malicious admin changes policy | Agent hard deny, scoped exception record, external audit | Admin can grant app access; no protection against authorized disclosure |
| Backup theft or rollback | Encrypt, separate keys, tested restore and audit | Host holding live key remains sensitive |
| Supply-chain/base image replacement | Pin digest, approved resolver, SBOM and scanning | Signatures/scans do not prove benign behavior |

## Explicit non-guarantees

- Docker containers do not completely isolate malicious workloads. Runtime compromise may expose sibling app data in the same VM.
- Single hardware host cannot guarantee management availability or independent failure domains. VM separation is not physical separation.
- No automatic safe rollback of incompatible data migrations; backups are necessary but may lose writes.
- Embedded arbitrary apps are not universally compatible; third-party cookie restrictions, XFO/CSP and app login policies may require protected new-tab fallback.
- No guarantee that malicious code has no vulnerabilities or that all secrets are absent from arbitrary output. Prevent exposure of sensitive inputs first.
- Revocation cannot erase data already delivered; connection closure has a documented bounded delay.
- DNS/public registries/package repositories can be compromised; allowlisting is network control, not content trust.

## Release blockers

Unproven cgroup/egress/volume quota enforcement; accepting real builds without disposable VMs; public app ports; fail-open gateway; skipped scanner policy without explicit unsupported status; undefined agent identity; inability to kill expired VM; logged credential fixture. PH5 strengthens controls that already exist; it does not postpone these blockers.

## Review cadence

Review at every new protocol, Compose key, iframe permission, secret type, worker capability and network exception. Record abuse case and regression test with ADR. Track residual risks with named operator owner; high-risk acceptance cannot silently override hard prohibitions.
