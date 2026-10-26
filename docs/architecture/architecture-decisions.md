# Architecture decision record index

These are proposed decisions pending operator approval; changes require ADR, threat-model update and executable acceptance tests.

| ADR | Decision | Rationale / consequence |
|---|---|---|
| 001 | Separate management, ephemeral builder and runtime VMs from PH1 | More RAM/operations; necessary for arbitrary builds |
| 002 | No privileged DinD or management Docker socket | Removes easy host-root path; agent/provisioner contracts required |
| 003 | Rootless Docker runtime, rootless BuildKit builder | Reduced privilege; require cgroup/network/storage compatibility proof |
| 004 | One controller, SQLite, single build slot | Lightweight and maintainable; no HA claim |
| 005 | Go backend/agents/relay, React TypeScript portal | Small deployable services, typed protocols; versions pinned at implementation |
| 006 | NGINX HTTP auth plus revocation-aware relay | Mature proxy without socket discovery; custom stream ownership needs tests |
| 007 | Separate app origins, preferably separate registrable domain | Protect portal DOM/storage/cookies; embedding compatibility limits |
| 008 | Strict Compose subset compiled to typed spec | Reject unsupported rather than partially execute dangerous config |
| 009 | Immutable digest/SHA/policy approval tuple | Reproducible rollout identity; no claim of deterministic builds |
| 010 | Admin-only PH1, full TOTP/ACL in PH3 | Meets staged scope; stronger day-one MFA policy advances PH3 tasks |
| 011 | No arbitrary private-network Git/dependency access | SSRF boundary; private on-prem repos unsupported until isolated mirror design |
| 012 | Controlled broker-only build egress; no build secrets | Compatibility cost is intentional; source exfiltration remains possible |
| 013 | Runtime agent never interprets raw Compose or shell | Narrow authority; duplicated independent validation intentional |
| 014 | Application data rollback is explicit and separate | Avoid data corruption; requires app-specific backup/migration contracts |

Rejected shortcuts: socket-proxy exposing generic Docker API; scanner as malware proof; privileged DinD as sandbox; wildcard origin credentials; stripping frame protection; silent rootful fallback; public host ports protected only by obscure URLs; postponing baseline security to PH5.
