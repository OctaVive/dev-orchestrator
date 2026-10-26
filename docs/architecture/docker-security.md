# Dockerfile, Compose and runtime policy

## Policy pipeline

Parse repository configuration in the disposable build VM under resource limits, then independently validate bounded normalized data in controller and agent. Do not execute `docker compose up` on repository content. Do not treat YAML parsing or a Dockerfile linter as proof of safety. Build commands are arbitrary code contained by VM/egress policy.

Policy version and canonical spec hash accompany every deployment and audit event. Agents reject unknown schema/fields, conflicting normalized values and obsolete minimum policy. Policy tests run against actual engine inspection, not only request JSON.

## Compose supported subset, PH1

Compose v2 syntax: maximum 5 services, depth/size/alias limits. Explicit service allowlist:

- `image` only approved immutable digests after scanning, or `build` with context strictly inside exported repo and approved Dockerfile path.
- `command` and `entrypoint` as bounded argv arrays (application execution only, no management shell interpolation).
- `environment` explicit approved key/value data, separate secret references; no expansion from controller/host environment or implicit `.env`.
- `expose` validated container port metadata; `ports` always denied.
- Managed named `volumes` referencing app-owned IDs and allowlisted in-container mount targets; no external volumes, host bind mounts, mount propagation or arbitrary driver options.
- One platform-managed app-private network; no user-controlled network drivers, IPAM, external networks or aliases crossing apps.
- Bounded healthcheck, dependency startup order, restart policy and resource requests compiled into platform limits. Healthcheck exec is workload code and executes only inside its container; HTTP checks use fixed private backend, no arbitrary health-check URLs.
- Limited `depends_on` without privileged lifecycle hooks; dependency conditions bounded by deployment deadline.

Every other field is rejected unless explicitly added to a versioned schema. This includes `privileged`, `devices`, `device_cgroup_rules`, `cap_add`, unsafe `security_opt`, `pid`, `ipc`, `uts`, `userns_mode`, `network_mode`, `volumes_from`, `container_name`, `runtime`, host PID/IPC/network, `extends`, `include`, profiles, custom extensions, lifecycle hooks, configs/secrets with external/file host sources, arbitrary logging drivers and custom sysctls. Reject YAML duplicate keys, unsafe tags, merge ambiguity and excessive aliases. No silent partial interpretation. Variable expansion, if later supported, uses a small explicit input dictionary and is resolved before schema checks; never host environment.

## Dockerfile and context checks

- Constrain Dockerfile/context to repo; reject symlink escape, absolute paths and tar traversal. Context allowlist plus excludes `.git`, platform files and secret material.
- Reject remote `ADD`, external build contexts, host networking, insecure entitlements, SSH forwarding, device/CDI access, Docker socket access and user-selected BuildKit frontend URLs. Pin approved frontend and base image digests through the controlled registry resolver. `RUN` network is brokered or disabled, never host.
- Arbitrary `RUN` still executes untrusted instructions. Static checks cannot reliably identify malicious code or prevent encoded network behavior; VM firewall is the enforcement boundary.
- Inspect final image config for user, exposed ports, env leakage, entrypoint, architecture and declared volumes. Reject root/default user unless it can run under enforced tested non-root UID. Reject unmanaged image volumes rather than allowing implicit host volume creation.

## Runtime hard profile

| Control | Default enforcement |
|---|---|
| User | Numeric non-root UID/GID, no supplementary host groups |
| Capabilities | Drop ALL; no arbitrary additions |
| Privilege | no-new-privileges, no privileged flag |
| Namespaces | Private PID/IPC/network/mount/user; no sharing with other apps/host |
| Filesystem | Read-only root, bounded tmpfs `/tmp` and necessary write locations |
| Mounts | App-owned managed volumes only, mount target validation, no socket/device exposure |
| Syscalls/MAC | Maintained seccomp profile; AppArmor/SELinux when supported; never unconfined |
| Resources | CPU, memory, no uncontrolled swap, PID and disk quotas; bounded logs |
| Network | No host ports, only relay ingress, default-deny egress and lateral traffic |
| Lifecycle | Fixed restart budget, health deadline, no endless crash-loop |

Initial per-service defaults to benchmark: 1 CPU, 512 MiB memory, 128 PIDs, 64 MiB tmpfs, 20 MiB rotated logs; app totals bounded by operator capacity. Build defaults live in pipeline document. Missing cgroup/MAC/network enforcement must be reported; required controls cause refusal, not warning-only deployment.

## Compatibility and exceptions

Dry-run returns machine-readable rejection paths and remediation: non-root image, configurable data directory, external URL, no host mounts. Allowed exception examples: increased memory, approved public dependency domain, extra tmpfs mount or read-write root in a **separately reviewed isolated profile**. Exceptions have owner, rationale, scope, expiry and tests; agent independently checks signed policy. Structural prohibitions (sockets, host namespaces, privileged mode, management connectivity, long-lived build secrets) are not waivable in this architecture. An app requiring them is unsupported or must move to a separately designed dedicated VM product.
