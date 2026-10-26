# Requirements, assumptions and boundaries

## Inspection and deployment assumptions

Inspection found an empty project directory except `plans/`; no implementation language, deployment conventions or test harness exists. Development host is Windows; production is a separate Linux machine with KVM, cgroup v2, usable rootless Docker resource enforcement, and a maintained kernel/hypervisor. Windows alone is not a production isolation substitute.

Initial sizing hypothesis, to benchmark rather than promise: 8 CPU threads, 24–32 GiB RAM, SSD storage; management 2–4 GiB, runtime 4–8 GiB plus application needs, one build 4–8 GiB, remaining capacity reserved for the host. One concurrent build initially. No KVM or insufficient capacity means **unsupported**, not fallback to local untrusted builds.

## Product scope

Admins configure repository URL, branch, display name, unique slug, Dockerfile/Compose mode, optional domain, category, runtime variables, secrets and per-app managed storage. Backend resolves immutable commits, builds, evaluates policy, deploys, verifies health, then publishes an authenticated route. Users see only assigned applications and cannot mutate infrastructure. All applications remain private; a custom domain does not mean anonymous publication.

PH1 is an admin-only product with secure password login. Full user enrollment, TOTP and ACL UI arrive in PH3. Non-admin identities, if provisioned by fixtures or later migrations, have no deployment permission and no app access without grants. If password+TOTP is mandatory for every production administrator from day one, PH3 MFA tasks become PH1 release dependencies; do not claim password-only PH1 meets that stronger requirement.

## Non-negotiable release gates

| Requirement | Enforcing boundary / earliest gate |
|---|---|
| Untrusted Git, build scripts, Dockerfiles, Compose | Ephemeral VM plus strict policy / PH1 |
| No UI/API Docker socket or privileged DinD | VM separation, mount and permission inventory / PH1 |
| Clone/build cannot reach host, metadata or management | Hypervisor firewall and controlled egress / PH1 |
| Default-deny workload ingress and lateral access | Runtime networking plus gateway / PH1 |
| Backend permissions on all HTTP and WS access | API and gateway auth service / PH1 |
| Resource, filesystem, volume and runtime restrictions | Agent validates typed runtime specification / PH1 |
| Credentials isolated, mTLS agents, audit | Credential broker, service identities, audit store / PH1 |
| Full MFA and per-user ACL administration | PH3, or move forward when required by operator |
| Stronger runtime isolation | Dedicated physical worker / optional per-app VM progression |

## Security assurance limits

VMs reduce kernel sharing with management but do not eliminate hypervisor escapes, CPU side channels or single-host denial of service. Containers inside one runtime VM share a guest kernel. Rootless reduces privilege, not complete isolation. Public dependency access permits outbound exfiltration of any material intentionally exposed to a build. Scanners cannot establish that code is benign. Log redaction cannot guarantee removal of arbitrary maliciously encoded secrets. No build receives management or long-lived credentials; sensitive private-repository source is itself data that builds may exfiltrate unless network access is removed.

## Unsupported initially

Privileged workloads; Docker socket consumers; arbitrary bind mounts; host namespaces/devices; unrestricted build networking; SSH Git; recursive submodules; custom Git helpers; Compose extensions outside the allowlist; public unauthenticated apps; applications requiring shared portal origin; application access without TLS; GPU passthrough; desktop Windows as the production worker; arbitrary remote Docker endpoints. Exceptions cannot override these structural boundaries.

Outstanding operator decisions and release blockers: [open questions](../decisions/open-questions.md).
