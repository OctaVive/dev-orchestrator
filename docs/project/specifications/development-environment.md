# Development and operator environment

Current Windows workspace is for source/doc editing and unit/browser tests. Real security acceptance requires dedicated Linux KVM lab. WSL or ordinary containers are not evidence of VM isolation or correct production rootless networking. Do not install dependencies, create VMs, deploy containers or change networking while executing this planning task.

Proposed lab: supported Linux LTS, KVM/libvirt with minimal host services, cgroup v2, quota-capable encrypted storage, separate management/runtime/build virtual networks, test egress proxy/resolver, private registry and development CA. Confirm CPU virtualization and available RAM/disk first. Provision templates from reproducible definitions; administrator reviews host network changes explicitly.

Use reserved test domains/hosts entries mapped to gateway and locally trusted TLS. Prefer separate registrable-domain test namespaces to exercise cross-site cookie limitations. No real cloud credentials, personal source repositories or production app volumes in tests. Fixture Git server/dependency mirrors provide rebinding and malicious dependency scenarios without contacting victims.

Develop unit/contract code against fake engine/provisioner first, clearly labeled non-secure simulation. A simulator cannot publish a production route or claim isolation capability. Privileged integration suite is opt-in and only targets a named lab instance with fresh scoped credentials. Cleanup inventories resources by immutable test-run ownership, never global prune.

CI stages: formatting/unit/fuzz budgets → contract/migration → isolated VM integration → browser → security gate/evidence archive. Pin dependencies and generate SBOM; keep production signing/enrollment keys off pull-request CI. No untrusted PR code on a runner holding infrastructure authority.

Operational runbooks to create: first admin/TLS bootstrap, template patching, agent enrollment/rotation/revocation, bad build kill, disk exhaustion recovery, private route fail-closed check, metadata/app backup and restore, secret rotation after runtime compromise. Target recovery objectives need operator approval; proposed initial metadata RPO 24 h/RTO 4 h are unvalidated hypotheses, not commitments.
