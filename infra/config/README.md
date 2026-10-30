# PH1M08 configuration policy lab

Raw YAML/Dockerfile parser tests and fuzzing run only inside disposable KVM guests.
Management software tests cover normalized contracts/policy, durable fences and
agent validation. Do not set M08_GUEST_TESTS on management to bypass the guest gate.

Pin Go parser dependencies through go.mod/go.sum: BuildKit v0.34.1 (matching the
existing frontend binary) and go.yaml.in/yaml/v3 v3.0.5. Upstream contracts:
[BuildKit parser](https://github.com/moby/buildkit/tree/v0.34.1/frontend/dockerfile/parser),
[YAML maintained fork](https://github.com/yaml/go-yaml).

Prepare a never-booted ingest template with current source using the existing
`infra/ingest/build-template.sh` procedure. Keep the immutable preloaded database
and its exact hash/UpdatedAt from infra/build/tools.lock.json; stale DB fails closed.
Make a private ingest backend config pointing to the new template and exact digest.
Do not reuse a previously executed guest or mount guest-modified images.

On the existing explicitly configured disposable M05/M07 host, run:

```sh
umask 077
M08_LAB_APPROVED=YES-I-AUTHORIZE-CONFIG-LAB python3 infra/config/lab.py \
  --lab <private-m05-lab-root> --tools <pinned-tools-directory> \
  --ingest-config <private-new-ingest-backend.json>
```

This builds fresh runner/provisioner/test binaries and a fresh never-booted builder
image, runs the ten M07 regression scenarios and three M08 scenarios, captures
packets, and restores fixture trust/addresses/firewall. The M08 two-service fixture
references the exact image independently admitted by the first Dockerfile fixture;
its local service has its own fresh build/scan admission. The runtime agent gate
validates both finalized specs without creating runtime containers.

The guest tests use fixed raw-disk tail regions for bounded credential-free test
output. The host reads opaque test output; it never mounts or parses a workload
filesystem. Guest parser children have a fixed cgroup under runner, 128 MiB memory,
zero swap, one CPU, 32 PIDs and a 5-second parent deadline. The enclosing guest retains
all M07 host quotas and independent expiry. Lab-only fuzz workers are separate from
production parser dispatch and do not receive artifact grant tokens.

`--cases` selects development cases and always prevents acceptance. Debug wrappers,
source changes during a run, skipped required cases, nonzero results, unexpected
network arrivals or uncertain cleanup prevent acceptance. Preserve failed runs as
development evidence and rerun the complete frozen source after corrections.

After implementation, follow the milestone test plan and run `report.py` with the
full software JSON log, hashed check manifest and complete private pipeline evidence.
Copy only bounded nonsecret logs, manifests and the per-case ledger into milestone
`testing/`; keep certificates, keys, database disks, raw images and packet captures
in the private lab directory. No production service is enabled by this lab.
