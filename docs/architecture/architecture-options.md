# Architecture alternatives

All options below must be considered with a separate authenticated gateway. None authorizes handing a Docker socket to the GUI/API. For a fair comparison, distinguish deployment simplicity from security completeness.

## A — Docker-in-Docker

Privileged DinD places a nested rootful daemon inside a privileged container. Broad capabilities, devices and mounts make compromise a credible host compromise. Nested bridges, overlay storage and volume ownership complicate routing, backups and debugging. A nested daemon is not a VM security boundary. Fast setup and modest idle memory do not compensate for the attack surface.

Rootless DinD removes some privilege but depends on user namespaces, nesting support and often relaxed outer-container constraints. It shares the host kernel; cgroup limits, networking and overlay behavior require validation. A build exploit can target both layers. Rootless DinD is not a substitute for disposable build VMs. Reject privileged DinD as primary architecture; rootless DinD is at most an explicitly isolated development experiment, never a production fallback.

## B — Host Docker Engine through local agent

A host agent, not the web service, holds rootful Docker authority. Easy ingress and volume operations, mature monitoring, low overhead. However Docker daemon authority is effectively host root. A narrow authenticated RPC reduces API exposure but an agent vulnerability or malicious daemon response handling threatens the machine and co-resident management. Local socket permission is a privilege boundary, not a hostile-workload isolation boundary. Building on this host violates the build separation requirement. Reject for arbitrary repositories.

## C — Rootless Docker + local deployment agent

Agent runs under a dedicated Unix account and controls only that account's rootless daemon. mTLS or local authenticated IPC protects its typed API. User-namespace mapping reduces host-root impact. Rootless network behavior, source addresses, bridge reachability, subuid/subgid, filesystem ownership and cgroup delegation complicate resource and network enforcement. Loopback/host reachability must be disabled and tested, not inferred from rootlessness.

Good for reviewed workloads on a small machine, but management and untrusted containers still share a host kernel. Per-app storage depends on agent ownership maps and mount validation. Cloning/building locally cannot meet the required build boundary. A remote ephemeral builder improves it but leaves weak runtime separation. Not the secure arbitrary-repository MVP.

## D — Dedicated runtime VM + independent management plane

Runtime VM contains Docker and a restricted agent. Management is in another VM or physical machine. Hypervisor firewall isolates both, and runtime volumes/backups stay in runtime storage. Agent compromise primarily compromises this VM, not management. VM overhead and networking are greater, but snapshots, quotas and rebuilding the worker are understandable single-server operations.

If builds share the runtime VM they can compromise running apps and storage. Therefore D alone does not meet disposable build isolation; **D + E** is the PH1 recommendation. Future workers use the same identity/capability protocol rather than introducing a cluster scheduler.

## E — Ephemeral build VMs + separate restricted runtime

Each job gets a clean VM, fixed resource budget, rootless BuildKit, a constrained egress path and no management secrets. Clone and build share only that disposable security domain. Immutable image export passes to a separate ingestion/registry path. Destroy VM and disks after completion or timeout. Runtime is D with rootless Docker, ideally separate hardware long term; higher-risk apps receive per-app or per-trust-group runtime VMs.

Strongest of these choices against malicious build tools, at the cost of VM lifecycle tooling, image maintenance, startup latency and RAM. Keep one build slot and warm **clean base images**, not reusable contaminated guests. Single-server operation is feasible with KVM, but management availability still depends on the same physical host.

## Backup and migration implications

A/B/C simplify disk access but tempt unsafe host mounts. D/E back up management SQLite, runtime volumes and registry artifacts separately. VM disk snapshots alone are not application-consistent database backups. Move runtime agents and volumes to another host using quiesced export/restore and a fresh agent identity; never mount one SQLite app database read-write from multiple workers.
