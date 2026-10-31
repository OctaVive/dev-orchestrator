# Disposable runtime feasibility experiments

These scripts and the MAC prototype were exercised only inside a trusted,
NIC-less, snapshot KVM guest. They are not production adapters, template installers
or full M09 acceptance tests. The `.go.txt` file is retained as provenance of the
minimal prototype; it is deliberately outside normal Go package builds.

The existing trusted guest root was prepared with pinned Docker/rootless extras
29.5.0, systemd cgroup v2 delegation, UID/GID 1000, subordinate IDs and the preloaded
`tap-runtime` AppArmor profile. `namespace-guest.sh` uses a single engine and stock
runc. `per-app-guest.sh` uses separate app-a/app-b engines and the minimal fixed
MAC prototype. Both run only known static BusyBox fixtures, with no repository
code, application ports, NIC or production credentials.

The app-a/app-b systemd user units set distinct
`DOCKERD_ROOTLESS_ROOTLESSKIT_STATE_DIR`, socket, data-root, exec-root and pidfile.
Each launches its own rootless namespace. Each registers the fixed prototype at
`/usr/local/bin/tap-runc`, with pinned real runc at
`/usr/local/libexec/runc-real`. Units use `Delegate=yes` and `Restart=no`.
The single-engine observation uses `m09-docker.service` and its private socket.

The MAC prototype applies the fixed profile to a trusted engine-generated OCI
bundle; it does not implement final bundle validation, independent observation,
ownership, capacity, crash recovery or a general RPC. Its success does not make
the current production hardener accepted. Any production supplement must validate
its fixed inputs and remain pinned/maintained.

[Recorded comparison](../../../docs/project/PH1/P1M09/testing/isolation-direction.json)
shows the shared-engine apps had the same user namespace and were unconfined.
The app-scoped prototype gave them distinct user namespaces and enforced MAC.
Neither experiment establishes real network denial, quotas, image admission or
signed-agent lifecycle. The full M09 ledger remains incomplete.

`backend-observer-guest.sh` and `backendprobe/` exercise the actual Go Linux
backend identity observer against both real app daemons. The fixed diagnostic
collects trusted boot/PID/namespace/map/socket bindings as guest root, drops to
UID/GID 1000, verifies both backends, persists/reopens the private ledger, and
checks start-time/map/namespace/boot mismatches. It chmods only the fixed fixture
socket/data paths. It does not run hostile workloads or assert full readiness.
The diagnostic observes already-provisioned daemons; it does **not** test the
production reserve-before-provisioning sequence. No command accepts deployment
input, arbitrary paths or executable options. Use only a fresh disposable guest
with `/etc/m09-disposable-guest`; no NIC, snapshot writes and an external timeout.
