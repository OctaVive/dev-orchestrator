# M07 OCI/scanner fixtures

`fixture.go` constructs known inert OCI tar bytes without reading an archive,
executing a container or invoking an image parser on management. The clean image
contains synthetic Alpine OS/package metadata for `m07-inert`. The vulnerable
image contains historical BusyBox package metadata only; no vulnerable executable
is run. Real Trivy must report HIGH/CRITICAL findings for that fixture before its
policy denial counts as evidence.

Consumers: `internal/ingest` guest tests and the isolated provisioner ingest
acceptance test. Host construction is permitted; every OCI/archive/scanner parser
and all fuzzing run inside disposable externally budgeted guests. No host-side
scanner or image extraction fallback exists.

The guest corpus includes ordinary/gzip images, safe internal links/whiteouts,
path/type/link attacks, malformed digests/graphs/config, decompression and entry
budgets, gzip corruption/concatenation, JSON ambiguity and root-user aliases.
`infra/build/report.py` inventories every required case. Inputs are generated at
runtime and bounded, rather than checking large hostile archives into Git.

The M07 extension of `infra/clone/fixture.py` constructs inert Git and registry
objects. Its repositories exercise sandboxed builds, CPU/log/disk/memory/PID
pressure and a base-image ONBUILD remote source. That last case must fail without
any controlled `remote-target` request. Workload execution occurs only in KVM.
