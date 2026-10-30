# M07 isolated OCI validation and scanning

Use a separate pinned, no-NIC KVM backend with `ingest_enabled`, a private
`artifact_root`, and `ingest_database`/`ingest_database_digest` pointing to a
trusted frozen read-only database image. Artifact/database storage must share the
backend root filesystem so the existing host I/O controls cover attached disks.
The scanner VM has the same externally enforced fixed profile as the builder;
the driver destroys the builder before starting it.

QEMU supplies sealed job input as vdb, exact opaque upload bytes as read-only
vdc, and the pinned database filesystem as read-only vdd. Host code hashes opaque
bytes; it never mounts or parses workload output. The database image is built
from a verified trusted snapshot with `build-database.sh`; it is never guest
writable. Do not bundle the 1.6 GiB DB in a 4 GiB guest's initramfs.

Trusted guest init runs validation as UID 1000 in a dedicated PID-limited cgroup.
The validator cannot write the result serial device. It validates the outer tar,
OCI graph, sizes, compressed hashes, uncompressed diff IDs, paths, links, entry
counts and expansion limits, then creates a private OCI layout view. Malformed
archives never enter the scanner phase. Root init kills validator descendants,
freezes that view under root ownership, and invokes scanning as UID 1001 with a
separate bounded scratch filesystem. Failure uses a fixed denial entry point.

Trivy runs offline against the verified layout with the pinned binary/database,
no ignore/config file supplied by the repository, no image execution, no internet
or engine socket. The scan rejects missing coverage, unknown severity, EOL OS,
stale/mismatched DB metadata, HIGH and CRITICAL findings including unfixed issues.
Exceptions match the exact manifest digest, package and finding and must expire.
Only normalized counts, closed outcomes and report/SBOM hashes leave the guest.
The complete immutable admission record remains distinct from deployment approval.

The outer layout supports only regular OCI files and expected directories. Layer
links must remain internal; absolute links, unsafe link ancestry/cycles, sparse/
PAX/GNU extensions, special files, set-ID modes and whiteouts combined with links
are rejected conservatively. Initial image config requires numeric non-root UID
1–65535, no OnBuild or declared volumes. Multi-platform indexes, external blob
URLs, non-SHA256 descriptors and concatenated gzip streams are unsupported.

`tests/fixtures/oci` constructs known inert image bytes without host-side parsing.
The hostile parser corpus and real scanner fixtures execute only in disposable
guests. Scan results do not prove an image benign or establish trustworthy source
provenance from a compromised builder. Full scheduling, current-policy approval
and runtime enforcement remain later milestones.

Build the scanner template with `build-template.sh` and its explicit
`M07_INGEST_TEMPLATE=YES-I-AUTHORIZE-INGEST-TEMPLATE` opt-in. The guest test binary
is compiled with `-fuzz` so its bounded parser fuzz run has coverage guidance.
