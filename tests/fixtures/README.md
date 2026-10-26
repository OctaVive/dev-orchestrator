# Security fixture inventory

These files are **test data**, not runnable examples. Never run `docker compose up`, a Docker build or shell commands from this tree on a developer host. `.invalid` domains are deliberately non-production. No real credentials or malicious executable payloads are included.

| Fixture | Consumer | Current assertion |
|---|---|---|
| `contracts/dockerfile-request.json` | `internal/contracts` tests | Dockerfile intent shape accepted, typed roundtrip |
| `contracts/compose-request.json` | Same | Compose intent shape accepted; does NOT parse Compose |
| `contracts/agent-command.json` | Same | Envelope shape/context accepted; dummy zero signature is NOT cryptographically valid |
| `contracts/build-lease.json` | Same / provisioner tests | Bounded fixed-template VM intent only; no host XML/path/network/secret inputs; not actual VM creation |
| Generated contract mutations | Same | Unknown keys, unsafe types, resource omissions, host settings, malformed JSON, mount overlaps rejected |
| `compose/review-candidate.yaml` | Future P1-M08 | Candidate two-service subset; not yet validated or approved |
| `compose/deny-privileged.yaml` | Future P1-M08 | Must reject privileged configuration |
| `compose/deny-host-access.yaml` | Future P1-M08 | Must reject host namespaces, sockets, bind mounts/devices |
| `compose/deny-ambiguous.yaml` | Future P1-M08 | Must reject duplicate YAML keys before normalization |

## Required future lab fixtures

- P1-M05/M06: controlled DNS server rebinding public to private; mixed A/AAAA; IPv4-mapped IPv6; redirect chains; metadata targets; public host aliasing management addresses; direct sockets/DoH/QUIC bypass. Unit URL checks are not completion evidence.
- P1-M06: Git helper protocols, submodules, LFS/filter hooks, path/symlink escape, huge pack/ref lists, branch movement during checkout. Never serve private/internal URLs without an isolated lab.
- P1-M07: process/memory/disk/log bombs, image/tar traversal and decompression bombs, image digest mismatch. Generate only in budgeted disposable guests.
- P1-M09/M10: wrong worker/app/volume IDs, symlink ownership race, replayed command, rootless resource bypass, cross-app network access.
- P1-M11/M14: direct app port scans, forged headers, auth outage, proxy config injection, late cancellation, orphan kill after controller loss.

All network/execution fixture cases are **pending**, not passing because this foundation cannot execute them. The capability checklist tracks the release blockers.
