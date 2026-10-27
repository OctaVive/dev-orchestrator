# P1-M01 - Scaffold domain/protocol contracts and fixture inventory; document capability checklist

Status: **Implemented/tested**.

## Requirement and acceptance contract

- Scope: Scaffold domain/protocol contracts and fixture inventory; document capability checklist.
- Prerequisites: None.
- Acceptance gate: Schemas reject unknown fields; security requirements mapped to tests.
- Source: [PH1 minimal plan](../../../plans/PH1/minimal.md).
- Requirements: [project requirements](../../requirements.md), [requirement-to-milestone map](../../requirement-milestones.md) and [evidence checklist](../../requirement-evidence.md).

## Documents

- [project structure](../../specifications/project-structure.md)
- [api design](../../specifications/api-design.md)
- [testing strategy](../../specifications/testing-strategy.md)
- [development environment](../../specifications/development-environment.md)

## Implementation history and validation

## P1-M01 — contract and test foundation

Status: foundation implemented and unit/contract checks passing; ready for review. This increment deliberately implements no listener, deployment runner or infrastructure changes. The existing 39 architecture/plan documents are preserved, with their index updated for implementation status.

### Deliverables

- `go.mod`, `go.sum`: Go module and pinned JSON Schema validation dependency.
- `api/{common,deployment,agent}.schema.json`: version 1, unknown fields denied on structured objects. Environment dictionaries intentionally permit bounded user keys.
- `api/openapi.yaml`: initial submit/status HTTP design contract; no handler implementation implied.
- `internal/domain`: state topology and default-deny principal permission helpers.
- `internal/contracts`: body/depth/UTF-8/duplicate/trailing checks, compiled local schemas, typed request decoding, lexical Git/path validation, worker/expiry/generation checks.
- `tests/fixtures`: accepted contract data, mutation tests and future Compose/network/execution fixture inventory.
- [Capability and requirement evidence checklist](../../requirement-evidence.md).

### Contract decisions / limitations

- IDs are lowercase canonical UUIDs; commands use safe integer generations ≤2^53−1. Agent leases may be at most 5 minutes, deployment bodies at most 64 KiB, commands 128 KiB, JSON nesting 32.
- Numeric tokens must be decimal integers fitting signed 64-bit range; exponent/fraction/oversized encodings are rejected before schema arithmetic. Future command signing/replay rules are specified in `api/README.md`, but cryptographic enforcement remains unimplemented.
- `restricted-v1` hard controls are backend-owned, not caller-disableable flags. No raw Compose, Docker options, host paths or proxy directives exist in command contracts.
- Managed mount targets initially limited to `/data` and named descendants. This is an intentionally small first contract; broader approved app directories require policy/schema review. Duplicate/overlapping mounts are rejected.
- Runtime env is bounded data; orchestrator/Docker/BuildKit control prefixes are reserved. Real secret reference materialization is M10, not an invitation to put management credentials in env.
- URL checks are lexical only, never DNS resolution or egress enforcement. DNS rebinding and allowed public-host exfiltration remain unresolved until worker network controls exist.
- `DecodeAgentCommand` accepts structurally valid signature bytes, **not a verified signature**. The fixture signature is dummy data. No function executes these commands. Signature verification, durable replay storage, app/volume ownership, registry policy and measured engine enforcement are M09/M10 duties.
- Principal helpers assume an already verified server-side session and current exact-app grant. They are not login middleware or an ACL cache.
- State helper validates legal edges only, not transaction durability or rollback health evidence.

### Validation

Executed on the Windows development host using Go 1.27.3 from a portable, SHA-256-verified official archive under the approved temporary directory (no system PATH change):

| Check | Result |
|---|---|
| `go test -count=1 -cover ./...` | PASS: contracts 89.9%, domain 100%; API resource package has no executable logic |
| `go vet ./...` | PASS |
| `go mod verify` | PASS, pinned schema validator v6.0.3 and x/text v0.43.0 |
| `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...` | PASS: cross-compilation only, not Linux execution |
| Markdown local link check | PASS, zero broken links |
| Deployment decoder fuzz, 10 s / 2 workers | PASS, 16,335 executions |
| Agent decoder fuzz, 10 s / 2 workers | PASS, 2,418 executions |

No Linux VM/security release gate can be proven by these Windows unit/contract checks. OpenAPI is an initial design contract, not implemented or end-to-end validated HTTP behavior. Fuzz runs are bounded smoke tests, not proof of parser correctness or complete denial-of-service resistance.

