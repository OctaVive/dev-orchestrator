# PH3 - MFA, users and application permissions

An administrator enrolls MFA and manages accounts and explicit application grants; users see and open only applications they are allowed to access.

These documents explain planned design and acceptance. Current implementation and test results remain in the [project status](../../PROJECT-STATUS.md) and linked milestone evidence.

```mermaid
flowchart LR
  A["Login and administration UI"] --> B["Auth / TOTP / ACL service"]
  B --> C["SQLite credentials and ACL epochs"]
  C --> D["Gateway / stream lease registry"]
```

The drawing is a responsibility overview, not a network connectivity or deployment topology.

## Minimal track

Source: [minimal plan](../../docs/plans/PH3/minimal.md). Recommended adds to minimal; hardened adds to both. Follow explicit cross-track dependencies.

| Milestone | Feature |
|---|---|
| [P3-M01](p3-m01.md) | AEAD key-version adapter and TOTP credential/recovery schema |
| [P3-M02](p3-m02.md) | TOTP pending-login/enrollment/confirmation and replay guard |
| [P3-M03](p3-m03.md) | Hashed one-use recovery codes and guarded reset flow |
| [P3-M04](p3-m04.md) | MFA UI and mandatory-admin enrollment policy |
| [P3-M05](p3-m05.md) | Admin/User CRUD and transactional per-app grants with ACL epochs |
| [P3-M06](p3-m06.md) | Grant management UI, session disable/revoke and durable invalidation |
| [P3-M07](p3-m07.md) | Full role/MFA/revocation audit and timed request/WS/SSE regression |

## Recommended track

Source: [recommended plan](../../docs/plans/PH3/recommended.md). Recommended adds to minimal; hardened adds to both. Follow explicit cross-track dependencies.

| Milestone | Feature |
|---|---|
| [P3-R01](p3-r01.md) | Session inventory, per-session/all-session revoke and recent-auth UX |
| [P3-R02](p3-r02.md) | Epoch-aware ≤5 s cache with push invalidation and strict lease expiry |
| [P3-R03](p3-r03.md) | TOTP encryption-key rotation and isolated recovery drill |
| [P3-R04](p3-r04.md) | Filtered audit browser and sensitive-action alerts |
| [P3-R05](p3-r05.md) | Concurrency/property tests and operator lockout exercise |

## Hardened track

Source: [hardened plan](../../docs/plans/PH3/hardened.md). Recommended adds to minimal; hardened adds to both. Follow explicit cross-track dependencies.

| Milestone | Feature |
|---|---|
| [P3-H01](p3-h01.md) | Hardware/external wrapping-key adapter with fail-closed startup |
| [P3-H02](p3-h02.md) | Dual approval for exceptional MFA reset/role escalation when two admins exist |
| [P3-H03](p3-h03.md) | Independent auth/ACL penetration review and fuzz campaign |
| [P3-H04](p3-h04.md) | Offline recovery/custody exercise with audit verification |
