# PH5 - Security assurance and recovery

Operators detect deployment risks, rehearse recovery and containment, and release only with current evidence and assigned residual-risk owners.

These documents explain planned design and acceptance. Current implementation and test results remain in the [project status](../../PROJECT-STATUS.md) and linked milestone evidence.

```mermaid
flowchart LR
  A["Operator / security reviewer"] --> B["Evidence and policy workflows"]
  B --> C["Scanner / encrypted backup / audit"]
  C --> D["Isolated test and recovery environment"]
```

The drawing is a responsibility overview, not a network connectivity or deployment topology.

## Minimal track

Source: [minimal plan](../../docs/plans/PH5/minimal.md). Recommended adds to minimal; hardened adds to both. Follow explicit cross-track dependencies.

| Milestone | Feature |
|---|---|
| [P5-M01](p5-m01.md) | Threat-model refresh and requirement-to-evidence inventory |
| [P5-M02](p5-m02.md) | Scanner DB freshness, severity policy and remediation tracking |
| [P5-M03](p5-m03.md) | Runtime/build tool template patch and secret/key rotation procedures |
| [P5-M04](p5-m04.md) | Encrypted metadata/key/app-volume backup implementation and restore drill |
| [P5-M05](p5-m05.md) | Full adversarial regression automation and scoped penetration-test rules |
| [P5-M06](p5-m06.md) | Remediation review, incident exercise and release risk signoff |

## Recommended track

Source: [recommended plan](../../docs/plans/PH5/recommended.md). Recommended adds to minimal; hardened adds to both. Follow explicit cross-track dependencies.

| Milestone | Feature |
|---|---|
| [P5-R01](p5-r01.md) | Periodic running-image rescans and risk inventory |
| [P5-R02](p5-r02.md) | Off-host encrypted backup and append-only audit export |
| [P5-R03](p5-r03.md) | Independent platform penetration test and prioritized fixes |
| [P5-R04](p5-r04.md) | Scheduled chaos and restore drills with capacity/lease telemetry |
| [P5-R05](p5-r05.md) | Release security checklist and operator incident training |

## Hardened track

Source: [hardened plan](../../docs/plans/PH5/hardened.md). Recommended adds to minimal; hardened adds to both. Follow explicit cross-track dependencies.

| Milestone | Feature |
|---|---|
| [P5-H01](p5-h01.md) | Physical separation rollout and host identity/network policy |
| [P5-H02](p5-h02.md) | Per-app runtime VM profile and placement capability model |
| [P5-H03](p5-h03.md) | Quiesced volume export/restore and digest-preserving worker migration |
| [P5-H04](p5-h04.md) | Compromised-worker quarantine, credential rotation and rebuild drill |
| [P5-H05](p5-h05.md) | Independent escape/segmentation review and final assurance statement |
