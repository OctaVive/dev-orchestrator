# Project delivery documentation

Follow the delivery chain: [requirements](requirements.md) -> [requirement-to-milestone map](requirement-milestones.md) -> [PH1 milestones](PH1/README.md) -> milestone implementation notes and acceptance evidence.

```text
docs/project/
|-- README.md
|-- requirements.md
|-- requirement-milestones.md
|-- requirement-evidence.md
|-- progress.md
|-- PH1/
|   |-- README.md
|   |-- P1M01/README.md
|   |-- P1M02/              # README + SQLite contract
|   |-- P1M03/              # README + authentication runbook
|   |-- P1M04/              # README + provisioner contract + testing/
|   |-- P1M05/ ... P1M14/   # one README per planned milestone
|-- specifications/        # shared implementation contracts
```

- [Progress](progress.md) records current status; skipped checks remain explicit.
- [Requirement evidence](requirement-evidence.md) records what tests prove and what remains open.
- [Shared specifications](specifications/README.md) contain contracts used by multiple milestones.
- [Reusable documentation structure guide](documentation-structure-guide.md) explains this layout and provides templates for future projects.
- [Phase plans](../plans/master-roadmap.md) retain the scope and sequencing for PH1-PH5, including recommended and hardened tracks. Later phases receive milestone folders when implementation is scheduled; their plans remain authoritative.
- [Architecture](../README.md#architecture) explains system boundaries and design decisions.

Folder names omit the task ID hyphen (`P1M01` = `P1-M01`). Keep each milestone's implementation notes, runbooks and acceptance reports inside its folder. Keep shared contracts in `specifications/` and link them from milestone READMEs. Update the requirement map, milestone status and evidence checklist when scope or evidence changes. A folder's existence does not mean its milestone is implemented.
