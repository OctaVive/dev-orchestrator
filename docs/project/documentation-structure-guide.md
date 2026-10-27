# Reusable project documentation structure

Use this guide when starting a project or organizing an existing one. It describes the documentation approach used in this repository and provides templates that can be copied into another project. Application source folders can follow the conventions of that project's language and framework.

The reading order is:

```text
Requirements -> milestone mapping -> phase -> milestone -> implementation -> acceptance evidence
```

## Current documentation structure

```text
docs/
|-- README.md                         # Entry point for all documentation
|-- architecture/                    # System design, boundaries and tradeoffs
|-- decisions/                       # Open questions and exception policy
|-- plans/
|   |-- master-roadmap.md            # Phase sequencing and release rules
|   |-- PH1/                         # Minimal/recommended/hardened phase plans
|   |-- PH2/ ... PH5/
|-- project/
    |-- README.md                    # Delivery documentation entry point
    |-- documentation-structure-guide.md
    |-- requirements.md              # Product scope and required boundaries
    |-- requirement-milestones.md    # Requirements mapped to milestone owners
    |-- requirement-evidence.md      # Evidence, gaps and remaining dependencies
    |-- progress.md                  # Overall status and next work
    |-- specifications/              # Contracts shared by multiple milestones
    |   |-- README.md
    |   |-- api-design.md
    |   |-- deployment-agent.md
    |   |-- development-environment.md
    |   |-- frontend-design.md
    |   |-- project-structure.md      # Proposed application source structure
    |   |-- reverse-proxy.md
    |   |-- testing-strategy.md
    |-- PH1/
        |-- README.md                # Phase milestone index
        |-- P1M01/
        |   |-- README.md            # Contracts and domain foundation
        |-- P1M02/
        |   |-- README.md
        |   |-- sqlite-storage.md
        |-- P1M03/
        |   |-- README.md
        |   |-- auth-core.md
        |-- P1M04/
        |   |-- README.md
        |   |-- build-provisioner.md
        |   |-- testing/
        |       |-- acceptance-report.md
        |       |-- command-debug-plan.md
        |       |-- linux-checklist.md
        |       |-- real-host.md
        |-- P1M05/ ... P1M14/         # Each contains its own README.md
```

Only PH1 currently has implementation milestone folders. PH2-PH5 remain phase plans. A milestone folder can describe planned work; its existence does not imply implementation or acceptance.

## Folder and ownership conventions

| Location | Owns | Update when |
|---|---|---|
| `requirements.md` | Scope, constraints and requirement definitions | A requirement changes |
| `requirement-milestones.md` | Requirement-to-milestone assignments | Delivery ownership or dependencies change |
| `requirement-evidence.md` | Requirement-level evidence and unresolved gaps | Validation provides new evidence |
| `progress.md` | Overall status and next milestone | A milestone's status changes |
| `plans/` | Phase scope, sequence and acceptance rules | The delivery plan changes |
| `PH1/README.md` | Phase milestone index | Milestones are added or change status |
| `PH1/P1M01/README.md` | Milestone scope, dependencies, acceptance and handoff | That milestone progresses |
| `PH1/P1M01/testing/` | Milestone test procedures and acceptance records | Checks are defined or executed |
| `specifications/` | Contracts used across milestones | A shared interface or convention changes |
| `architecture/` | System design and rationale | Architectural decisions change |
| `decisions/` | Unresolved choices and explicit exceptions | A decision is raised or resolved |

Keep one authoritative definition of each requirement or shared contract. Other documents should link to it. Put documents used only by a milestone inside that milestone's folder. Put documents used by several milestones in `specifications/`.

## Naming

- Phase folders: `PH1`, `PH2`, `PH3`.
- Milestone folders: `P1M01`, `P1M02`, `P2M01`.
- Canonical task IDs in prose, tables and commits: `P1-M01`, `P1-M02`, `P2-M01`.
- Document filenames: lowercase words separated by hyphens.
- Every phase and milestone folder has a `README.md` entry point.
- Use relative Markdown links so copied documentation works in another repository.

Keep assigned IDs stable. Add milestones without renumbering completed work. If a project already uses requirement IDs, retain them; this repository uses `SEC-01`, etc. for security release tests. A new project can use `REQ-001`, `REQ-002`, etc. for its own requirements.

## Starter structure for a new project

Create only the phases and milestones the project needs. Additional implementation notes and testing folders can be added as work progresses.

```text
docs/
|-- README.md
|-- architecture/
|-- decisions/
|-- plans/
|   |-- master-roadmap.md
|   |-- PH1/
|       |-- minimal.md
|-- project/
    |-- README.md
    |-- requirements.md
    |-- requirement-milestones.md
    |-- requirement-evidence.md
    |-- progress.md
    |-- specifications/
    |   |-- README.md
    |-- PH1/
        |-- README.md
        |-- P1M01/
        |   |-- README.md
        |-- P1M02/
            |-- README.md
```

This repository has minimal, recommended and hardened phase plans. Those tracks are optional for a new project; a single phase plan is enough when there are no distinct delivery tracks.

## Copyable requirement map

Place this table in `docs/project/requirement-milestones.md`. Define each requirement in `requirements.md` and link its acceptance evidence from `requirement-evidence.md`.

```markdown
# Requirement-to-milestone map

| Requirement | Expected behavior | Delivery milestone | Acceptance evidence |
|---|---|---|---|
| REQ-001 | Describe an observable outcome | [P1-M01](PH1/P1M01/README.md) | Required checks; evidence pending |
| REQ-002 | Describe an observable outcome | [P1-M02](PH1/P1M02/README.md) | Required checks; evidence pending |
```

A requirement may span several milestones. List all contributing milestones and identify the final acceptance gate. Every in-scope requirement should have a delivery owner or an explicit deferred decision.

## Copyable milestone README

Place this template in `docs/project/PH1/P1M01/README.md` and adjust IDs and links for the target milestone.

```markdown
# P1-M01 - Milestone title

Status: Planned.

## Requirement and acceptance contract

- Scope: Describe the outcome and its boundaries.
- Requirements: REQ-001; see [requirement map](../../requirement-milestones.md).
- Prerequisites: None, or links to prerequisite milestones.
- Acceptance gate: State observable conditions required for acceptance.
- Source: [Phase plan](../../../plans/PH1/minimal.md).

## Documents

- Link relevant shared specifications and milestone-specific notes here.

## Implementation

Record delivered behavior, affected source paths and meaningful decisions.
Keep proposed work clearly distinguished from implemented behavior.

## Validation and evidence

| Check | Result | Evidence |
|---|---|---|
| Acceptance check | Not run | No evidence recorded |

Record the environment, versions, execution date and evidence location.
Keep private logs and credentials outside the repository.

## Limitations and next work

Record unresolved issues, skipped checks and the next dependent milestone.
```

## Status and evidence rules

Use explicit statuses such as `Planned`, `In progress`, `Implemented; acceptance pending`, `Accepted`, or `Blocked` with the blocking condition. Preserve qualified outcomes such as this repository's M04 status with skipped checks.

Record PASS, FAIL, SKIP and Not run separately. A passing unit test establishes only what it exercises; deployment or infrastructure requirements need evidence from the applicable environment. Link detailed reports from the milestone README and summarize requirement coverage in `requirement-evidence.md`.

## Workflow for future projects

1. Define scope, requirement IDs and observable acceptance conditions.
2. Plan phases and milestones with explicit dependencies.
3. Map each requirement to its delivery milestone and acceptance gate.
4. Create phase indexes and milestone READMEs using the template above.
5. Link shared specifications; keep milestone-specific notes and tests with their milestone.
6. As implementation progresses, record behavior, validation, limitations and next work.
7. Update milestone status, the phase index, overall progress and requirement evidence together.
8. Check relative links after moving documents and remove obsolete duplicate copies.

## Copyable instruction for a project assistant

```text
Organize this project's documentation under docs/project/ using a requirement-to-milestone structure.
Create requirements.md, requirement-milestones.md, requirement-evidence.md and progress.md.
Group milestones by phase: PH1/P1M01/, PH1/P1M02/, then PH2/P2M01/ when needed.
Give each phase and milestone a README.md.
Each milestone must identify its requirements, prerequisites, acceptance gate,
relevant specifications, implementation status, evidence and remaining work.
Keep shared contracts in specifications/ and milestone-specific documents inside
their milestone folder. Retain architecture and phase plans as linked sources.
Preserve existing requirement/task IDs, historical evidence and skipped-check qualifications.
Update incoming links when moving files. Do not mark planned work as implemented.
```
