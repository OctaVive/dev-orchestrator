# Reusable project documentation structure

Use this guide when starting a project or organizing an existing one. It describes the documentation approach used in this repository and provides templates that can be copied into another project. Application source folders can follow the conventions of that project's language and framework.

The reading order is:

```text
Requirements -> milestone mapping -> phase -> milestone design (LLD) -> implementation -> acceptance evidence
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

The repository also contains this design collection at the repository root, alongside `docs/`:

```text
LLD-documents/
|-- README.md                        # Collection index and reading guide
|-- PH1/
|   |-- README.md                    # Phase index, grouped by delivery track
|   |-- p1-m01.md                    # One design document per minimal milestone
|   |-- ... p1-m14.md
|   |-- p1-r01.md ... p1-r06.md      # Recommended additions
|   |-- p1-h01.md ... p1-h05.md      # Hardened additions
|-- PH2/                             # README.md and 15 milestone documents
|-- PH3/                             # README.md and 16 milestone documents
|-- PH4/                             # README.md and 15 milestone documents
|-- PH5/                             # README.md and 16 milestone documents
```

The [LLD collection](../../LLD-documents/README.md) contains 87 milestone documents across all five phases and all three delivery tracks. Only PH1 currently has implementation milestone folders under `docs/project/`; PH2-PH5 have phase plans and LLD documents. A design document or milestone folder does not imply implementation or acceptance.

## Folder and ownership conventions

| Location | Owns | Update when |
|---|---|---|
| `requirements.md` | Scope, constraints and requirement definitions | A requirement changes |
| `requirement-milestones.md` | Requirement-to-milestone assignments | Delivery ownership or dependencies change |
| `requirement-evidence.md` | Requirement-level evidence and unresolved gaps | Validation provides new evidence |
| `PROJECT-STATUS.md` | Overall project status, current phase/milestone, blockers and next work | Project status or priorities change |
| `progress.md` | Existing delivery progress records, linked from `PROJECT-STATUS.md` when retained | Delivery progress changes |
| `plans/` | Phase scope, sequence and acceptance rules | The delivery plan changes |
| `LLD-documents/README.md` (repository root) | Design collection index and reading conventions | Phases or collection conventions change |
| `LLD-documents/PH1/README.md` | Phase design index for all delivery tracks | Milestones or their track assignments change |
| `LLD-documents/PH1/p1-m01.md` | Functional explanation, technical design, diagrams and linked acceptance gate for one milestone | Its scope, dependencies or design changes |
| `PH1/README.md` | Phase milestone index | Milestones are added or change status |
| `PH1/P1M01/README.md` | Milestone scope, dependencies, acceptance and handoff | That milestone progresses |
| `PH1/P1M01/implementation-plan.md` | Target behavior, implementation sequence and delivery boundaries | The implementation approach changes |
| `PH1/P1M01/test-plan.md` | Required test cases, expected results and acceptance criteria | Coverage or validation requirements change |
| `PH1/P1M01/implementation-evidence.md` | Delivered behavior, executed checks and development history | Implementation or validation produces new evidence |
| `PH1/P1M01/testing/` | Reproducible execution procedures and acceptance records | Checks are defined or executed |
| `specifications/` | Contracts used across milestones | A shared interface or convention changes |
| `architecture/` | System design and rationale | Architectural decisions change |
| `decisions/` | Unresolved choices and explicit exceptions | A decision is raised or resolved |

Keep one authoritative definition of each requirement or shared contract. Other documents should link to it. Put implementation notes and evidence used only by a milestone inside that milestone's implementation folder. Put documents used by several milestones in `specifications/`. Keep explanatory milestone designs in `LLD-documents/`, linking to the authoritative plans, specifications and evidence.

## Naming

- Phase folders: `PH1`, `PH2`, `PH3`.
- Milestone folders: `P1M01`, `P1M02`, `P2M01`.
- Canonical task IDs in prose, tables and commits: `P1-M01`, `P1-M02`, `P2-M01`.
- LLD documents use lowercase canonical task IDs as filenames: `LLD-documents/PH1/p1-m01.md`, `p1-r01.md`, `p1-h01.md`. `M`, `R` and `H` identify minimal, recommended and hardened tasks respectively.
- Document filenames: lowercase words separated by hyphens, except standard entry points such as `README.md` and `PROJECT-STATUS.md`.
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
    |-- PROJECT-STATUS.md            # Overall project status and next work
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

Add a sibling `LLD-documents/` collection at the repository root using the structure above. Create a phase folder and `README.md` for each planned phase, and one Markdown design document for every milestone in the selected tracks.

## Milestone design document contents

Use a mix of functional and technical writing so readers understand both the purpose and the mechanism. Each LLD document includes:

- The feature's purpose, intended users or operators, and observable outcome.
- Its delivery track, scope, prerequisites and links to dependent contracts.
- Components and responsibilities, with a Mermaid architecture drawing.
- The functional flow, with a Mermaid flowchart showing validation, success and failure paths.
- Technical behavior, protected state, trust boundaries and failure handling.
- The source acceptance gate, validation expectations and handoff.
- Links to the phase plan, shared specifications and existing implementation evidence.

Diagrams describe logical responsibilities unless explicitly identified as deployment topology. They do not introduce API contracts or grant infrastructure access. Plans own scope and dependencies; specifications own shared interfaces; implementation records own status and test evidence. Keep LLD explanations and drawings aligned with those sources, preserving qualified acceptance and skipped checks.

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

## Planning, building, testing and accepting a milestone

Use [P1-M05](PH1/P1M05/README.md) as a worked example of this lifecycle. Its phase plan defines the outcome and prerequisite; its LLD explains the design; separate plans describe implementation and required tests; execution records establish what was actually built and observed. Apply the same separation at a scale appropriate to the milestone.

```text
Requirement + phase acceptance gate + shared contracts
    -> LLD + implementation plan + test plan
    -> implementation + software validation
    -> applicable environment acceptance + cleanup verification
    -> implementation evidence + acceptance decision
    -> milestone, phase and project status + requirement evidence
```

### Document set and responsibilities

For a milestone needing detailed implementation and environment validation, use:

```text
docs/project/PH1/P1M01/
|-- README.md                       # Contract, status and links to every record
|-- implementation-plan.md          # Target behavior and delivery sequence
|-- test-plan.md                    # Required cases and expected results
|-- implementation-evidence.md       # Delivered behavior and actual validation
|-- testing/
    |-- real-host.md                # Reproducible environment procedure, if needed
    |-- acceptance-report.md        # Observed results and bounded acceptance decision
```

Keep the LLD at `LLD-documents/PH1/p1-m01.md`. Use an appropriate procedure filename when validation does not involve a real host. Small milestones may keep these sections in their README; retain the distinction between planned checks, execution evidence and acceptance.

P1-M05 demonstrates each responsibility:

| Record | What to learn from it |
|---|---|
| [Implementation plan](PH1/P1M05/implementation-plan.md) | Outcome, boundaries, policy/interfaces, component work, lifecycle, packaging order and acceptance assumptions |
| [LLD](../../LLD-documents/PH1/p1-m05.md) | Functional and technical explanation, topology, source responsibilities, startup/cleanup ordering and design tradeoffs |
| [Test plan](PH1/P1M05/test-plan.md) | SEC-07 objective, prerequisites, U01–U10 software cases, N01–N13 real-host cases and explicit evidence requirements |
| [Execution procedure](PH1/P1M05/testing/real-host.md) | Preflight, reproducible harness commands, controlled fixtures, capture points, fault injection, cleanup and result mapping |
| [Implementation evidence](PH1/P1M05/implementation-evidence.md) | Delivered components, commands, actual results, artifact identities, failures and corrected reruns |
| [Acceptance report](PH1/P1M05/testing/acceptance-report.md) | Dated decision, tested environment, hashes, results by ID, cleanup evidence, qualifications and handoff |

### 1. Establish the contract and implementation plan

Start with the requirement IDs, phase-plan acceptance gate, prerequisite milestones and shared specifications. State the observable outcome, included work, excluded work and later milestone dependencies. Preserve prerequisite qualifications: P1-M05 explicitly retains P1-M04 V14/V15 as SKIP.

Write `implementation-plan.md` before building. Describe the interfaces and configuration, component responsibilities, failure handling, lifecycle/cleanup obligations, compatibility, packaging and ordered delivery steps. Link the LLD for detailed mechanisms and diagrams. As the design evolves, align these documents with authoritative contracts. After execution, retain the target contract and link actual results rather than turning planned statements into evidence.

### 2. Derive the test plan before execution

Create `test-plan.md` from the requirements, acceptance gate and design risks:

1. Turn each required outcome into an observable assertion and map it to its requirement or gate.
2. Cover normal behavior, invalid inputs, boundary conditions, dependency failures, resource limits and applicable security threats.
3. Include lifecycle cases such as cancellation, expiry, interrupted setup, recovery, concurrent operations and cleanup where the feature owns resources.
4. Choose the validation layer that can prove each assertion: unit/integration checks for software behavior, and actual environment checks for infrastructure or deployment behavior. Specify fixtures and observation points.
5. Assign stable case IDs. For each case define prerequisites, procedure, expected result and required evidence before recording an actual result.
6. Define the acceptance rule, blocking prerequisites, allowed qualifications and residual limits. Missing required evidence leaves acceptance pending.

P1-M05 separates U01–U10 software checks from N01–N13 real-host checks. Its network-denial assertions require simultaneous captures and destination canaries: a timeout alone cannot establish that traffic never reached a protected destination. Generalize this principle by choosing independent observations at the boundary where the requirement must hold. Include a successful control so a broken fixture cannot make every denial appear to pass.

Use this copyable test-plan outline:

```markdown
# P1-M01 test plan — Milestone title

Status: Planned; link execution evidence when available.

## Objective and traceability

- Requirements and source acceptance gate: links and IDs.
- Outcomes to prove, scope boundaries and inherited qualifications.

## Prerequisites and environment

- Required tools, versions/capabilities, fixtures, data and topology.
- Environment authorization where applicable; conditions blocking execution.
- Baseline inventory, evidence storage and cleanup/restoration requirements.

## Required checks

| ID | Requirement/gate | Layer | Scenario/procedure | Expected result | Required evidence |
|---|---|---|---|---|---|
| T01 | REQ-001 | Integration | Exercise the normal operation | Observable success | Command output and resulting state |
| T02 | REQ-001 | Integration | Exercise an invalid input | Defined rejection; protected state preserved | Response and state observation |

Link detailed procedures and list applicable software validation commands.

## Acceptance rule and limits

Identify every required case and the evidence needed for acceptance.
Record PASS, FAIL, SKIP and Not run separately in execution records.
State known limits, deferred gates and the next milestone handoff.
```

### 3. Build and maintain reproducible execution procedures

Implement in the planned dependency order, adding the checks needed to exercise the contract. Record delivered behavior and relevant source paths in `implementation-evidence.md`; update the LLD when implementation changes the design. Run applicable software checks, including platform-specific integration checks, builds, static analysis, race checks or fuzzing when justified by the feature.

For environment acceptance, write a procedure under `testing/` with exact commands or harness entry points, preflight, fixture setup, observation points, case-ID mapping, fault injection and cleanup. Identify temporary configuration/trust changes and how their restoration is verified. Keep test-only overrides or fault hooks isolated from production behavior. Record source revision (and content hashes for uncommitted changes), binary/configuration/template identities, tool versions, operator, execution times and topology so the tested artifacts can be identified.

### 4. Record execution evidence and issue an acceptance report

For each case record its ID, PASS/FAIL/SKIP/Not run, command or probe identifier, expected and observed results, and evidence location. Keep raw logs, captures, keys and sensitive ownership records in an appropriate private location; commit sanitized summaries and evidence references. Preserve failed runs and corrections, giving reruns distinct identities. P1-M05 records a failed slow-header harness assertion, its correction and the final rerun rather than relabeling the earlier failure.

Use this acceptance-report outline:

```markdown
# P1-M01 acceptance report

Decision: Pending / PASS / qualified PASS / FAIL; execution date.
Scope: Exact environment, artifacts and acceptance gate covered.

## Environment and evidence

Record revision/content and binary/configuration hashes, versions, topology,
operator, execution interval and raw evidence locations.

## Results

| Case ID | Expected result | Observed result | Result | Evidence |
|---|---|---|---|---|
| T01 | Defined success | Actual observation | Not run | Pending |

## Cleanup and restoration

Record final resource inventory and comparison with the baseline, if applicable.

## Qualifications and handoff

Record failures, skips, missing evidence, residual limits, deferred gates
and the next milestone. Explain how these affect the acceptance decision.
```

Accept only when required checks have the required evidence; any exception must follow the project's explicit exception policy and remain visible in the decision. Software PASS alone does not establish environment acceptance. P1-M05's PASS applies to its isolated KVM lab and tested template; it does not pass historical M04 skips, authorize repository execution or establish production rollout or phase release approval.

After recording the decision, update the milestone README, LLD status, phase indexes, `PROJECT-STATUS.md` (or this repository's retained `progress.md`) and `requirement-evidence.md` consistently. Link detailed evidence instead of duplicating it, and preserve remaining downstream gates.

## Status and evidence rules

Use `docs/project/PROJECT-STATUS.md` in every project as the authoritative overview of overall project status. Include the last updated date, current phase and milestone, completed work, work in progress, blockers or risks, and next steps. Link to milestone details and acceptance evidence rather than duplicating them. This repository currently uses `progress.md`; when applying this guide to an existing project, consolidate its overall status into `PROJECT-STATUS.md` and update incoming links, retaining useful historical progress records as needed.

Use explicit statuses such as `Planned`, `In progress`, `Implemented; acceptance pending`, `Accepted`, or `Blocked` with the blocking condition. Preserve qualified outcomes such as this repository's M04 status with skipped checks.

Record PASS, FAIL, SKIP and Not run separately. A passing unit test establishes only what it exercises; deployment or infrastructure requirements need evidence from the applicable environment. Link detailed reports from the milestone README and summarize requirement coverage in `requirement-evidence.md`.

## Workflow for future projects

1. Define scope, requirement IDs and observable acceptance conditions.
2. Plan phases and milestones with explicit dependencies.
3. Map each requirement to its delivery milestone and acceptance gate.
4. Create phase indexes and milestone READMEs using the template above.
   Create the repository-root `LLD-documents/` collection with phase indexes and one design document per milestone, including architecture drawings and flowcharts.
5. Link shared specifications; write milestone implementation and test plans, deriving stable test cases and evidence requirements from the acceptance gate. Keep milestone-specific notes and tests with their milestone.
6. Implement, run software checks and applicable environment procedures, then record implementation evidence and an acceptance report with actual case results, cleanup, limitations and next work.
7. Update milestone status, the phase index, `PROJECT-STATUS.md` and requirement evidence together.
8. Check relative links after moving documents and remove obsolete duplicate copies.

## Copyable instruction for a project assistant

```text
Organize this project's documentation under docs/project/ using a requirement-to-milestone structure.
Create requirements.md, requirement-milestones.md, requirement-evidence.md and PROJECT-STATUS.md.
Use docs/project/PROJECT-STATUS.md for overall project status, including the last updated
date, current phase/milestone, completed and ongoing work, blockers or risks, and next steps.
Keep it current as project status changes and link to detailed milestone evidence.
Group milestones by phase: PH1/P1M01/, PH1/P1M02/, then PH2/P2M01/ when needed.
Give each phase and milestone a README.md.
Also create LLD-documents/ at the repository root, with a README.md and one folder per phase.
Give each LLD phase folder a README.md and one document per milestone, using lowercase
task IDs as filenames (for example PH1/p1-m01.md, p1-r01.md and p1-h01.md).
Cover every milestone in the selected delivery tracks. Explain the feature functionally
and technically, including components, dependencies, architecture drawings, flowcharts,
failure handling, acceptance gates and links to authoritative contracts and evidence.
Keep these design explanations aligned with plans and implementation records.
Each milestone must identify its requirements, prerequisites, acceptance gate,
relevant specifications, implementation status, evidence and remaining work.
For milestones needing detailed validation, create implementation-plan.md, test-plan.md,
implementation-evidence.md and testing/acceptance-report.md, plus reproducible execution
procedures under testing/. Derive stable test IDs from requirements and acceptance gates;
define prerequisites, procedures, expected results and required evidence before execution.
Record actual PASS/FAIL/SKIP/Not run results, artifact identities, evidence locations,
cleanup, qualifications and handoff. Preserve failed runs and distinguish software checks
from environment acceptance. Update status only after recording the acceptance decision.
Keep shared contracts in specifications/ and milestone-specific documents inside
their milestone folder. Retain architecture and phase plans as linked sources.
Preserve existing requirement/task IDs, historical evidence and skipped-check qualifications.
Update incoming links when moving files. Do not mark planned work as implemented.
```
