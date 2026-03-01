# Charter Funding Deck (Draft v1)

Date: 2026-03-01  
Owner: Charter founding team  
Goal: secure design-partner pilots and pre-seed/seed funding based on verifiable PoC evidence.

## Deck Intent

Use this deck for:
- investor first meetings
- design-partner executive briefings
- strategic partner introductions

Target runtime: 15-20 minutes + 10 minutes Q&A.

## Slide 1: Title

Title:
- `Charter: Custody-Native Blockchain For Regulated Digital Asset Operations`

Subtitle:
- `Deterministic policy enforcement, auditable controls, and replayable evidence`

Presenter fields:
- name
- role
- date
- contact

## Slide 2: Problem

Core problem:
- institutional custody controls are usually enforced off-chain in private workflow systems.

Consequences:
- fragmented audit trails
- reconciliation overhead
- inconsistent control enforcement across operators
- weak shared evidence for regulators and counterparties

## Slide 3: Why Existing Approaches Fall Short

Current market baseline:
- governance and compliance checks often live outside consensus state.

Gap:
- critical controls are not deterministic ledger rules.

Observed pain:
- hard-to-prove policy adherence
- expensive manual compliance operations
- low portability of evidence between institutions/regulators

## Slide 4: Charter Solution

Thesis:
- make custody governance and compliance controls first-class protocol rules.

Protocol-level controls (current PoC):
- threshold approvals
- timelocks
- per-transaction limits
- destination whitelist requirements
- claim/attestation gating
- signer quarantine and degraded mode controls
- explicit workspace/vault jurisdiction context

## Slide 5: Product Proof (Current PoC)

What is implemented and tested:
- deterministic state machine with SCALE encoding
- RocksDB-backed state and query surface
- backup/snapshot/replay pathways
- canonical golden workflow script

Evidence artifacts:
- `tests/run_proof_first_demo.sh`
- `tests/proof_report_<timestamp>.txt`
- `doc/golden_workflow_contract.md`
- integration/unit test suite (`build.debug/charter_tests`)

## Slide 6: Why Now

Timing drivers:
- tighter institutional governance expectations
- growing need for machine-verifiable controls in custody flows
- demand for regulator-facing deterministic evidence, not only logs and attestations

Positioning:
- bridges operational compliance requirements with protocol determinism.

## Slide 7: Beachhead Market

Initial wedge:
- institutional treasury/custody operations for digital assets.

Ideal early adopters:
- mid-size funds
- OTC desks
- fintech treasury teams
- custody platform builders

Adoption entry point:
- pilot one high-value workflow (treasury transfer with policy controls).

## Slide 8: Go-To-Market

Motion:
- design-partner pilots first
- convert pilot controls into production integration roadmap

Near-term objectives:
- 1-2 signed design-partner LOIs
- 1 live pilot with defined acceptance criteria
- repeatable evidence bundle from pilot runs

## Slide 9: Business Model

Phase-1 model:
- protocol usage fees per governed transaction/event flow
- optional validator participation economics for network operators

Principle:
- no token dependency required for pilot traction.

## Slide 10: Roadmap

Current:
- CometBFT-backed PoC with frozen golden workflow contract.

Next:
- production architecture hardening
- richer jurisdiction-aware policy profiles
- pilot integration tooling and evidence bundle standardization

Longer term:
- consensus rail migration plan (while preserving state-machine semantics).

## Slide 11: Team and Execution

Message:
- principal-level engineering execution with working protocol artifacts.

Show:
- shipped milestones
- test coverage breadth
- operational rigor (contracts/docs/demo reproducibility)

## Slide 12: Funding Ask

Ask template:
- raise amount: `[target_raise_usd]`
- runway target: `[months]`
- milestone coverage: pilot launch + security hardening + production architecture prep

Use of proceeds (example split):
- protocol engineering and hardening
- security review/testing
- pilot delivery and integrations
- legal/compliance/governance framework

## Appendix A: Demo Contract Snapshot

Reference:
- `doc/golden_workflow_contract.md`

Current canonical expected tx denials/success paths include:
- `28` limit exceeded
- `29` destination not whitelisted
- `30` claim requirement unsatisfied
- `40` asset missing
- `41` asset disabled
- `42` jurisdiction mismatch (workspace/vault mismatch)

## Appendix B: Diligence Links

Primary docs:
- `doc/one_pager.md`
- `doc/funding_checklist.md`
- `doc/operation_happy_failure_paths.md`
- `doc/error_codes_and_events_contract.md`
- `doc/query_and_keyspace_contract.md`

## Presenter Notes (Use In Every Meeting)

1. Lead with proof artifacts, not architecture vision.
2. Keep wedge narrow: one workflow, one buyer, one measurable outcome.
3. Avoid overclaiming regulator outcomes; position as deterministic control substrate.
4. End with a specific next step:
   - investor: diligence package + follow-up partner meeting
   - design partner: scoped pilot statement of work
