# Charter Funding Checklist (30/60/90 Days)

## Objective
Prepare Charter for:
- pre-seed/seed fundraising conversations
- design-partner pilots
- early regulator-facing diligence

## Principles
- Sell evidence, not promises.
- Keep scope tight around one beachhead market.
- Track readiness with objective artifacts.

## Locked Initial Wedge
- Primary segment: institutional treasury/custody operations for digital assets (mid-size funds, OTC desks, fintech treasury teams).
- Network framing: public-read, permissioned-write/validate.
- Initial economics: fee-per-transaction only; no token dependency for phase 1.
- Consensus strategy: CometBFT for pilot evidence, ConcordBFT/homegrown as production roadmap.

## Golden Workflow (What We Sell First)
- Treasury transfer request with policy controls:
- threshold approvals
- timelock delay
- transfer amount limit
- destination whitelist check
- compliance claim/attestation gate
- deterministic audit and replay evidence
- canonical acceptance contract: `doc/golden_workflow_contract.md`

## Branching Rule
- Do not expand to additional verticals until the wedge has:
- 2 signed design-partner LOIs
- 1 live pilot with measurable outcomes
- reproducible regulator-style evidence pack

## Day 0-30: Foundation and Story Discipline

### Product and Scope
- [ ] Lock the primary segment above and remove alternate narratives from pitch materials.
- [ ] Define one primary use case (golden workflow) and one fallback use case only.
- [ ] Freeze PoC feature scope for external demos.

### Technical Artifacts
- [ ] Publish `one_pager.md` and production architecture memo.
- [ ] Finalize deterministic workflow demo script (end-to-end).
- [ ] Freeze canonical workflow inputs/expected outputs/report schema in `doc/golden_workflow_contract.md`.
- [ ] Ensure replay/snapshot/backup flows are reproducible in demo environment.
- [ ] Publish API/query matrix and expected control outcomes.
- [ ] Add one scripted demo runbook that a non-author can execute.

### Compliance and Risk Narrative
- [ ] Draft controls mapping: policy control -> protocol behavior -> audit evidence.
- [ ] Draft trust model and assumptions (identity, keys, validator operations).
- [ ] Define what is public vs confidential data.
- [ ] Add plain-language statement: protocol reduces compliance burden, it does not replace institution-level obligations.
- [ ] Publish US-first licensing strategy draft in `doc/licensing_strategy_us.md`.
- [ ] Engage external regulatory counsel for activity scoping and licensing sequence review.
- [ ] Identify interim compliance owner (fractional CCO or equivalent).

### GTM and Outreach
- [ ] Prepare 2-3 outreach posts and direct intro message templates.
- [ ] Build target list:
- [ ] 20 design partners in the wedge segment
- [ ] 20 strategic investors with market-structure or compliance infra focus
- [ ] 10 regulatory/policy advisors

## Day 31-60: Proof and Pilot Readiness

### Product Proof
- [ ] Run 3 repeatable demos with third-party observers.
- [ ] Add negative-path demos:
  - [ ] limit rejection
  - [ ] whitelist rejection
  - [ ] missing-claim rejection
- [ ] Produce exported audit bundle from each run.

### Reliability and Security Baseline
- [ ] Add regression suite for policy logic and replay behavior.
- [ ] Run basic adversarial tests and failure-injection scenarios.
- [ ] Commission scoped external security review (or secure written commitment).

### Governance and Economics
- [ ] Draft validator admission/removal policy.
- [ ] Draft fee and validator reward policy.
- [ ] Draft conflict-of-interest and concentration policy.
- [ ] Draft initial service-level expectations for validators (availability, incident response windows).

### Legal and Operating Structure
- [ ] Decide legal vehicle and ownership structure for protocol operations.
- [ ] Draft validator terms and pilot terms.
- [ ] Draft risk disclosures for partners/investors.
- [ ] Define target licensed-operator model (who holds which licenses).
- [ ] Complete preliminary activity-to-license matrix validation with counsel.

## Day 61-90: Fundraise and Pilot Execution

### Funding Materials
- [ ] Build investor deck:
- [ ] problem and market (wedge-first)
- [ ] why now
- [ ] product proof
- [ ] architecture roadmap (Comet -> Concord/homegrown)
- [ ] economics and moat
- [ ] team and execution plan
- [ ] Keep `doc/funding_deck.md` updated as the canonical deck draft.
- [ ] Keep `doc/sponsor_packet.md` updated as the canonical diligence packet structure.
- [ ] Build data room:
- [ ] product docs
- [ ] architecture/security docs
- [ ] demo evidence
- [ ] legal/corporate docs

### Pilot Launch
- [ ] Sign at least 1 design-partner LOI.
- [ ] Start pilot with clear acceptance criteria and timeline.
- [ ] Produce pilot scorecard with measurable outcomes.
- [ ] Define expansion criteria from wedge into next segment.

### Regulatory Engagement Prep
- [ ] Build regulator briefing packet:
- [ ] network model
- [ ] validator controls
- [ ] audit/replay evidence flow
- [ ] incident response model
- [ ] licensing and supervision model by operating entity
- [ ] Run one mock regulator walkthrough.

## KPI Targets (By Day 90)

- [ ] 1-2 signed design-partner LOIs
- [ ] 5+ serious investor conversations
- [ ] 1 external security assessment started/completed
- [ ] 1 pilot running with objective metrics
- [ ] complete data room and diligence checklist

## Funding Readiness Gate

Only start broad fundraising when all are true:
- [ ] demo is deterministic and repeatable by non-authors
- [ ] policy controls verified with test evidence
- [ ] architecture roadmap and migration plan documented
- [ ] legal/governance model is coherent
- [ ] licensing strategy is reviewed by counsel and mapped to go-to-market phase
- [ ] one customer segment and one primary narrative are locked

## Common Failure Modes to Avoid

- [ ] Overpromising regulator outcomes.
- [ ] Mixing “public chain” and “permissioned validators” without clear model language.
- [ ] Introducing token complexity before utility and legal clarity.
- [ ] Pitching too many verticals at once.
- [ ] Selling architecture without operating model and governance detail.
- [ ] Switching target segment before collecting wedge-level evidence.
