# Charter Sponsor Packet (Draft v1)

Date: 2026-03-01  
Audience: investors, design partners, strategic sponsors  
Purpose: provide a concise diligence packet tied to reproducible PoC evidence.

## Packet Goals

This packet should let a reviewer answer:
- what problem Charter solves
- what is already proven in code
- what funding/sponsorship accelerates next
- what a pilot engagement looks like

## Packet Contents

### 1) Executive Summary

Use:
- `doc/one_pager.md`

Key message:
- custody controls are deterministic protocol behavior, not off-chain workflow assumptions.

### 2) Product Proof

Use:
- `doc/golden_workflow_contract.md`
- `tests/run_proof_first_demo.sh`
- latest `tests/proof_report_<timestamp>.txt`

Reviewer expectations:
- canonical workflow is repeatable
- expected tx codes and query assertions are explicit
- report format has pass/fail contract

### 3) Technical Contract Surface

Use:
- `doc/error_codes_and_events_contract.md`
- `doc/query_and_keyspace_contract.md`
- `doc/operation_happy_failure_paths.md`

Reviewer expectations:
- stable tx/query/event semantics
- deterministic failure behavior
- clear mapping from operation to state mutation

### 4) Architecture and Roadmap

Use:
- `doc/production_architecture.md`
- `doc/schema-definition.md`
- `doc/workflow_playbooks.md`

Reviewer expectations:
- clear path from PoC to production
- known gaps and explicit sequencing
- incident/governance considerations documented

### 5) Funding and Execution Plan

Use:
- `doc/funding_checklist.md`
- `doc/funding_deck.md`

Reviewer expectations:
- concrete 30/60/90 plan
- realistic milestone-based capital use
- clear go/no-go gates

### 6) Regulatory And Licensing Plan (US-First)

Use:
- `doc/licensing_strategy_us.md`

Reviewer expectations:
- clear activity-to-license mapping
- explicit legal/compliance ownership model
- phased licensing sequence tied to product rollout
- clear statement of what is implemented now vs what is counsel-dependent

## Recommended Packet Order (What To Send)

1. `doc/one_pager.md`
2. `doc/funding_deck.md`
3. `doc/golden_workflow_contract.md`
4. latest `tests/proof_report_<timestamp>.txt`
5. `doc/error_codes_and_events_contract.md`
6. `doc/query_and_keyspace_contract.md`
7. `doc/licensing_strategy_us.md`
8. `doc/funding_checklist.md`

## Suggested Cover Email Text

Subject:
- `Charter PoC diligence packet: custody-native policy enforcement`

Body:
- We built a custody-native blockchain PoC where institutional controls are deterministic state-machine rules.
- Attached is a short packet with:
  - product summary,
  - canonical workflow contract,
  - latest proof report,
  - error/query contracts, and
  - funding/pilot plan.
- If useful, we can run a live 30-minute walkthrough of the golden workflow and then scope a design-partner pilot.

## Design-Partner Offer Structure (Template)

Pilot objective:
- validate one treasury transfer workflow under policy controls and evidence requirements.

Pilot scope:
- environment setup
- scripted golden workflow runs
- control mapping and evidence review
- gap report and next-phase plan

Pilot deliverables:
- signed acceptance criteria
- run reports and artifacts
- integration notes
- recommended production hardening backlog
- regulatory readiness memo (controls mapping + licensing path assumptions)

Pilot timeline:
- 4-8 weeks (depending on partner integration depth)

## Diligence Q&A Prompts (Prepare In Advance)

- Which controls are enforced on-chain vs off-chain?
- How are tx failures standardized for integrators?
- How is replay/snapshot safety validated?
- How does jurisdiction context currently work?
- Which legal entities hold which licenses and in what sequence?
- Which controls are protocol-enforced vs operator policy controls?
- What is implemented now vs roadmap only?
- What security review plan is in place pre-production?

## Readiness Checklist Before Sending Packet

- [ ] latest `charter_tests` run passed
- [ ] latest proof script run produced `PASS`
- [ ] referenced report file exists and is included
- [ ] doc links and filenames are current
- [ ] roadmap/funding ask values are updated for current quarter
- [ ] compliance lead and external regulatory counsel identified

## Next-Step CTAs

Investor CTA:
- schedule a technical diligence session with protocol walk-through.

Design-partner CTA:
- schedule pilot scoping workshop with acceptance criteria and timeline.

Strategic sponsor CTA:
- discuss co-development scope plus potential validator participation terms.
