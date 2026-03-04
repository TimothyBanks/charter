# Charter Pitch Deck (a16z Version)

Date: 2026-03-02  
Audience: a16z crypto partners, platform team, and technical diligence reviewers  
Goal: secure a partner meeting and move into full diligence.

## 0) Deck Strategy

This deck is optimized for:
- venture-scale framing
- technical credibility backed by reproducible artifacts
- clear wedge and moat in institutional custody infrastructure

Core rule:
- lead with proof and operating model, then expand to market and scale.

## 1) Slide 1 - Title

Headline:
- `Charter: Compliance-First Custody Infrastructure Network`

Subheadline:
- `Deterministic policy enforcement and auditable controls for institutional digital asset operations`

Footer:
- founder name, contact, GitHub, date

## 2) Slide 2 - The Problem

Institutional custody is still stitched together from:
- private workflow systems
- fragmented approval tools
- compliance logs not anchored to canonical state

Result:
- control drift between policy and execution
- expensive reconciliation after incidents and audits
- weak shared evidence across custodians, exchanges, and regulators

Pointed line:
- institutions do not need another general-purpose chain; they need deterministic control rails.

## 3) Slide 3 - Why Now

Timing drivers:
- institutional digital asset participation continues to grow
- governance and compliance expectations are increasing
- current custody control stacks remain mostly off-chain and hard to verify externally

Thesis:
- this is the right cycle to standardize custody controls as protocol behavior.

## 4) Slide 4 - Solution

Charter is a custody-native, permissioned BFT network where policy checks are consensus-visible state transitions.

Current policy controls in protocol state:
- threshold approvals
- timelocks
- per-transaction limits
- destination allowlist requirements
- claim and attestation gating
- signer quarantine and degraded-mode controls
- jurisdiction metadata alignment checks

Privacy boundary:
- PII remains off-chain
- on-chain records store cryptographic references and evidence links

## 5) Slide 5 - Product Proof (What Exists Now)

Implemented PoC:
- deterministic execution engine
- RocksDB-backed state
- query surface for state, history, and events
- snapshot, backup, and replay support
- canonical golden workflow script and report artifacts

Diligence artifacts:
- `https://github.com/TimothyBanks/charter/tests/run_proof_first_demo.sh`
- `https://github.com/TimothyBanks/charter/doc/operations/golden_workflow_contract.md`
- `https://github.com/TimothyBanks/charter/doc/operations/error_codes_and_events_contract.md`
- `https://github.com/TimothyBanks/charter/doc/operations/query_and_keyspace_contract.md`

## 6) Slide 6 - Workflow Value (Wedge Use Case)

Beachhead:
- institutional treasury transfer governance

Workflow:
1. Intent is submitted with custody context and destination.
2. Charter enforces approvals, timing, limits, and compliance claims.
3. If checks pass, Charter records deterministic approval evidence.
4. Settlement attestation is anchored back into Charter state.

Outcome:
- a replayable and regulator-readable custody decision trail.

## 7) Slide 7 - Market and Buyer

Initial buyer profile:
- custodians
- exchanges with custody operations
- broker-dealers and fintech treasury teams

Land motion:
- one high-value workflow pilot

Expand motion:
- broader policy coverage
- multi-jurisdiction control profiles
- standardized evidence bundles for audits and partner reporting

Note for presenter:
- if asked for TAM, use externally sourced market references during live pitch and keep this slide focused on ICP and buying pain.

## 8) Slide 8 - Why Charter Wins

Differentiation:
- not a generic compute chain
- not only an off-chain policy SaaS
- custody policy and governance are first-class protocol semantics

Moat vectors:
- deterministic policy execution contract
- explicit tx failure taxonomy for integrations
- reproducible replay and evidence model
- compliance-first validator model (permissioned and accountable)

## 9) Slide 9 - Competition

Reference categories:
- institutional custody platforms with policy tooling
- bank-led blockchain rails
- adjacent custody-onchain or settlement ecosystems

Positioning line:
- Charter focuses on institutional custody governance as protocol state, with a narrower and more auditable product boundary.

Source doc:
- `https://github.com/TimothyBanks/charter/doc/strategy/competitive_matrix.md`

## 10) Slide 10 - Business Model

Phase 1:
- per-transaction protocol fees
- no mandatory token dependency for pilot utility

Phase 2:
- validator participation economics
- premium compliance/evidence services through ecosystem operators
- cross-chain indexing and settlement-attestation services

Design principle:
- align network revenue to real custody workflow usage, not speculative activity.

## 11) Slide 11 - Go-To-Market

12-month motion:
1. Sign 1-2 design partners.
2. Run one production-like pilot with objective acceptance criteria.
3. Convert pilot into repeatable integration package and control catalog.
4. Expand through institutional operator and validator partnerships.

Proof requirements for conversion:
- deterministic pass/fail workflow reports
- control-to-evidence mapping
- integration runbook and SLO expectations

## 12) Slide 12 - Team

Team credibility:
- 25+ years mission-critical distributed systems and C++ protocol engineering
- custody architecture leadership at Bullish (Block.one)
- PBFT/Autobahn and execution safety leadership at Somnia
- EOSIO protocol internals and determinism work

Custody-specific highlights:
- delivered MPC-signing-adjacent custody workflows under high-stakes deadlines
- redesigned custody smart contract architecture for long-term extensibility with near-zero post-launch defects
- patent-pending SQL-to-key-value semantic mapping used at Bullish to reduce blockchain integration time

## 13) Slide 13 - Milestones and Roadmap

Current:
- PoC running with canonical workflow and reproducible evidence scripts

Phase 1 (0-12 months):
- production hardening and external security review
- pilot launch with signed acceptance criteria
- validator onboarding standard and governance docs
- richer jurisdiction-aware policy packs
- observability and explorer/read API polish

Phase 2 (12-24 months):
- oracle/attestation network for external-chain settlement confirmation
- chain-indexing layer for policy-relevant transaction monitoring
- institutional read APIs and regulator evidence export bundles

Phase 3 (24+ months):
- broader custody workflow coverage beyond initial treasury transfer wedge
- mature validator economics and fee-governance controls
- ecosystem integrations with custodians, exchanges, and compliance providers

## 14) Slide 14 - Fundraise Ask

Round:
- `[target_raise_usd]` pre-seed/seed

Runway:
- `[18-24]` months

Use of proceeds:
- protocol hardening and security
- pilot integrations and solution engineering
- compliance/legal execution and operating structure
- validator and ecosystem onboarding

Milestone target by end of runway:
- at least one live institutional pilot converted to recurring production usage.

## 15) Appendix - Diligence Pack

Primary references:
- `https://github.com/TimothyBanks/charter/doc/protocol/one_pager.md`
- `https://github.com/TimothyBanks/charter/doc/protocol/lite_paper.md`
- `https://github.com/TimothyBanks/charter/doc/strategy/production_architecture.md`
- `https://github.com/TimothyBanks/charter/doc/strategy/licensing_strategy_us.md`
- `https://github.com/TimothyBanks/charter/doc/funding/sponsor_packet.md`
- `https://github.com/TimothyBanks/charter/doc/funding/funding_checklist.md`

## Presenter Notes (a16z-Specific)

Open with:
- why this is a category-defining infrastructure wedge, not just another chain.

Emphasize:
- institutional custody pain
- deterministic control semantics
- reproducible technical proof
- founder-market fit from custody and protocol delivery

Avoid:
- overclaiming regulatory outcomes
- leading with token design before pilot utility is demonstrated
- broad multi-vertical narratives before wedge dominance
- presenting oracle/indexing as prerequisite to the initial custody wedge

Close with:
- a direct diligence ask: technical review session plus pilot design-partner introduction support.
