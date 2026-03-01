# Charter US Licensing Strategy (Draft v1)

Date: 2026-03-01  
Status: working draft for counsel review  
Scope: US-first operating model for licensed deployment of the Charter network.

## Important Note

This is not legal advice.  
It is a product and operating strategy draft to accelerate discussions with qualified regulatory counsel.

## Objective

Create a licensed operating model that:
- preserves deterministic on-chain policy enforcement,
- reduces compliance integration burden for customers,
- supports institutional and regulator trust in network operations.

## Core Strategy

Design principle:
- keep the protocol neutral,
- place regulated activity in licensed operator entities that run service gateways and/or validators.

Implication:
- licenses attach to legal entities and activities, not to protocol code alone.

## Activity To License Mapping (Initial Hypothesis)

| Activity | Likely US regulatory posture | Why it matters for Charter |
| --- | --- | --- |
| Accepting/transmitting convertible virtual currency for others | FinCEN MSB obligations and AML program controls; state money transmission analysis | Core for hosted transfer operations and customer-facing transaction services |
| Serving New York customers in covered virtual currency business activity | NYDFS BitLicense and/or NY limited purpose trust path (activity-dependent) | Needed for broad institutional coverage including NY entities |
| Qualified custody/trust-style operation model | State trust company or federal trust/bank pathway (fit depends on product scope) | Enables stronger custody positioning for institutional clients |
| Securities-related digital asset activity | SEC/FINRA-regulated pathways as applicable | Required if product scope includes securities custody/execution functions |

## Recommended Phased Sequence

### Phase 0: Counsel-Validated Scoping (0-60 days)

- Hire external US regulatory counsel (crypto payments + trust + securities crossover).
- Build a definitive activity inventory for:
  - what the operator entity does,
  - what counterparties do,
  - where funds/keys/control actually sit.
- Confirm jurisdictional go-to-market constraints (starting with NY policy decision).

Exit criteria:
- signed legal memo mapping activities to likely license obligations and exclusions.

### Phase 1: Pilot-Ready Compliance Baseline (60-180 days)

- Form operator legal entity strategy.
- Stand up baseline compliance program (BSA/AML governance, policies, controls, recordkeeping).
- Build licensing application plan:
  - state money transmission strategy,
  - New York route decision,
  - trust charter feasibility decision.

Exit criteria:
- pilot terms that match legal perimeter and compliance controls.

### Phase 2: Licensed Expansion (180+ days)

- Execute prioritized licensing sequence.
- Expand design-partner footprint within approved geographies and activities.
- Tie regulator-facing evidence bundle to production workflows.

Exit criteria:
- repeatable licensed operating posture for target customer segment.

## Organization Plan

Minimum compliance org for next stage:
- fractional CCO/compliance lead (immediate),
- external regulatory counsel (immediate),
- AML operations support (as pilot scope grows),
- audit/security partner support for control assurance.

## Product/Protocol Alignment

Keep these boundaries explicit:
- protocol controls:
  - policy enforcement (threshold/timelock/limits/claims/whitelist),
  - deterministic history and replay evidence,
  - explicit jurisdiction context in workspace/vault state.
- operator controls:
  - KYC/KYB onboarding,
  - sanctions screening operations,
  - suspicious activity processes,
  - licensing and supervisory reporting obligations.

## How This Reduces User Burden

If executed correctly, customers can rely on:
- pre-defined, audited control rails in the operator layer,
- deterministic proof artifacts from chain state,
- lower custom integration overhead for policy/governance controls.

Note:
- this reduces user effort, but does not eliminate each customer's own regulatory responsibilities.

## Immediate Next Actions (30 Days)

1. Finalize this draft with named counsel review comments.
2. Build a versioned activity inventory appendix.
3. Add licensing assumptions to investor and design-partner materials:
   - `doc/funding_deck.md`
   - `doc/sponsor_packet.md`
4. Add pilot contract language that matches legal perimeter.

## Open Questions For Counsel

1. Which specific operator activities trigger MSB/state MTL treatment in our exact flow?
2. Is New York entry best handled via BitLicense path, trust path, or staged deferral?
3. Which trust/bank charter options are realistically aligned with product scope and timeline?
4. At what point does securities regulation become implicated by planned features?
5. What customer disclosures and contractual controls are mandatory pre-pilot?

## Primary References (Checked 2026-03-01)

- FinCEN CVC guidance (2019): https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-certain-business-models
- NYDFS virtual currency licensing overview: https://www.dfs.ny.gov/virtual_currency_businesses
- OCC news release 2025-42: https://www.occ.treas.gov/news-issuances/news-releases/2025/nr-occ-2025-42.html
- OCC Interpretive Letter 1183 (2025): https://www.occ.treas.gov/topics/charters-and-licensing/interpretations-and-actions/2025/int1183.pdf
- Wyoming SPDI program overview: https://wyomingbankingdivision.wyo.gov/banks-and-trust-companies/special-purpose-depository-institutions
