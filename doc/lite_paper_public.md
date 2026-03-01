# Charter Protocol Public Lite Paper

Version: 0.1 (Public)
Date: March 1, 2026
Status: Public summary for ecosystem, partners, and design-partner discussions

## Public Scope Notice

This document is intentionally high level. It describes Charter's architecture,
goals, and operating model without publishing sensitive operational detail.

## Abstract

Charter is a custody-native blockchain protocol for regulated digital asset
operations. Instead of pushing governance and compliance controls to off-chain
workflow systems, Charter encodes them into deterministic state transitions that
can be audited and replayed.

The objective is practical adoption: make blockchain useful for real custody
operations by focusing on control correctness, accountability, and evidence.

## 1. Problem

Institutional custody processes are often fragmented across separate systems for
approvals, policy checks, and reporting. That creates operational friction and
weakens verifiability.

Charter addresses this by making custody control logic part of the protocol.

## 2. Category Thesis

Charter is intentionally not a general-compute chain. It is a domain-specific
protocol for custody workflows.

Specialized protocols can expand blockchain adoption by solving concrete,
high-friction industry workflows with clearer guarantees and cleaner operating
models.

## 3. Design Goals

- Deterministic policy enforcement.
- Replayable and auditable transaction history.
- Permissioned write/finality with public-read transparency.
- Consensus-portable application layer.
- Low-friction integration for regulated operators.

## 4. Intentional Consensus Choice

Charter uses a BFT model with a curated validator set by design.

Why this model:
- clear operator accountability
- predictable governance for regulated workflows
- strong finality characteristics for custody state transitions

Target network profile:
- permissioned validators
- public-read access for transparency
- operational focus on control integrity over raw throughput competition

## 5. Economic Model (Design Intent)

- Transaction-fee-based economics.
- No mandatory subscription-style protocol fee in baseline model.
- Fees targeted to remain low while supporting validator operations and network
  reliability.

## 6. Workflow Focus

Charter centers on practical custody workflows such as:
- workspace and vault onboarding
- policy-managed transfer intent lifecycle
- approval and timelock controls
- destination and compliance gating
- emergency controls and operational evidence

## 7. Architecture Summary

The architecture separates:
- application/state-machine semantics
- consensus integration
- persistent data and audit surfaces
- read and observability interfaces

This separation is intended to preserve deterministic behavior while allowing
consensus and infrastructure evolution over time.

## 8. Current Status

Current stage: Proof of Concept.

Implemented at PoC level:
- custody workflow state machine
- deterministic execution and replay paths
- backup/snapshot primitives
- read/query and observability foundations

## 9. Roadmap Themes

Next themes include:
- public devnet operations
- observability and explorer-read experience
- governance and compliance packaging
- production hardening and external review
- partner-driven pilot execution

## 10. What Charter Is Not

- Not positioned as a generic smart-contract execution race.
- Not positioned as a speculative throughput-first chain.
- Not claiming production-readiness in current PoC state.

## 11. Collaboration

Charter is actively seeking:
- design partners for custody workflow pilots
- compliance and regulatory domain collaborators
- infrastructure and operations partners

## 12. Conclusion

Charter's core bet is that custody controls should be protocol-native,
deterministic, and verifiable. By focusing on real institutional workflows,
Charter aims to broaden practical blockchain adoption beyond generic chain
templates.

## License

Charter is currently released under a proprietary license.
