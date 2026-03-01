# Charter Protocol Lite Paper

Version: 0.1 (PoC)
Date: March 1, 2026
Status: Working draft for technical and design-partner review

## Abstract

Charter is a custody-native protocol that moves institutional control logic from off-chain workflow systems into a deterministic, auditable state machine. Instead of treating policy checks as opaque middleware, Charter encodes approvals, timelocks, limits, destination controls, claims, and emergency controls directly in protocol state transitions.

The current implementation uses CometBFT + ABCI as a fast path for proof of concept. The core thesis is consensus-portable: the custody engine and schema remain stable while the consensus layer can evolve.

## 1. Problem

Institutional custody operations are usually split across multiple internal systems:
- policy engines
- workflow databases
- approval systems
- audit log pipelines

This fragmentation creates three failure modes:
- control drift between policy configuration and actual execution
- expensive reconciliation between systems after incidents or audits
- limited external verifiability for partners, regulators, and customers

## 2. Thesis

Custody should be a protocol-level state machine, not an application-side afterthought.

Charter makes:
- policy resolution deterministic
- enforcement replayable
- security events queryable
- state transitions portable across consensus backends

## 2.1 Category Thesis: Domain-Specific Protocols Expand Adoption

Charter is intentionally not a general-compute chain. It is a purpose-built
custody protocol. This is a design choice, not a limitation: specialized
protocols can accelerate real-world blockchain adoption by solving concrete,
high-friction workflows with clearer control and evidence models.

In this view, domain-specific protocols complement general L1s by:
- making blockchain utility legible to institutions through workflow-native
  guarantees
- reducing integration ambiguity for regulated onboarding and operations
- broadening the public understanding of what blockchain architectures can do

## 3. Design Goals

- Deterministic enforcement: same transaction sequence yields the same state root.
- Policy-first execution: risk and compliance controls gate value movement, not just reporting.
- Auditability by default: history, event streams, backup, replay, and snapshots are core paths.
- Permissioned operations with public-read transparency.
- Consensus abstraction: application semantics are not tied to one BFT implementation.

## 3.1 Consensus and Validator Operating Model (Intentional BFT Choice)

Charter intentionally uses a BFT model with a small, permissioned validator set.
The target is not a permissionless, high-throughput general-compute network. The
target is regulated custody coordination with strong finality and clear operator
accountability.

Design intent:
- Validator set remains curated and operationally vetted.
- Validator organizations are expected to operate under appropriate licensing
  posture for the jurisdictions they serve.
- Public-read access remains open, while write/finality participation is
  permissioned.

Economic intent:
- Protocol revenue is transaction-fee-based, not subscription-based.
- No mandatory monthly/yearly protocol license fee for customers is intended.
- Fees are targeted to remain as low as possible while funding validator
  operations, compliance overhead, and security posture.

Performance posture:
- Charter prioritizes control correctness, auditability, and deterministic
  governance over maximum TPS and minimum latency.
- Lower throughput targets reduce validator infrastructure pressure relative to
  high-performance generic L1 networks.

## 4. System Model

Charter models custody as scoped state:
- workspace: tenant boundary and top-level governance context
- vault: custody account/model boundary within workspace
- asset: onboarded instrument registry with enable/disable controls
- destination: transfer target metadata and governance state
- policy_set + active_policy_pointer: executable controls currently in force
- intent + approval: transfer lifecycle and approval evidence
- attestation_record: compliance claims used by policy checks
- role_assignment: scoped authorization and separation of duties
- signer_quarantine + degraded_mode: emergency containment controls

Key execution artifacts:
- transaction_result (write envelope)
- query_result (read envelope)
- history_entry (ordered replay source)
- security_event_record (risk/ops evidence stream)

## 5. Transaction Lifecycle

1. CheckTx validates transaction envelope, nonce, signer/signature compatibility, authorization preconditions, and policy gating prerequisites required at admission time.
2. PrepareProposal filters candidate mempool transactions under size and validity constraints.
3. ProcessProposal performs validator-side proposal verification.
4. FinalizeBlock executes transactions deterministically, emits per-transaction result/events, and computes post-block state root.
5. Commit persists finalized state metadata and snapshot progress.

In Charter terms, ABCI `app_hash` is treated as the application state root.

## 6. Policy Engine Semantics

Policy enforcement is operation-aware and scope-aware. For transfer workflows:
- threshold approvals enforce minimum sign-off count
- timelock enforces minimum wait before execution
- per-transaction limit caps nominal transfer amount
- destination rule can require whitelist enablement
- claim requirements gate execution on attestation presence/validity
- velocity limits cap cumulative transfer value in deterministic windows
- separation-of-duties prevents prohibited signer-role overlap

Merge behavior for overlapping policy rules is intentionally conservative:
- threshold: strictest count
- timelock: longest delay
- per-tx limit: tightest cap
- required claim set: union

## 7. Governance and Safety Controls

Governance paths include:
- create/activate policy sets
- staged destination update workflow (propose, approve, apply)
- role assignment updates

Safety paths include:
- signer quarantine to block suspicious operators
- degraded mode to restrict operational surface
- explicit error code taxonomy for control-plane outcomes
- security event stream for triage and evidence

## 8. Compliance and Jurisdiction Model

Charter currently supports jurisdiction as structured metadata attached to custody scope and validated in key flows (for example, workspace/vault consistency checks). This gives a base for jurisdiction-aware policy profiles and compliance routing without hard-coding one regulatory regime into consensus logic.

Near-term compliance extensions are expected to include:
- richer jurisdiction profile bundles
- regulator evidence bundle generation
- explicit control mapping from schema fields to regulatory obligations

## 9. Data Integrity, Recovery, and Evidence

Operational resilience features are first-class:
- backup export/import
- deterministic history replay
- snapshot list/offer/load/apply flows
- state root checkpointing

These paths allow:
- reproducible incident analysis
- chain-state recovery drills
- independent verification of custody transition history

## 10. Observability and Read Surface

Read endpoints expose:
- state queries (`/state/*`)
- history/event queries (`/history/*`, `/events/*`)
- explorer-oriented queries (`/explorer/overview`, `/explorer/block`, `/explorer/transaction`)
- metrics summary (`/metrics/engine`)

Intended deployment model:
- Prometheus/Grafana polling (passive metrics collection)
- lightweight indexer for explorer/read API UX
- no engine-side push dependency on dashboard infrastructure

## 11. Trust and Threat Assumptions

Charter assumes:
- vetted validator membership for write/finality participation
- deterministic application code at all validators
- hardened signer/key-management process outside protocol core

Charter does not yet claim:
- production-grade privacy guarantees for all metadata classes
- complete legal/licensing framework across jurisdictions
- full validator decentralization economics

## 12. Roadmap

PoC complete/near complete:
- custody state machine and workflow coverage
- deterministic execution and replay paths
- snapshots, backup/restore, and query contract
- observability and explorer read foundations

Next milestones:
- public devnet operations (validator/read nodes, reset policy, runbooks)
- observability hardening (alerts, dashboards, SLOs)
- explorer/indexer service for external evaluators
- formal governance and compliance evidence packs
- consensus abstraction toward production target
- close pre-pilot ownership gaps tracked in `doc/pre_pilot_gap_checklist.md`

## 13. Why This Can Matter

If successful, Charter reduces operational ambiguity in custody by making policy execution verifiable and replayable at the protocol level. The benefit is not only technical cleanliness; it is reduced compliance friction, clearer incident forensics, and stronger institutional trust boundaries.

## 14. Current Limitations

- PoC implementation prioritizes clarity and determinism over throughput tuning.
- Public infra posture (devnet reliability, monitoring, read UX) is still roadmap work.
- Compliance/legal packaging is in progress and requires domain-expert partnership.
- Cryptographic and security hardening for production remains a gated phase.

## 15. Conclusion

Charter is a practical attempt to treat custody controls as consensus-anchored protocol logic. The project demonstrates that institutional policy workflows can be encoded as deterministic state transitions with replayable evidence, while keeping a path open to evolve consensus and infrastructure over time.
