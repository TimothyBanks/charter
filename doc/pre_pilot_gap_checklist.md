# Charter Pre-Pilot Gap Checklist

Version: 0.1
Date: March 1, 2026
Status: Working checklist (PoC -> pilot readiness)

## Purpose

This document separates:
- what is acceptable to leave incomplete in PoC
- what must be answered before pilot
- what almost certainly requires outside expert support

Use this as an execution tracker, not a vision document.

## Reality Check

It is normal for a PoC founder team to not have complete answers for:
- regulatory/legal structure
- validator licensing strategy and supervisory posture
- external security assurance
- production SLO/SLA operations model

The goal is not to have everything solved now. The goal is to make unknowns
explicit, assign owners, and convert them to concrete artifacts.

## Priority Matrix

| Gap Area | Current PoC Status | Needed Before Pilot | Needed Before Production | Likely External Help |
|---|---|---|---|---|
| Validator admission/removal policy | Not fully specified | Draft policy + evidence requirements | Formal governance controls and enforcement tooling | Governance advisor + counsel |
| Jurisdiction/licensing posture | Conceptual strategy exists | Activity-to-license matrix for initial jurisdictions | Ongoing licensing/compliance operations | Regulatory counsel |
| Fee/reward policy | Directional (tx-fee model) | Published fee formula and reward split | Parameter governance and periodic review | Tokenomics/market-structure advisor (optional) |
| Upgrade/rollback governance | High-level roadmap | Versioning and rollout/rollback process | Formal on-chain/off-chain change control | Protocol governance expert |
| Privacy/data classification | Partial | Public vs confidential data policy | Retention, redaction, disclosure workflows | Privacy/compliance architect |
| Key management baseline | Partial | HSM/MPC minimum controls | Attestation lifecycle and audits | Security architect + HSM/MPC SME |
| Incident response/runbooks | Partial | Core incident playbooks and owner matrix | Regular drills with measured outcomes | SRE/ops lead |
| SLO/SLA definition | Not formalized | Pilot SLOs (availability/finality/support) | Contractual SLAs and penalties | Ops lead + legal |
| Security assurance | Internal testing only | Scoped external review commitment/report | Recurring security program | External security firm |
| Regulator evidence packaging | Partial | Pilot evidence bundle template | Formal regulator-facing package and verifier tooling | Compliance/risk advisor |
| Explorer/read API ops | PoC routes exist | Stable read contract + indexer service | Production read API posture | Backend/platform engineer |
| Observability and alerting | Basic counters and routes | Prometheus/Grafana baseline + alerts | SLO-backed production monitoring | SRE/platform engineer |

## External Experts to Recruit First (Practical Order)

1. Regulatory counsel (US-first or primary launch jurisdiction)
2. Fractional compliance lead (CCO/MLRO profile depending on scope)
3. Security reviewer (crypto + application security)
4. Infrastructure/SRE advisor (devnet->pilot reliability)
5. Governance/legal structuring advisor (validator agreements and liability)

## Deliverables by Role

### Regulatory Counsel
- Activity-to-license matrix for target jurisdictions
- Permitted/prohibited operating model memo
- Validator licensing posture memo

### Compliance Lead
- Control mapping: policy checks -> evidence -> obligation
- Compliance operations playbook (onboarding, monitoring, escalation)
- Regulatory reporting requirements matrix

### Security Reviewer
- Threat model review with risk-ranked findings
- Priority remediation list and verification criteria
- Sign-off memo for pilot scope

### SRE/Platform
- Devnet/pilot deployment topology
- Monitoring and alert catalog
- Incident runbooks and escalation tree

### Governance/Legal Structuring
- Validator participation terms
- Liability/risk allocation model
- Change-control and emergency action governance memo

## Minimal Artifact Gate for Pilot

Do not start pilot conversations without these artifacts:
- Validator policy draft (admission/removal + obligations)
- Jurisdiction/licensing memo for target launch scope
- Fee/reward policy draft
- Incident runbook set (minimum viable)
- Monitoring dashboard + alert baseline
- External security review scope (scheduled or complete)

## Suggested Owner Template

Use this template for each gap:
- `Gap:`
- `Owner:`
- `Support:`
- `Target Date:`
- `Deliverable:`
- `Dependency:`
- `Status:`

## Two-Week Action Sprint (Starting Point)

Week 1:
- Lock target jurisdictions for first pilot.
- Engage regulatory counsel for activity/license scoping.
- Draft validator policy v0 and fee policy v0.

Week 2:
- Draft pilot SLOs and incident runbooks.
- Publish monitoring/alert baseline.
- Confirm security review scope and timeline.

## Related Docs

- `doc/lite_paper.md`
- `doc/production_architecture.md`
- `doc/funding_checklist.md`
- `doc/licensing_strategy_us.md`
