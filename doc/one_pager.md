# Charter: Custody-Native BFT Protocol (One Pager)

## Problem
Institutional custody workflows are usually enforced off-chain in internal systems. That creates fragmented audit trails, reconciliation overhead, and trust assumptions around private record keeping.

## Thesis
Make custody policy execution a deterministic, auditable protocol function:

- Threshold approvals, timelocks, limits, whitelists, and claims are state-machine rules.
- Ledger state is the canonical source of truth for custody governance.
- Validators run BFT consensus with vetted participants and public-read transparency.

## Product Direction

- **Current PoC rail**: CometBFT-backed ABCI app to move quickly.
- **Production rail**: ConcordBFT (or custom BFT stack) with retained state-machine semantics.
- **Network model**: public-read, permissioned-write/validate.
- **Commercial model**: per-transaction protocol fees; validator reward distribution; no enterprise license lock-in.

## Why This Matters

- Reduces reliance on opaque third-party workflow databases.
- Gives institutions deterministic control enforcement and replayable history.
- Gives regulators verifiable audit access to canonical data.

## What Exists in PoC

- Custody workflow state machine
- Policy activation and intent lifecycle
- Threshold/timelock enforcement
- Per-tx limits and destination whitelist enforcement
- Claim/attestation gating
- Snapshot/backup/replay paths
- Query endpoints and integration tests

## What Production Requires (10 Critical Areas + Proposed Approach)

1. **Privacy model**
   - Keep policy outcomes public; keep sensitive metadata encrypted/off-chain.
   - Use hash commitments and selective disclosure proofs for regulator review.

2. **Identity + PKI**
   - Use institutional identity registry with key attestation and rotation history.
   - Bind validator/operator identities to legal entities and cert chains.

3. **Key management standard**
   - Define minimum HSM/MPC controls, quorum signing rules, and emergency key rotation.
   - Require periodic attestation that signer keys meet policy baseline.

4. **Governance model**
   - Formalize protocol change process, emergency controls, and quorum thresholds.
   - Publish governance charter with upgrade policy and rollback criteria.

5. **Legal/liability framework**
   - Create operating entity/foundation model and explicit liability boundaries.
   - Define validator obligations, indemnities, and insurance expectations.

6. **Regulator access model**
   - Provide regulator APIs + audit bundles + deterministic replay tooling.
   - Standardize evidentiary exports and timestamped custody event trails.

7. **Incident response**
   - Define playbooks for validator compromise, chain halt, and state recovery.
   - Include incident communications policy and postmortem requirements.

8. **Security program**
   - External audits, fuzzing, adversarial simulations, and dependency risk process.
   - Move toward SOC2/ISO controls for operations and software lifecycle.

9. **Consensus migration plan**
   - Keep deterministic app semantics stable while swapping consensus layer.
   - Publish compatibility constraints and migration checkpoints (PoC -> pilot -> mainnet).

10. **Economic policy**
   - Transparent fee schedule, reward distribution, treasury policy, and reserve policy.
   - Avoid speculative token coupling until core network utility is proven.

## Near-Term Milestones

1. Finalize custody control mappings to policy engine behavior.
2. Publish production architecture and threat model.
3. Complete validator governance/economics draft.
4. Run design-partner pilot with reproducible regulator-facing demo.
