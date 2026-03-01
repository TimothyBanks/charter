# Charter Production Architecture (CometBFT -> ConcordBFT)

## Context
CometBFT is used as a fast path to validate custody state-machine design. It is not the final consensus target.

Target end state:

- BFT consensus with a small vetted validator pool.
- Public-read ledger for transparent verification.
- Permissioned validator membership and write participation.

## Architecture Layers

1. **Application Layer (stable across consensus engines)**
   - Custody policy engine
   - Deterministic encoding/state transitions
   - Audit/replay/snapshot/export logic

2. **Consensus Integration Layer (replaceable)**
   - Current: ABCI integration with CometBFT
   - Target: adapter layer for ConcordBFT (or internal BFT module)

3. **Data Layer**
   - Deterministic key schema
   - Persistent state/history/snapshot artifacts
   - Backup/export and restore semantics

4. **Access Layer**
   - Institutional APIs
   - Regulator/auditor read interfaces
   - Monitoring and evidence export

## Migration Strategy

### Phase 0: PoC Hardening (now)
- Stabilize transaction schema and versioning policy.
- Keep consensus dependencies isolated behind engine-facing interfaces.
- Build compliance-oriented demo workflows and audit exports.

### Phase 1: Pilot Network (CometBFT)
- Vetted validator pilot with governance process.
- Freeze app semantics for pilot window.
- Collect latency, failure, and operator workload metrics.

### Phase 1.5: Public Devnet Preview (Pre-Funding Friendly)
- Run a small public devnet footprint (2 validators + 1 public RPC/read node).
- Publish explicit non-production terms:
  - resettable chain
  - no asset safety guarantees
  - no availability SLA
- Expose read-first surfaces for external evaluation:
  - explorer endpoints (`/explorer/overview`, `/explorer/block`, `/explorer/transaction`)
  - engine metrics endpoint (`/metrics/engine`)
- Stand up baseline Grafana/Prometheus pipeline using:
  - CometBFT node metrics
  - app-level metrics exported from engine query endpoint

### Phase 1.5 Owner Checklist (Infra You Need to Run)
- Devnet operations:
  - run at least 2 validator nodes + 1 public read/RPC node
  - define reset/restart process for devnet epochs
  - keep backup and restore drill for chain data
- Observability:
  - run Prometheus scrapes for CometBFT and `/metrics/engine`
  - publish Grafana dashboards for chain health and policy activity
  - add baseline alerts (node down, tx failure-rate spike, block stall)
- Explorer/read stack:
  - run an indexer that polls `/explorer/overview`, `/explorer/block`, and `/explorer/transaction`
  - expose a public read API and/or minimal UI for external evaluators
  - document reindex and data-retention behavior
- Ops/security baseline:
  - front public endpoints with TLS and basic rate-limiting
  - document runbooks for incident triage and service restarts
  - keep operator contact path for bug reports and abuse reports

### Infra Cost Reality (Free Software, Paid Operations)
- Free/open-source components:
  - CometBFT
  - Prometheus + Grafana OSS
  - explorer/indexer code you write
  - open-source DBs (SQLite/Postgres)
- Recurring paid costs for a public devnet:
  - compute for validator/read nodes
  - storage and backups
  - network egress/bandwidth
  - domain/TLS and uptime monitoring
  - optional managed services (hosted DB/monitoring)
- Practical expectation:
  - local/private demos can be near $0
  - public devnet normally has monthly cloud spend; budget this as pre-funding credibility infrastructure

### Phase 2: Consensus Abstraction
- Create explicit consensus adapter contract:
  - mempool check
  - proposal process/prepare
  - finalize/commit
  - snapshot/state sync interfaces
- Ensure engine has no Comet-specific logic.

### Phase 3: ConcordBFT Integration
- Implement adapter with same deterministic app behavior.
- Run replay-equivalence tests between Comet and Concord traces.
- Execute staged migration with validator overlap and rollback path.

### Phase 4: Mainnet Readiness
- Production governance/legal/security controls.
- External assessments.
- Regulator-facing operations and evidence tooling.

## Ten Production Gaps and Concrete Design Suggestions

1. **Privacy Model**
- Split data into:
  - public control events (safe for global visibility)
  - confidential payloads (encrypted blobs + hash refs on-chain)
- Add policy-level redaction class and data retention policy.
- Introduce proof artifacts so regulators can verify confidentiality-preserving claims.

2. **Identity and PKI**
- Define identity objects for:
  - institution
  - validator organization
  - operational signer roles
- Back identities with certs and key attestation records.
- Require revocation handling and periodic re-validation.

3. **Key Management Baseline**
- Require HSM/MPC controls for production signing.
- Define key ceremony controls:
  - generation
  - activation
  - rotation
  - emergency revocation
- Enforce minimal signer entropy and attestation evidence.

4. **Governance and Upgrade Model**
- Establish two governance tracks:
  - protocol governance (version/parameters)
  - operational governance (validator admissions/removals)
- Specify emergency controls with strict expiry and audit logging.
- Codify supermajority thresholds and quorum safety checks.

5. **Legal and Liability Structure**
- Define operator agreements for validator duties and availability.
- Clarify liability for downtime, censorship, and policy execution faults.
- Choose legal vehicle (foundation/company/SPV) and IP/control arrangements early.

6. **Regulator Access and Oversight**
- Build regulator-specific read APIs:
  - case-based query
  - institution-wide checks
  - deterministic replay output
- Provide signed evidence bundles that can be archived independently.
- Include service-level commitments for regulator response times.

7. **Incident Response and Business Continuity**
- Create operational runbooks:
  - validator compromise
  - consensus stalls
  - corrupted storage
  - key compromise
- Include communication matrices and severity levels.
- Test disaster recovery with regular game days.

8. **Security Program**
- Minimum program for production:
  - external security review
  - dependency governance
  - fuzz/invariant testing
  - secure build/release pipeline
- Add abuse scenarios specific to custody policy manipulation and replay.

9. **Consensus Migration Safety**
- Define replay-equivalence test harness:
  - same tx stream -> same state root history
- Version app state schema with migration tooling.
- Provide rollback mechanism for failed consensus cutovers.

10. **Economics and Validator Incentives**
- Define fee model and distribution:
  - validator rewards
  - treasury allocation
  - protocol maintenance allocation
- Add anti-centralization guardrails:
  - validator cap rules
  - concentration alerts
  - conflict-of-interest policy
- Keep tokenization optional until core utility and legal clarity exist.

11. **Observability and Explorer UX**
- Define a minimum app metrics contract (names, units, reset semantics).
- Provide a reference exporter that converts `/metrics/engine` into Prometheus series.
- Provide a lightweight explorer/indexer service that:
  - polls `/explorer/block`
  - stores normalized tx/event rows
  - serves a simple public read API
- Include dashboard and explorer links in every devnet release note.

## Recommended Deliverables Before Funding Roadshow

1. Production architecture and threat model docs.
2. Governance + validator policy draft.
3. Regulator evidence pack example.
4. Pilot economics model with sensitivity analysis.
5. Migration design memo (CometBFT -> ConcordBFT).

## Implementation Progress Snapshot (2026-02-27)

Completed in current PoC code:

- Core custody policy controls:
  - threshold approvals
  - timelock gating
  - per-transaction limit
  - destination whitelist gate
  - claim/attestation gate
- Extended controls:
  - role assignment state + role-based authz checks
  - signer quarantine controls
  - degraded mode controls
  - velocity-limit schema + counter state and enforcement
  - destination governance tx lifecycle (propose/approve/apply)
- Operational evidence:
  - persistent security event stream
  - replay/snapshot/backup flows
  - expanded query surface for governance and event state

Still required before serious pilot:

- fully scoped actor/SoD policy matrix and tests across all operation combinations
- formalized error/event contract freeze for integrators
- regulator evidence bundle schema with independent verifier workflow
- operator runbooks with measured RTO/RPO drill evidence
- public metrics + explorer stack with reproducible deploy artifacts
