# Charter Engine Policy Rules And Failure Matrix

Date: 2026-02-27
Scope: current behavior in `src/execution/engine.cpp` and related schema/types.

## 1. Transaction Lifecycle (What Is Checked, In Order)

1. `check_tx` / `process_proposal_tx`
- Decode SCALE transaction bytes.
- Run `validate_tx`.
- Reject early if any global validation fails.

2. `finalize_block`
- Decode each tx.
- Run `validate_tx` with per-signer expected nonce tracking for the block.
- If valid, run payload-specific `execute_operation`.
- Persist every tx into history as `(code, raw_tx)` under `SYS|HISTORY|TX|...` (success and failure).
- Update nonce and app hash only for successful txs (`code == 0`).

3. `commit`
- Persist committed `(height, app_hash)`.
- Create snapshot when due (`height % snapshot_interval == 0`, interval non-zero).

## 2. Global Validation Rules (All Payloads)

Applied by `validate_tx` before payload execution:

- `version` must be `1` -> fail `code=2`
- `chain_id` must match engine chain id -> fail `code=3`
- signer/signature variant compatibility must hold -> fail `code=5`
- cryptographic signature verification must pass -> fail `code=6`
- nonce must match expected nonce -> fail `code=4`

Decode failure at envelope level:
- tx bytes not decodable -> fail `code=1`

Notes:
- Codespace varies by phase: `charter.checktx`, `charter.proposal`, `charter.finalize`, `charter.execute`.
- All tx failures are logged with `spdlog::error` by `make_error_tx_result`.

## 3. Custody Workflow Rules By Step

## 3.1 Workspace bootstrap

### `create_workspace`
- Must not already exist.
- Fails:
  - `10` workspace already exists

### `create_vault`
- Workspace must exist first.
- Vault id must be unique within workspace.
- Fails:
  - `11` workspace missing
  - `12` vault already exists

### `upsert_destination`
- Workspace must exist.
- Upserts destination state (`enabled` drives whitelist behavior).
- Fails:
  - `11` workspace missing

## 3.2 Policy setup and activation

### `create_policy_set`
- Policy scope target must exist:
  - workspace scope => workspace exists
  - vault scope => workspace and vault exist
- `(policy_set_id, policy_version)` must be unique.
- Fails:
  - `13` policy scope missing
  - `14` policy set already exists

### `activate_policy_set`
- Scope target must exist.
- Referenced policy set/version must exist.
- Stores active pointer by scope.
- Fails:
  - `13` policy scope missing
  - `15` policy set missing

## 3.3 Intent lifecycle

### `propose_intent`
- Workspace and vault must exist.
- Active policy must exist on vault scope.
- Intent id must be unique.
- Policy resolution must succeed (active pointer and policy row must both resolve).
- Transfer-specific policy checks at proposal time:
  - per-transaction limit enforced -> fail if amount exceeds limit
  - destination whitelist enforced -> fail if destination not enabled
- Intent state initialized with:
  - `required_threshold`
  - `not_before` from timelock
  - resolved claim requirements
- Fails:
  - `16` vault scope missing
  - `17` active policy missing
  - `19` intent already exists
  - `20` policy resolution failed
  - `28` limit exceeded
  - `29` destination not whitelisted

### `approve_intent`
- Workspace/vault must exist.
- Intent must exist.
- Intent cannot already be finalized (`executed`/`cancelled`).
- If expired at approval time:
  - intent status is set to `expired`
  - approval rejected
- Signer can approve only once.
- Approval increments `approvals_count`; status moves to `executable` only when:
  - `approvals_count >= required_threshold`
  - current time >= `not_before`
- Fails:
  - `16` vault scope missing
  - `21` intent missing
  - `22` intent not approvable
  - `23` intent expired
  - `24` duplicate approval

### `cancel_intent`
- Workspace/vault must exist.
- Intent must exist.
- Executed intent cannot be cancelled.
- Fails:
  - `16` vault scope missing
  - `21` intent missing
  - `25` intent already executed

### `execute_intent`
- Workspace/vault must exist.
- Intent must exist.
- If expired at execution time:
  - intent status set to `expired`
  - execution rejected
- Execution requires:
  - approvals threshold met
  - timelock matured (`now >= not_before`)
  - every claim requirement satisfied by active, unexpired attestation
- Fails:
  - `16` vault scope missing
  - `21` intent missing
  - `23` intent expired
  - `26` intent not executable (threshold/timelock)
  - `30` claim requirement unsatisfied

## 3.4 Attestation lifecycle

### `upsert_attestation`
- Workspace must exist.
- Creates/updates attestation record with status `active`.
- Fails:
  - `18` workspace missing

### `revoke_attestation`
- Workspace must exist.
- Target attestation must exist.
- Sets status to `revoked`.
- Fails:
  - `18` workspace missing
  - `27` attestation missing

## 4. Tx Failure Code Catalog

- `1` invalid transaction (decode failed)
- `2` unsupported transaction version
- `3` invalid chain id
- `4` invalid nonce
- `5` invalid signature type (variant mismatch)
- `6` signature verification failed
- `10` workspace already exists
- `11` workspace missing
- `12` vault already exists
- `13` policy scope missing
- `14` policy set already exists
- `15` policy set missing
- `16` vault scope missing
- `17` active policy missing
- `18` workspace missing (attestation path)
- `19` intent already exists
- `20` policy resolution failed
- `21` intent missing
- `22` intent not approvable
- `23` intent expired
- `24` duplicate approval
- `25` intent already executed
- `26` intent not executable
- `27` attestation missing
- `28` limit exceeded
- `29` destination not whitelisted
- `30` claim requirement unsatisfied

## 5. Security Events Vs Audit Events

## 5.1 Security-Critical (Process-Terminating) Events

These call `charter::common::critical(...)` (critical log, shutdown, `SIGTERM`, terminate):
- strict crypto required but OpenSSL backend unavailable at engine startup
- RocksDB open/read/write/metadata persistence hard failures
- SCALE encode/decode hard failures in strict paths

Operational meaning:
- Node should be treated as failed-stop and restarted under incident procedure.

## 5.2 Security-Relevant Warning/Error Events (Non-Terminating)

- Tx validation/execution failures (`make_error_tx_result`) -> `spdlog::error`
- Query decode/path failures (`make_error_query_result`) -> `spdlog::error`
- Snapshot validation rejects (format/chunk count/hash/sender issues) -> `spdlog::warn`
- Snapshot restore decode failure -> `spdlog::error`
- Replay checkpoint mismatch -> `spdlog::warn` and replay result carries error text

## 5.3 Audit Events You Can Reliably Use Today

- Every finalized tx is recorded in history with tx code and raw tx bytes.
- Query endpoints expose:
  - state objects (`/state/*`)
  - history slices (`/history/range`)
  - full export bundle (`/history/export`)
- Backup/export includes:
  - committed state marker
  - state KV rows
  - tx history rows
  - snapshot metadata/chunks
  - chain id

## 6. Notes For Policy Authors

- Rules are enforced on operation type; current intent action mapping is transfer-focused.
- For transfer rules:
  - strictest per-tx limit wins (minimum limit)
  - whitelist requirement is OR-combined across matched rules
  - threshold and delay are effectively maxed across matched rule fragments
- Claim requirements are stored onto the intent at proposal time and evaluated at execution time.

## 7. Suggested Next Additions (Pragmatic)

1. Add explicit actor authorization checks for each operation (admin/operator role model).
2. Add explicit security/audit event emission object (not only logs), persisted as queryable event rows.
3. Freeze and publish a stable error-code contract in public docs for client integrators.

## 8. Expanded Policy Catalog (Fireblocks-Like Model)

Note: this is an implementation-oriented policy catalog based on common institutional custody controls. It is not a claim about proprietary internals.

### 8.1 Identity and actor controls

- Role-based initiator permissions (who can propose by workspace/vault/asset)
  - Status: partially present (role assignments + policy roles are enforced for tx paths; asset-specific role tiering remains missing)
- Approver set constraints by role tier (ops/compliance/risk)
  - Status: partially present (threshold exists; role model missing)
- Break-glass roles with explicit emergency policy path
  - Status: missing

### 8.2 Approval controls

- M-of-N threshold approvals
  - Status: implemented
- Threshold tiers by amount bands
  - Status: missing
- Threshold tiers by destination risk class
  - Status: missing
- Prohibit self-approval by proposer
  - Status: implemented (SoD rule path with `code=35`)

### 8.3 Time controls

- Timelock before execution
  - Status: implemented
- Business-hours-only execution windows
  - Status: missing
- Cooling-off window after destination changes
  - Status: missing

### 8.4 Spend controls

- Per-transaction amount limit
  - Status: implemented
- Daily/weekly/monthly cumulative spend velocity limits
  - Status: implemented (velocity rules + counters with deny `code=34`)
- Per-asset and per-chain limit profiles
  - Status: missing

### 8.5 Destination controls

- Destination whitelist required
  - Status: implemented
- Destination allow/deny list with reason and owner metadata
  - Status: partially present (enabled flag exists; metadata governance missing)
- Destination approval workflow (add/edit/remove needs approvals + delay)
  - Status: implemented (propose/approve/apply destination update flow; `codes=36..39`)

### 8.6 Compliance/claims controls

- Required claims for execution (KYB/sanctions/travel-rule/risk-approved)
  - Status: implemented
- Trusted issuer constraints per claim
  - Status: schema present, not fully exercised by tx path
- Minimum validity horizon (`minimum_valid_until`)
  - Status: schema present, not fully exercised by tx path

### 8.7 Transaction-type controls

- Policy by operation type (transfer, etc.)
  - Status: implemented (currently transfer-oriented)
- Policy by destination type (address vs contract)
  - Status: missing
- Policy by contract interaction method selector
  - Status: missing

### 8.8 Vault/workspace governance

- Workspace-level baseline policy with vault-level override
  - Status: partially present (scopes exist; merge/precedence model limited)
- Policy version governance with staged activation and rollback
  - Status: partially present (versioning exists; staged rollout missing)
- Dual-control for policy activation
  - Status: missing

### 8.9 Security controls and detections

- Explicit anomaly flags (nonce gaps, sudden spend spikes, new destination + high value)
  - Status: missing
- Tamper-evident audit events (security-event stream)
  - Status: implemented (`security_event_record_t` persistence + `/events/range`)
- Replay safety checks as alertable event class
  - Status: partially present (warning log exists)

### 8.10 Operations controls

- Snapshot/backup restore authorization policy
  - Status: missing
- Peer/source allowlist for snapshot chunk sender
  - Status: missing (only non-empty sender check exists)
- Restore replay requirement before node becomes active
  - Status: missing

## 9. Source-To-Control Mapping

Use this section as a practical ingest point: each source family maps to implementable protocol controls and customer-facing selling points.

### 9.1 Custody Platform Patterns (Feature Parity Targets)

Sources to ingest:
- Fireblocks policy engine and transaction authorization docs
- Fireblocks whitelist / travel-rule policy docs
- BitGo policy and wallet control docs

Controls to map into protocol:
- initiator/approver role matrix by workspace/vault
- amount-tiered approval thresholds
- destination governance workflow (add/remove/approve/delay)
- policy-based tx simulation and pre-check outcome transparency
- travel-rule and sanctions gating at execution time

Selling points unlocked:
- "institution-style policy guardrails, but on-chain and auditable"
- "platform parity without closed vendor lock-in"

Current status in Charter:
- implemented: threshold, timelock, per-tx limit, destination whitelist gate, claims gate
- missing: actor role matrix, amount-tiered thresholds, destination governance workflow

### 9.2 Security Standards (Assurance Targets)

Sources to ingest:
- CCSS control families
- NIST CSF 2.0
- ISO 27001/27002 control catalog

Controls to map into protocol/operations:
- signer key lifecycle attestation (generation, custody, rotation, revocation)
- mandatory dual-control for high-risk actions (policy updates, restore, emergency controls)
- security event taxonomy with immutable event persistence
- key and validator operational evidence exports for audits

Selling points unlocked:
- "provable control implementation, not just policy documents"
- "audit-ready evidence package from canonical ledger state"

Current status in Charter:
- partial: cryptographic verification path, deterministic tx history, export/replay
- missing: role-governed emergency operations hardening and key lifecycle policy objects

### 9.3 AML/Travel-Rule/Regulatory Expectations (Licensing Readiness)

Sources to ingest:
- FATF virtual asset guidance and updates
- jurisdiction-specific crypto AML regimes (e.g., FCA/FinCEN/EU)
- MiCA/CASP operational obligations

Controls to map into protocol:
- counterparty identity claim requirements by policy scope
- jurisdictional policy profiles (per-region control bundles)
- configurable "block/hold/review" outcomes (not only allow/deny)
- regulator query/report bundles with deterministic replay references

Selling points unlocked:
- "compliance controls are first-class protocol behavior"
- "regulator verification can be performed directly against mainnet state"

Current status in Charter:
- implemented: claim requirement gate and attestation lifecycle
- missing: jurisdiction profiles, review-state outcomes, regulator-specific report profiles

### 9.4 Institutional Treasury / Ops Reality (Adoption Readiness)

Sources to ingest:
- treasury operating procedures from design partners
- SOC2-style incident/ops playbooks
- internal audit evidence requirements from target institutions

Controls to map into protocol:
- business-hour and holiday execution windows
- cumulative velocity limits (daily/weekly/monthly)
- anomaly/risk scoring hooks for intents
- mandatory post-incident replay and checkpoint verification

Selling points unlocked:
- "fits existing treasury risk processes"
- "operations and compliance teams can validate outcomes independently"

Current status in Charter:
- partial: timelock and replay checkpoint warning
- missing: business windows, cumulative limits, risk scoring hooks, enforced restore/replay SOP

## 10. Enrichment Backlog (Prioritized)

1. Add actor authorization model (initiator/approver/admin roles) and enforce in each operation path.
2. Add destination governance workflow tx types (propose destination, approve destination, activate after delay).
3. Add cumulative spend limits (per asset, per window) with deterministic counters.
4. Add explicit security/audit event records in storage plus query path `/events/range`.
5. Add policy profiles by jurisdiction (claim bundles + destination constraints + threshold templates).
6. Add regulator export schema v1 with reproducible replay references and signed manifest hash.

## 11. GitHub Issue Pack (Copy/Paste Ready)

Use one issue per item below.

### 11.1 `feat(policy): actor authorization model and enforcement`

- Type: Feature
- Priority: P0
- Sprint: S1
- Problem:
  - Policy checks exist, but actor-role authorization is not enforced per operation.
- Scope:
  - add role model for workspace/vault (`initiator`, `approver`, `admin`)
  - enforce role checks in `create_policy_set`, `activate_policy_set`, `propose_intent`, `approve_intent`, `execute_intent`, attestation ops
  - add deterministic storage/query for role assignments
- Acceptance criteria:
  - unauthorized actor attempts fail with explicit code and codespace
  - unit/integration tests cover authorized and unauthorized paths
  - docs include role matrix by operation
- Deliverables:
  - schema updates, engine enforcement, tests, doc update

### 11.2 `feat(destination): governance workflow for whitelist entries`

- Type: Feature
- Priority: P0
- Sprint: S1
- Problem:
  - destination upsert is direct; no approval/timelock governance flow for destination changes.
- Scope:
  - add destination governance txs: propose/approve/activate-disable destination
  - optional timelock on destination activation
  - record proposer/approver and activation time
- Acceptance criteria:
  - destination changes require configured approvals before becoming effective
  - execution path reads only active destination state
  - regression tests for bypass attempts and race conditions
- Deliverables:
  - tx/schema additions, engine logic, tests, workflow doc updates

### 11.3 `feat(policy): cumulative velocity limits`

- Type: Feature
- Priority: P1
- Sprint: S2
- Problem:
  - only per-transaction limit is enforced today.
- Scope:
  - add rolling or fixed window limits (daily/weekly/monthly)
  - support per-asset/per-vault counters
  - deterministic counter updates during finalize/commit
- Acceptance criteria:
  - proposals above window budget fail with deterministic code
  - counters are replay-safe and snapshot/restore-safe
  - tests include window rollover boundaries
- Deliverables:
  - schema for velocity rules, counter storage keys, engine checks, tests

### 11.4 `feat(events): durable security/audit event stream`

- Type: Feature
- Priority: P1
- Sprint: S2
- Problem:
  - security/audit signals are mostly logs; not first-class queryable state.
- Scope:
  - define `event_record_t` and persistent event storage prefix
  - emit events for tx failures, policy denials, replay mismatch, snapshot rejects/restores
  - add `/events/range` query endpoint
- Acceptance criteria:
  - events are persisted with deterministic ordering and event type
  - events export in backup/history bundles
  - integration test validates emitted events for negative workflow paths
- Deliverables:
  - schema, storage, engine emits, query path, tests, docs

### 11.5 `feat(policy): jurisdiction profile bundles`

- Type: Feature
- Priority: P2
- Sprint: S3
- Problem:
  - policy has claim gates but no jurisdiction-specific control bundles.
- Scope:
  - profile object mapping jurisdiction -> required claims + thresholds + destination constraints
  - attach profile to workspace/vault and apply at policy resolution
  - support profile versioning
- Acceptance criteria:
  - profile selection changes effective controls deterministically
  - mismatched txs fail with clear policy/profile denial reason
  - tests cover at least two profile variants
- Deliverables:
  - profile schema, engine merge logic, tests, doc examples

### 11.6 `feat(export): regulator evidence bundle v1`

- Type: Feature
- Priority: P2
- Sprint: S3
- Problem:
  - backup/export exists but lacks regulator-targeted manifest and verification flow.
- Scope:
  - define export manifest v1 (chain_id, height range, hashes, replay checkpoint)
  - include signed manifest hash support
  - add verification utility/workflow
- Acceptance criteria:
  - independent verifier can reproduce replay result from bundle
  - bundle includes deterministic manifest and integrity hash
  - workflow doc includes end-to-end verification steps
- Deliverables:
  - schema/format docs, engine export update, verifier tool/test

## 12. Sprint Execution Checklist

### Sprint S1 (Proof hardening)
- [x] Implement actor authorization model (baseline role checks)
- [x] Implement destination governance workflow
- [ ] Add tests for authorization and destination lifecycle bypass attempts
- [ ] Update workflow docs and tx_builder flags

### Sprint S2 (Risk controls)
- [x] Implement cumulative velocity limits
- [x] Implement durable security/audit event stream
- [ ] Add replay/snapshot coverage tests for new state and counters
- [ ] Add event query examples to Comet workflow guide

### Sprint S3 (Regulatory packaging)
- [ ] Implement jurisdiction profile bundles
- [ ] Implement regulator evidence bundle v1 and verifier flow
- [ ] Publish regulator walkthrough runbook
- [ ] Freeze error-code and event-type contracts for pilot integrators

## 13. Undeniable V1 Additions (Proof-First)

These additions make claims testable by third parties.

### 13.1 Control Coverage Matrix (Required)

Add a machine-readable matrix (CSV/JSON) with:
- `control_id`
- `threat_scenario`
- `enforced_by` (engine function / rule)
- `tx_type`
- `failure_code`
- `test_case_id`
- `evidence_artifact`

Acceptance gate:
- every policy control maps to at least one deterministic failing test and one passing test.

### 13.2 Adversary Scenario Catalog (Required)

Minimum scenarios:
- malicious initiator bypass attempt
- compromised signer key
- duplicate/replay tx submission
- validator/state divergence and replay mismatch
- snapshot poisoning attempt

Acceptance gate:
- each scenario has expected prevention/detection/recovery behavior and evidence output.

### 13.3 Separation-Of-Duties Matrix (Required)

Add explicit constraints:
- proposer cannot self-approve (if policy says so)
- policy editor cannot solo-activate high-risk policy
- backup/restore operator cannot unilaterally finalize live state

Acceptance gate:
- every SoD rule has a code path and test asserting denial.

### 13.4 Deterministic Evidence Pack Spec (Required)

For each demo/pilot run, produce:
- tx input manifest
- tx result code manifest
- queried state snapshots
- event stream slice
- replay result (`height`, `app_hash`, mismatch status)
- signed bundle hash

Acceptance gate:
- independent operator can verify bundle integrity and replay outcome.

### 13.5 Security Event Taxonomy (Required)

Define stable event IDs/severity/classes:
- `SIG_VERIFY_FAIL`
- `NONCE_MISMATCH`
- `POLICY_DENIED_LIMIT`
- `POLICY_DENIED_DESTINATION`
- `POLICY_DENIED_CLAIM`
- `SNAPSHOT_REJECTED`
- `REPLAY_CHECKPOINT_MISMATCH`

Acceptance gate:
- event schema versioned and queryable with deterministic ordering.

### 13.6 Recovery SLO + Drill Criteria (Required)

Define RPO/RTO targets for PoC environments:
- max tolerated data loss window
- max restore and replay time for target dataset size

Acceptance gate:
- runbook-driven restore drill meets SLO and produces signed report.

## 14. First-Version Required Feature Set

This is the minimum v1 bar for serious pilot credibility.

### 14.1 Must-Have Functional Features

- actor authorization model (workspace/vault roles)
- threshold + timelock + per-tx limit + whitelist + claim gating
- destination governance workflow (not direct mutable whitelist only)
- deterministic nonce/signature enforcement
- deterministic tx history and replay path
- snapshot + backup + import/restore workflows
- query coverage for all governed state (including destination and events)
- stable error-code contract and event-type contract

### 14.2 Must-Have Security/Operational Features

- strict crypto mode default-on for non-dev environments
- fail-stop handling for storage/encoding critical faults
- signed evidence export bundle (manifest + hash)
- separation-of-duties enforcement for critical operations
- replay mismatch escalation policy and operator runbook

### 14.3 Must-Have Test Coverage

- negative-path tests for each denial code in the matrix
- deterministic replay equivalence tests
- snapshot offer/apply reject-path tests
- backup export/import round-trip tests
- workflow tests that mirror CometBFT RPC execution path

### 14.4 Must-Have Documentation

- control coverage matrix (control -> code -> test -> evidence)
- custody workflow runbook with expected code outcomes
- incident and recovery runbook
- regulator/investor one-page proof summary with links to artifacts

## 15. Candidate Post-V1 Features (Do Not Block First Proof)

- jurisdiction profile bundles
- advanced velocity controls (multi-window and risk-tiered)
- business-hours and holiday execution windows
- risk scoring and anomaly models
- zero-knowledge or selective-disclosure privacy enhancements
- consensus migration readiness (CometBFT -> ConcordBFT/homegrown)

## 16. Policy Definitions: Happy Path and Failure Path Triggers

This section defines each policy as executable behavior: what must happen on success, and what state/events trigger denial or escalation.

### 16.1 Transaction Envelope Policy

- Happy path:
  - tx decodes
  - version is supported
  - chain id matches
  - signer/signature types match
  - signature verifies
  - nonce equals expected value
- Failure triggers:
  - decode failure -> `code=1`
  - unsupported version -> `code=2`
  - chain mismatch -> `code=3`
  - nonce mismatch -> `code=4`
  - signer/signature mismatch -> `code=5`
  - signature verification failure -> `code=6`
- Audit/security events:
  - `TX_VALIDATION_FAILED` with failure code and signer id

### 16.2 Workspace and Vault Existence Policy

- Happy path:
  - workspace is created once
  - vault is created only after workspace exists
- Failure triggers:
  - duplicate workspace create -> `code=10`
  - missing workspace on vault create -> `code=11`
  - duplicate vault create -> `code=12`
- Audit/security events:
  - `STATE_PRECONDITION_FAILED` for missing/duplicate scope state

### 16.3 Policy Scope and Activation Policy

- Happy path:
  - policy set is created against existing scope
  - policy version is unique
  - active policy pointer references existing policy set/version
- Failure triggers:
  - scope target missing -> `code=13`
  - duplicate policy id/version -> `code=14`
  - activation references missing policy set -> `code=15`
  - intent references unresolved active policy pointer -> `code=20`
- Audit/security events:
  - `POLICY_REFERENCE_INVALID`

### 16.4 Intent Creation Preconditions Policy

- Happy path:
  - workspace/vault exists
  - active policy exists for vault scope
  - intent id is unique
  - transfer intent passes proposal-time policy checks
- Failure triggers:
  - workspace/vault missing -> `code=16`
  - active policy missing -> `code=17`
  - duplicate intent id -> `code=19`
  - proposal amount exceeds policy limit -> `code=28`
  - destination required-whitelist but destination not enabled -> `code=29`
- Audit/security events:
  - `INTENT_CREATE_DENIED_LIMIT`
  - `INTENT_CREATE_DENIED_DESTINATION`

### 16.5 Approval Threshold Policy

- Happy path:
  - approval recorded once per signer
  - approval count reaches required threshold
  - intent transitions to executable when threshold and timelock satisfied
- Failure triggers:
  - intent missing -> `code=21`
  - intent finalized (`executed`/`cancelled`) -> `code=22`
  - duplicate approval by same signer -> `code=24`
  - intent expired at approval time -> `code=23` (status set to `expired`)
- Audit/security events:
  - `APPROVAL_DUPLICATE_ATTEMPT`
  - `INTENT_EXPIRED_ON_APPROVAL`

### 16.6 Timelock Policy

- Happy path:
  - execution attempts only after `not_before`
  - when threshold met and time matured, intent executes
- Failure triggers:
  - execution attempted before timelock maturity -> `code=26`
- Audit/security events:
  - `INTENT_EXECUTE_DENIED_TIMELOCK`

### 16.7 Per-Transaction Limit Policy

- Happy path:
  - transfer amount is less than or equal to effective per-tx limit
- Failure triggers:
  - transfer amount exceeds effective per-tx limit -> `code=28`
- Audit/security events:
  - `INTENT_CREATE_DENIED_LIMIT` with attempted amount and limit

### 16.8 Destination Whitelist Policy

- Happy path:
  - destination exists and is enabled when policy requires whitelist
- Failure triggers:
  - destination missing or disabled while whitelist required -> `code=29`
- Audit/security events:
  - `INTENT_CREATE_DENIED_DESTINATION` with destination id

### 16.9 Claim/Attestation Gate Policy

- Happy path:
  - each required claim resolves to active, unexpired attestation at execution time
  - trusted issuer/min-valid constraints (when configured) are satisfied
- Failure triggers:
  - required claim absent, expired, revoked, or issuer constraint not met -> `code=30`
- Audit/security events:
  - `INTENT_EXECUTE_DENIED_CLAIM`

### 16.10 Intent Expiry Policy

- Happy path:
  - intent is approved/executed before `expires_at`
- Failure triggers:
  - approval attempt after expiration -> `code=23`, status set to `expired`
  - execution attempt after expiration -> `code=23`, status set to `expired`
- Audit/security events:
  - `INTENT_EXPIRED`

### 16.11 Intent Cancellation Policy

- Happy path:
  - non-executed intent can be cancelled
- Failure triggers:
  - cancel on missing intent -> `code=21`
  - cancel on already executed intent -> `code=25`
- Audit/security events:
  - `INTENT_CANCEL_DENIED_ALREADY_EXECUTED`

### 16.12 Attestation Lifecycle Policy

- Happy path:
  - attestation upsert allowed for existing workspace
  - revoke flips existing attestation state to revoked
- Failure triggers:
  - workspace missing -> `code=18`
  - revoke target not found -> `code=27`
- Audit/security events:
  - `ATTESTATION_UPSERT`
  - `ATTESTATION_REVOKE`
  - `ATTESTATION_REVOKE_MISSING`

### 16.13 Actor Authorization Policy (Required v1)

- Happy path:
  - actor role is authorized for requested operation in workspace/vault scope
- Failure triggers:
  - actor lacks required role -> `code=<new_auth_code>`
  - actor attempts prohibited SoD combination -> `code=<new_auth_code>`
- Audit/security events:
  - `AUTHZ_DENIED_ROLE`
  - `AUTHZ_DENIED_SOD`

### 16.14 Destination Governance Policy (Required v1)

- Happy path:
  - destination add/update/remove follows governance flow:
    - propose
    - approve
    - optional timelock
    - activate
- Failure triggers:
  - governance approvals not met -> `code=<new_destination_gov_code>`
  - governance timelock not matured -> `code=<new_destination_gov_code>`
- Audit/security events:
  - `DESTINATION_GOV_PROPOSED`
  - `DESTINATION_GOV_APPROVED`
  - `DESTINATION_GOV_ACTIVATED`
  - `DESTINATION_GOV_DENIED`

### 16.15 Cumulative Velocity Policy (Required v1)

- Happy path:
  - cumulative transfers remain within active window budget (daily/weekly/monthly)
- Failure triggers:
  - transaction would exceed window budget -> `code=<new_velocity_code>`
  - counter state missing/corrupt during strict mode -> critical fault
- Audit/security events:
  - `VELOCITY_LIMIT_DENIED`
  - `VELOCITY_COUNTER_ANOMALY`

### 16.16 Security Event Persistence Policy (Required v1)

- Happy path:
  - all denials/relevant warnings are persisted in deterministic event stream
  - `/events/range` returns complete ordered event records
- Failure triggers:
  - event persistence write failure -> critical fault
  - query decode/path errors -> query error code path
- Audit/security events:
  - `EVENT_PERSIST_FAILED`

### 16.17 Snapshot Offer/Apply Policy

- Happy path:
  - offered snapshot format/chunk count valid
  - trusted hash check passes
  - sender present
  - chunk hash and decode restore pass
  - committed checkpoint updated
- Failure triggers:
  - unsupported format -> `offer_snapshot_result::reject_format`
  - unsupported chunk count -> `offer_snapshot_result::reject`
  - trusted hash mismatch -> `offer_snapshot_result::reject`
  - empty sender -> `apply_snapshot_chunk_result::reject_snapshot`
  - bad index/empty chunk/no pending offer -> `apply_snapshot_chunk_result::retry_snapshot`
  - chunk hash mismatch -> `apply_snapshot_chunk_result::reject_snapshot`
  - restore decode failure -> `apply_snapshot_chunk_result::reject_snapshot`
- Audit/security events:
  - `SNAPSHOT_OFFER_REJECTED`
  - `SNAPSHOT_CHUNK_REJECTED`
  - `SNAPSHOT_APPLIED`

### 16.18 Backup Import Policy

- Happy path:
  - backup bundle decodes
  - version supported
  - chain id matches local chain
  - state/history/snapshot prefixes replaced successfully
  - committed state restored and loaded
- Failure triggers:
  - decode failure -> import returns false with error
  - unsupported version -> import returns false with error
  - chain id mismatch -> import returns false with error
- Audit/security events:
  - `BACKUP_IMPORT_STARTED`
  - `BACKUP_IMPORT_FAILED`
  - `BACKUP_IMPORT_COMPLETED`

### 16.19 Replay Integrity Policy

- Happy path:
  - each history row decodes
  - validation code matches stored code
  - successful txs replay and fold into same app hash
  - final replayed committed checkpoint matches expected committed state
- Failure triggers:
  - history decode failure -> replay returns `ok=false` with error
  - validation code mismatch -> replay returns `ok=false` with error
  - execution failure during replay -> replay returns `ok=false` with error
  - checkpoint mismatch -> warning + replay `ok=true` with mismatch error text
- Audit/security events:
  - `REPLAY_FAILED_DECODE`
  - `REPLAY_FAILED_VALIDATION_CODE_MISMATCH`
  - `REPLAY_FAILED_EXECUTION`
  - `REPLAY_CHECKPOINT_MISMATCH`

### 16.20 Critical Fault Policy

- Happy path:
  - no critical path faults in storage/encoding/strict-crypto initialization
- Failure triggers:
  - critical dependencies unavailable or corrupt state writes in strict path
  - `charter::common::critical(...)` invoked
- Audit/security events:
  - `CRITICAL_FAULT_TERMINATING`

## 17. Open Codes To Define (V1 Additions)

Reserve explicit tx codes for newly required policies:
- actor authorization denial
- separation-of-duties denial
- destination governance precondition denial
- cumulative velocity denial

Recommendation:
- assign contiguous range and freeze in public error-code contract before pilot demos.

## 18. Additional On-Chain Policies (Happy Path / Failure Path)

These are protocol-side controls that should live on chain for custody-grade assurance.

### 18.1 Actor Authorization and Role Assignment Policy

- Happy path:
  - role assignment transaction is authorized by required admin quorum
  - actor-role binding is stored with scope (`workspace`/`vault`) and effective time
  - operation checks pass because actor has required role
- Failure triggers:
  - unauthorized role assignment attempt -> `code=<new_auth_admin_code>`
  - invalid scope reference -> `code=<new_scope_code>`
  - operation by actor without required role -> `code=<new_auth_code>`
- Audit/security events:
  - `ROLE_ASSIGNED`
  - `ROLE_REVOKED`
  - `AUTHZ_DENIED_ROLE`

### 18.2 Separation-Of-Duties (SoD) Policy

- Happy path:
  - proposer/approver/executor constraints are respected for high-risk operations
  - system enforces SoD incompatibility sets deterministically
- Failure triggers:
  - same actor attempts prohibited dual-role action -> `code=<new_sod_code>`
  - actor is in blocked conflict-of-duty set -> `code=<new_sod_code>`
- Audit/security events:
  - `SOD_DENIED`

### 18.3 Destination Governance Workflow Policy

- Happy path:
  - destination change is proposed, approved, optionally delayed, then activated
  - only active destination state is read by execution checks
- Failure triggers:
  - destination governance threshold not met -> `code=<new_destination_gov_code>`
  - governance timelock not matured -> `code=<new_destination_gov_code>`
  - activation references missing pending proposal -> `code=<new_destination_gov_code>`
- Audit/security events:
  - `DESTINATION_PROPOSED`
  - `DESTINATION_APPROVED`
  - `DESTINATION_ACTIVATED`
  - `DESTINATION_GOV_DENIED`

### 18.4 Cumulative Velocity Control Policy

- Happy path:
  - transaction passes per-window cumulative checks (daily/weekly/monthly)
  - deterministic counters update on successful execution
- Failure triggers:
  - tx pushes cumulative amount above configured window -> `code=<new_velocity_code>`
  - counter update failure in strict path -> critical fault
- Audit/security events:
  - `VELOCITY_LIMIT_DENIED`
  - `VELOCITY_COUNTER_UPDATED`

### 18.5 Fee and Anti-Spam Policy

- Happy path:
  - tx meets minimum fee requirements
  - fee accounting is deterministic and attributable
- Failure triggers:
  - fee below policy minimum -> `code=<new_fee_code>`
  - malformed fee accounting payload -> `code=<new_fee_code>`
- Audit/security events:
  - `FEE_DENIED`
  - `FEE_APPLIED`

### 18.6 Validator Admission / Removal Policy

- Happy path:
  - validator set changes pass governance thresholds and activation rules
  - validator metadata and status changes are fully auditable
- Failure triggers:
  - unauthorized validator set change -> `code=<new_validator_gov_code>`
  - invalid validator identity/attestation reference -> `code=<new_validator_gov_code>`
- Audit/security events:
  - `VALIDATOR_ADMITTED`
  - `VALIDATOR_REMOVED`
  - `VALIDATOR_GOV_DENIED`

### 18.7 Upgrade and Parameter Change Policy

- Happy path:
  - protocol parameter changes follow governance workflow
  - effective height/version transition is deterministic
- Failure triggers:
  - unauthorized parameter update -> `code=<new_upgrade_gov_code>`
  - invalid parameter envelope/version -> `code=<new_upgrade_gov_code>`
- Audit/security events:
  - `PARAM_CHANGE_PROPOSED`
  - `PARAM_CHANGE_ACTIVATED`
  - `UPGRADE_GOV_DENIED`

### 18.8 Durable Security Event Stream Policy

- Happy path:
  - security-relevant denials and warnings are persisted in ordered event records
  - `/events/range` returns deterministic replayable event history
- Failure triggers:
  - event write failure in strict path -> critical fault
  - event query malformed key/path -> query error response
- Audit/security events:
  - `EVENT_WRITE_FAILED`

### 18.9 Regulator Export and Verification Policy

- Happy path:
  - export bundle includes manifest, integrity hash, and replay anchors
  - independent verifier reproduces replay results for covered range
- Failure triggers:
  - export request references unsupported schema version -> query/export error
  - manifest integrity mismatch on verification -> verification failure
- Audit/security events:
  - `EXPORT_CREATED`
  - `EXPORT_VERIFICATION_FAILED`
  - `EXPORT_VERIFIED`

### 18.10 Confidentiality Boundary Policy (On-Chain Commitments)

- Happy path:
  - sensitive payloads are represented by commitments/hashes where required
  - policy outcome remains publicly verifiable without disclosing sensitive fields
- Failure triggers:
  - missing commitment for required confidential field -> `code=<new_confidentiality_code>`
  - commitment/reference mismatch at verification point -> `code=<new_confidentiality_code>`
- Audit/security events:
  - `CONFIDENTIALITY_POLICY_DENIED`

## 19. Business and Operating Process Controls (Off-Chain)

These are not just code features. They are operating model decisions that make the protocol deployable in real custody contexts.

### 19.1 Legal Structure and Liability Model

Idea:
- Define who operates protocol governance, who operates validators, and where liability sits when failures occur.
- Without this, institutions cannot onboard even if tech works.

What to decide:
- operating entity/foundation structure
- validator contractual obligations
- indemnity and insurance posture

### 19.2 Regulatory Engagement Model

Idea:
- The protocol should reduce audit burden, not claim to replace regulated obligations.
- Regulators need a clear map from policy control to evidence artifact.

What to define:
- regulator briefing packet template
- standard evidence request response package
- jurisdiction-specific legal review cadence

### 19.3 Incident Response and Crisis Governance

Idea:
- You need a pre-agreed process for key compromise, validator outage, replay mismatch, or suspected tampering.
- This is as important as prevention controls.

What to define:
- severity levels and escalation ownership
- halt/continue decision policy
- post-incident replay and disclosure obligations

### 19.4 Operational SLOs and Reliability Commitments

Idea:
- Design partners and regulators will ask for measurable reliability targets.

What to define:
- RPO/RTO targets
- node recovery SLAs
- evidence that periodic restore/replay drills pass

### 19.5 Key Management and Custody Operations Standard

Idea:
- Institutional adoption requires clear requirements for HSM/MPC practices, key rotation, and operator controls.

What to define:
- minimum key ceremony requirements
- signer rotation cadence and revocation workflow
- emergency key replacement process

### 19.6 Governance Transparency and Change Management

Idea:
- Every major protocol or policy change should be predictable and reviewable.

What to define:
- proposal lifecycle and notice periods
- emergency change process and rollback criteria
- public changelog and rationale standard

### 19.7 Economics and Market Conduct

Idea:
- Fee and reward policy must avoid perverse incentives (spam, censorship, concentration).

What to define:
- fee schedule governance
- validator reward policy
- concentration and conflict-of-interest limits

### 19.8 Commercial Packaging and Design-Partner Readiness

Idea:
- A strong PoC still fails commercially without repeatable onboarding and support process.

What to define:
- pilot onboarding checklist
- support and escalation model
- success criteria and scorecard template for pilots

### 19.9 Data Governance and Privacy Compliance

Idea:
- Decide exactly what data is public, pseudonymous, encrypted, or externalized.
- This is critical for legal/privacy review.

What to define:
- data classification policy
- retention/deletion and legal hold handling
- selective disclosure workflow for auditors/regulators

### 19.10 Independent Assurance Plan

Idea:
- “Undeniable” requires third-party validation, not self-attestation.

What to define:
- external security review scope
- periodic control testing plan
- independent replay/evidence verification procedure

## 20. Additional On-Chain Policies (Same Format)

### 20.1 Asset Ledger and Reservation Policy (`required_for_v1`)

- Happy path:
  - every executed intent updates canonical asset state deterministically
  - available, reserved, and settled balances remain internally consistent
  - transfer execution decrements available balance and records movement state
- Failure triggers:
  - insufficient available balance for intent -> `code=<new_balance_code>`
  - reservation/state mismatch on execute -> `code=<new_balance_code>`
  - asset state decode/corruption in strict path -> critical fault
- Audit/security events:
  - `ASSET_RESERVATION_CREATED`
  - `ASSET_EXECUTED`
  - `ASSET_BALANCE_DENIED`

### 20.2 Finality and Reorg Safety Policy (`required_for_v1`)

- Happy path:
  - custody status transitions to final only after defined finality rule
  - finality rule is deterministic and queryable by clients
- Failure triggers:
  - attempted final-state transition before finality threshold -> `code=<new_finality_code>`
  - commit/finality metadata mismatch -> `code=<new_finality_code>`
- Audit/security events:
  - `FINALITY_REACHED`
  - `FINALITY_DENIED`

### 20.3 Schema Version and Migration Policy (`required_for_v1`)

- Happy path:
  - state schema version is explicit
  - migrations execute as deterministic versioned transforms
  - post-migration replay/hash checks pass
- Failure triggers:
  - unsupported schema version encountered -> `code=<new_schema_code>`
  - migration transform failure -> critical fault
  - post-migration replay mismatch -> replay mismatch event + escalation
- Audit/security events:
  - `MIGRATION_STARTED`
  - `MIGRATION_COMPLETED`
  - `MIGRATION_FAILED`

### 20.4 Deterministic Time Source Policy (`required_for_v1`)

- Happy path:
  - timelock/expiry policy derives from deterministic chain time model
  - time source used in validation is explicit in docs and queryable metadata
- Failure triggers:
  - non-deterministic or invalid timestamp envelope -> `code=<new_time_code>`
  - time source inconsistency across replay -> replay failure
- Audit/security events:
  - `TIME_POLICY_APPLIED`
  - `TIME_POLICY_DENIED`

### 20.5 Signer Compromise Quarantine Policy (`required_for_v1`)

- Happy path:
  - compromised signer can be quarantined on-chain by authorized governance action
  - quarantined signer is blocked from proposing/approving/executing
  - recovery flow can rotate and re-authorize signer identity
- Failure triggers:
  - tx from quarantined signer -> `code=<new_signer_quarantine_code>`
  - unauthorized quarantine/unquarantine request -> `code=<new_auth_admin_code>`
- Audit/security events:
  - `SIGNER_QUARANTINED`
  - `SIGNER_UNQUARANTINED`
  - `SIGNER_QUARANTINE_DENIED`

### 20.6 Tenant Segregation Policy (`required_for_v1`)

- Happy path:
  - all state accesses are scoped by workspace/vault tenant boundaries
  - queries cannot cross tenant boundaries without explicit allowed scope
- Failure triggers:
  - cross-tenant read/write attempt -> `code=<new_tenant_code>`
  - ambiguous scope key decode -> query error path
- Audit/security events:
  - `TENANT_BOUNDARY_DENIED`

### 20.7 Degraded/Halt Mode Policy (`phase_2_recommended`)

- Happy path:
  - chain can enter explicit degraded mode under governance
  - only allowed operation subset executes during degraded mode
  - exit requires governed approval and state checks
- Failure triggers:
  - blocked operation attempted during degraded mode -> `code=<new_degraded_mode_code>`
  - unauthorized mode transition -> `code=<new_upgrade_gov_code>`
- Audit/security events:
  - `DEGRADED_MODE_ENTERED`
  - `DEGRADED_MODE_OPERATION_DENIED`
  - `DEGRADED_MODE_EXITED`

### 20.8 Invariant Enforcement Policy (`required_for_v1`)

- Happy path:
  - invariant checks run at deterministic checkpoints (block finalize/commit/replay)
  - no invariant violations occur
- Failure triggers:
  - invariant violation detected -> `code=<new_invariant_code>` or critical fault (by severity)
  - replay invariant mismatch -> replay failure
- Audit/security events:
  - `INVARIANT_CHECK_PASSED`
  - `INVARIANT_CHECK_FAILED`

## 21. Additional Off-Chain Process Controls (Same Explanatory Format)

### 21.1 Pilot Acceptance Contract (`required_for_v1`)

Idea:
- Define objective criteria that must be met before calling pilot success.
- Prevents ambiguous “it seems good” outcomes.

What to define:
- success metrics (latency, denial accuracy, replay consistency, uptime)
- pass/fail thresholds and sign-off owners
- evidence artifacts required for acceptance

### 21.2 Verifier and Observer UX (`required_for_v1`)

Idea:
- Independent teams must be able to verify outcomes quickly without engineering support.

What to define:
- minimal verifier CLI workflow
- “one-command proof” for acceptance demos
- documented expected outputs and troubleshooting paths

### 21.3 Control Mapping to Customer Audits (`required_for_v1`)

Idea:
- Customers and auditors think in control statements, not internal code paths.

What to define:
- mapping from protocol controls to common audit control objectives
- evidence locations for each objective
- cadence for refreshing evidence packs

### 21.4 Change Advisory Process (`required_for_v1`)

Idea:
- Even in early stage, protocol changes need formal review and release discipline.

What to define:
- release approval workflow
- rollback triggers
- emergency patch process and communication template

### 21.5 Key Ceremony and Operator Training (`required_for_v1`)

Idea:
- Human process quality around keys and operations is a primary failure domain.

What to define:
- key ceremony checklist and witnesses
- operator runbooks and training cadence
- mandatory drill schedule and review logs

### 21.6 Vendor and Dependency Risk Governance (`required_for_v1`)

Idea:
- Open-source and third-party dependency risk can break assurance claims.

What to define:
- dependency inventory and criticality classification
- patch/vulnerability response SLAs
- approved cryptographic/provider baselines

### 21.7 Communications and Disclosure Policy (`phase_2_recommended`)

Idea:
- Incidents, outages, and policy failures need consistent external communication.

What to define:
- incident disclosure thresholds
- timelines and accountable spokesperson roles
- customer/regulator communication templates

### 21.8 Commercial Readiness and Support Model (`phase_2_recommended`)

Idea:
- Early customer trust depends on predictable support and escalation.

What to define:
- support tiers and response windows
- ownership matrix across protocol/operator/customer
- handoff model from pilot to production support

## 22. Definition Of Done For V1 (Stop-Adding-Scope Gate)

Only call v1 complete when all are true:

- [ ] Every `required_for_v1` control has:
  - [ ] on-chain enforcement path
  - [ ] explicit failure code
  - [ ] persisted event type
  - [ ] passing + failing test coverage
  - [ ] evidence artifact link
- [ ] Replay from exported bundle reproduces same `(height, app_hash)` on clean node.
- [ ] Restore drill meets declared RTO/RPO targets with signed run report.
- [ ] Error code and event type contracts are frozen and documented.
- [ ] One external observer can execute runbook end-to-end without author assistance.

## 23. Current Implementation Snapshot (2026-02-27)

Newly wired in codebase:

- Transaction types:
  - `upsert_role_assignment`
  - `upsert_signer_quarantine`
  - `set_degraded_mode`
  - `propose_destination_update`
  - `approve_destination_update`
  - `apply_destination_update`
- Policy schema:
  - `policy_rule.velocity_limits`
- State/event types:
  - `security_event_record`
  - `velocity_counter_state`
  - destination governance state (`destination_update_state`)
- Engine enforcement:
  - signer quarantine deny (`code=31`)
  - degraded mode gate (`code=32`)
  - role-based authz gate (`code=33`, conditional on configured role policy)
  - velocity deny (`code=34`)
  - SoD deny (`code=35`)
  - destination governance lifecycle errors (`codes=36..39`)
- Query paths:
  - `/state/destination`
  - `/state/role_assignment`
  - `/state/signer_quarantine`
  - `/state/degraded_mode`
  - `/state/destination_update`
  - `/events/range`
- Event persistence:
  - tx validation/execution denials
  - replay checkpoint mismatch
  - snapshot reject/apply
  - backup import failures
  - role/quarantine/degraded updates

Notes:
- Authorization is strict-by-default for operations with required roles.
- Scope admins are accepted as a superuser fallback, and global-role operations (`set_degraded_mode`, `upsert_signer_quarantine`) require matching role assignments (or admin) from role-assignment state.
