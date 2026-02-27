# Schema Types And Workflow Mapping

This document maps the current on-chain schema model to engine behavior and the custody workflows it drives.

## 1) Core Identity, Scope, and Transaction Types

### `primitives.hpp`
- `hash32_t`, `bytes_t`, `amount_t`, `timestamp_milliseconds_t`: base value types reused everywhere.
- `signer_id_t`: signer identity (`ed25519`, `secp256k1`, or named signer hash).
- `vault_t`, `workspace_scope_t`, `policy_scope_t`: policy and authorization scope boundary.

### `transaction.hpp`
- `transaction_t`: signed operation envelope (`chain_id`, `nonce`, `signer`, `payload`, `signature`).
- `transaction_payload_t`: operation union the engine dispatches on.

Attached workflows:
- Every custody mutation is represented as one transaction payload.
- ABCI `CheckTx/DeliverTx` decode `transaction_t` and route by payload type.

## 2) Workspace, Vault, and Asset Lifecycle

Types:
- `create_workspace_t`
- `create_vault_t`
- `upsert_destination_t`
- `upsert_attestation_t`
- `revoke_attestation_t`
- `asset_state_t` (schema-defined, currently not in `transaction_payload_t`)
- `disable_asset_t` (schema-defined, currently not in `transaction_payload_t`)
- `attestation_record_t`

Attached workflows:
- Tenant bootstrap (`create_workspace_t`)
- Vault creation and destination enrollment (`create_vault_t`, `upsert_destination_t`)
- Claims/compliance gating (`upsert_attestation_t`, `revoke_attestation_t`)
- Asset operational state transitions are schema-defined but not currently executable via tx payload routing.

## 3) Policy and Approval Model

Types:
- `create_policy_set_t`
- `activate_policy_set_t`
- `policy_set_t`, `policy_rule_t`
- `approval_rule_t`, `time_lock_rule_t`, `limit_rule_t`, `destination_rule_t`
- `velocity_limit_rule_t`, `velocity_counter_state_t`, `velocity_window_t`
- `claim_requirement_t`, `claim_type_t`

Attached workflows:
- Authoring policy definitions (`create_policy_set_t`)
- Selecting active policy for execution (`activate_policy_set_t`)
- Runtime checks in execution engine:
  - destination allow/deny
  - min approvals
  - time locks
  - per-transfer limits
  - claim requirements
  - velocity windows and spend counters

## 4) Intent Lifecycle (Custody Transfer Execution)

Types:
- `propose_intent_t`
- `approve_intent_t`
- `cancel_intent_t`
- `execute_intent_t`
- `intent_state_t`, `approval_state_t`
- `intent_status_t`, `intent_action_t`

Attached workflows:
- Transfer request creation -> approval collection -> execution or cancellation.
- This is the primary custody movement state machine.

## 5) Governance and Access Control Extensions

Types:
- `upsert_role_assignment_t` (`role_assignment_state_t`)
- `upsert_signer_quarantine_t` (`signer_quarantine_state_t`)
- `set_degraded_mode_t` (`degraded_mode_state_t`)
- `role_id_t`, `degraded_mode_t`

Attached workflows:
- Per-scope signer-role mapping (initiator, approver, executor).
- Emergency isolation of compromised signers (quarantine).
- Global degraded-mode operations for incident response.

## 6) Destination Change Governance

Types:
- `propose_destination_update_t`
- `approve_destination_update_t`
- `apply_destination_update_t`
- `destination_update_state_t`
- `destination_update_status_t`

Attached workflows:
- Two/three-step controlled destination updates with delay and approval thresholds.
- Prevents single-signer immediate destination mutations.

## 7) Security and Audit Event Model

Types:
- `security_event_record_t`
- `security_event_type_t`
- `security_event_severity_t`

Attached workflows:
- Engine emits structured security/audit events for:
  - validation/execution denials
  - policy/authz failures
  - replay/snapshot anomalies
  - emergency control state changes
- Queried through event endpoints for triage and compliance evidence.

## 8) Storage-Keyed State Domains

While key types live in `schema/key/*`, the main logical state buckets are:
- Workspace / vault / asset / destination state
- Policy set + active policy pointer
- Intent + approval state
- Role assignments / signer quarantine / degraded mode
- Velocity counters
- Destination update proposals
- Security event log stream

Attached workflows:
- Deterministic key/value persistence in RocksDB.
- Replay/backup/snapshot paths reconstruct the same schema state deterministically.

## 9) Encoding Layer

Types:
- `encoding/encoder.hpp`
- `encoding/scale/*`

Attached workflows:
- Canonical wire/storage encoding for transactions and state snapshots.
- Current implementation uses SCALE behind `encoder<scale_encoder_tag>` abstraction.

## 10) End-to-End Workflow Summary

1. Client builds and signs `transaction_t`.
2. ABCI server forwards tx bytes to execution engine.
3. Engine decodes payload and runs guards:
   - signature/nonce/replay checks
   - role/quarantine/degraded checks
   - policy checks (limits, approvals, destinations, timelock, claims, velocity)
4. Engine mutates state and appends security/audit events.
5. RocksDB persists state for query, replay, backup, and snapshot.

This is the current schema-to-engine contract for the PoC baseline.
Note: asset registry schemas are present but not yet wired into tx payload dispatch/execution paths.

## 11) Workflow Attachments (Happy Path)

### Workspace Bootstrap
1. `create_workspace_t`
2. Optional role assignments via `upsert_role_assignment_t`
3. Optional degraded-mode baseline via `set_degraded_mode_t`

Primary stored state:
- `workspace_state_t`
- `role_assignment_state_t` (if configured)
- `degraded_mode_state_t` (if configured)

### Vault Onboarding
1. `create_vault_t`
2. `upsert_destination_t` (whitelist destination)
3. `create_policy_set_t`
4. `activate_policy_set_t`

Primary stored state:
- `vault_state_t`
- `destination_state_t`
- `policy_set_state_t`
- `active_policy_pointer_t`

### Transfer Lifecycle
1. `propose_intent_t`
2. `approve_intent_t` (one or more)
3. `execute_intent_t` (after threshold + timelock + claims)

Primary stored state:
- `intent_state_t`
- `approval_state_t`
- `velocity_counter_state_t`
- `security_event_record_t` (for denials/anomalies)

### Destination Governance Update
1. `propose_destination_update_t`
2. `approve_destination_update_t`
3. `apply_destination_update_t`

Primary stored state:
- `destination_update_state_t`
- `destination_state_t`

### Compliance Claims Lifecycle
1. `upsert_attestation_t`
2. `revoke_attestation_t`

Primary stored state:
- `attestation_record_t`

## 12) Common Failure Attachments

The following schema families participate directly in denials:
- Authorization failures: `role_assignment_state_t`, `role_id_t`
- Emergency block conditions: `signer_quarantine_state_t`, `degraded_mode_state_t`
- Policy denials: `policy_rule_t`, `limit_rule_t`, `time_lock_rule_t`, `destination_rule_t`, `claim_requirement_t`, `velocity_limit_rule_t`
- Audit artifacts: `security_event_record_t`, `security_event_type_t`, `security_event_severity_t`

## 13) Implementation Notes For Productionization

- Treat any change to transaction variants or state structs as schema migration work.
- Keep SCALE vectors deterministically ordered where required (`rules`, approvals, limits, roles).
- Maintain query compatibility since operational tooling depends on stable `codespace/code/log/info`.
- Keep keyspace prefix ownership explicit; avoid reusing prefixes across independent state domains.

## 14) Companion Docs

- `doc/transaction_workflow_matrix.md`: payload-level preconditions, writes, failures, and event hooks.
- `doc/query_and_keyspace_contract.md`: query envelope behavior and keyspace prefixes.
- `doc/error_codes_and_events_contract.md`: client-facing numeric contracts and compatibility rules.
- `doc/workflow_playbooks.md`: operator playbooks for bootstrap, transfer, emergency, replay, and snapshot flows.
