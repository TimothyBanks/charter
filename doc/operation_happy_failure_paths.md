# Operation Happy/Failure Paths (State + Attributes)

Date: 2026-02-28  
Source of truth: `src/execution/engine.cpp` (`validate_transaction`, `execute_operation`)

## Scope

This document describes current PoC behavior for every `transaction_payload_t` operation:

- happy path,
- operation-specific failure paths,
- state objects and attributes read/written.

It also includes common validation gates that run before payload execution.

## Common Validation Gates (All Operations)

These checks run in `validate_transaction` before `execute_operation`:

| Error code | Name | Condition |
| --- | --- | --- |
| 32 | `degraded_mode_active` | Degraded mode is not `normal` and payload is not `set_degraded_mode_t`. |
| 31 | `signer_quarantined` | Signer is quarantined at current block time. |
| 33 | `authorization_denied` | Signer lacks required role for payload scope/global role check. |
| 2 | `unsupported_transaction_version` | `tx.version != 1`. |
| 3 | `invalid_chain_id` | `tx.chain_id` mismatches engine `chain_id_`. |
| 5 | `invalid_signature_type` | Signer ID and signature variant are incompatible. |
| 6 | `signature_verification_failed` | Signature verifier callback rejects signature. |
| 4 | `invalid_nonce` | `tx.nonce` does not match expected per signer. |

Notes:

- `create_workspace_t` has no role requirement; all others require one or more roles.
- Any non-zero result code emits a security event after operation handling.

## Required Roles By Operation

| Operation | Required roles |
| --- | --- |
| `create_workspace_t` | none |
| `create_vault_t` | `admin` |
| `upsert_destination_t` | `admin` |
| `upsert_asset_t` | `admin` |
| `disable_asset_t` | `admin` |
| `create_policy_set_t` | `admin` |
| `activate_policy_set_t` | `admin` |
| `propose_intent_t` | `initiator` |
| `approve_intent_t` | `approver` |
| `cancel_intent_t` | `initiator` OR `admin` |
| `execute_intent_t` | `executor` |
| `upsert_attestation_t` | `attestor` OR `admin` |
| `revoke_attestation_t` | `attestor` OR `admin` |
| `propose_destination_update_t` | `admin` |
| `approve_destination_update_t` | `approver` OR `admin` |
| `apply_destination_update_t` | `executor` OR `admin` |
| `upsert_role_assignment_t` | `admin` |
| `upsert_signer_quarantine_t` | `guardian` OR `admin` |
| `set_degraded_mode_t` | `guardian` OR `admin` |

## Operation Paths

### `create_workspace_t`

Input attributes: `workspace_id`, `admin_set`, `quorum_size`, `metadata_ref`.

Happy path:

- Reads `workspace_state_t` via `make_workspace_key(workspace_id)`.
- Writes `workspace_state_t` as the full operation payload.
- For each signer in `admin_set`, writes `role_assignment_state_t` via `make_role_assignment_key(...)` with attributes:
  - `scope = workspace_scope{workspace_id}`,
  - `subject = admin signer`,
  - `role = admin`,
  - `enabled = true`,
  - `not_before = nullopt`,
  - `expires_at = nullopt`,
  - `note = nullopt`.

Operation-specific failures:

- `workspace_exists` (10): workspace key already present.

### `create_vault_t`

Input attributes: `workspace_id`, `vault_id`, `model`, `label`.

Happy path:

- Reads workspace existence.
- Reads vault uniqueness under workspace.
- Writes `vault_state_t` as the full operation payload via `make_vault_key(...)`.

Operation-specific failures:

- `workspace_missing` (11): workspace does not exist.
- `vault_exists` (12): vault key already present.

### `upsert_destination_t`

Input attributes: `workspace_id`, `destination_id`, `type`, `chain_type`, `address_or_contract`, `enabled`, `label`.

Happy path:

- Reads workspace existence.
- Writes `destination_state_t` as the full operation payload via `make_destination_key(...)`.

Operation-specific failures:

- `workspace_missing` (11): workspace does not exist.

### `upsert_asset_t`

Input attributes: `asset_id`, `chain`, `kind`, `reference`, `symbol`, `name`, `decimals`, `enabled`.

Happy path:

- Writes `asset_state_t` as the full operation payload via `make_asset_key(asset_id)`.

Operation-specific failures:

- none in payload execution path (only common validation gates can fail).

### `disable_asset_t`

Input attributes: `asset_id`.

Happy path:

- Reads `asset_state_t` by `asset_id`.
- Mutates and writes `asset_state_t.enabled = false`.

Operation-specific failures:

- `asset_missing` (40): asset state not found.

### `create_policy_set_t`

Input attributes: `policy_set_id`, `scope`, `policy_version`, `roles`, `rules`.

Happy path:

- Reads `policy_scope_exists(scope)` (workspace/vault target must exist).
- Reads policy set uniqueness via `make_policy_set_key(policy_set_id, policy_version)`.
- Writes `policy_set_state_t` as the full operation payload.

Operation-specific failures:

- `policy_scope_missing` (13): scope target does not exist.
- `policy_set_exists` (14): `(policy_set_id, policy_version)` already present.

### `activate_policy_set_t`

Input attributes: `scope`, `policy_set_id`, `policy_set_version`.

Happy path:

- Reads `policy_scope_exists(scope)`.
- Reads referenced `policy_set_state_t`.
- Writes `active_policy_pointer_t` via `make_active_policy_key(scope)` with attributes:
  - `policy_set_id`,
  - `policy_set_version`.

Operation-specific failures:

- `policy_scope_missing` (13): scope target does not exist.
- `policy_set_missing` (15): referenced policy set missing.

### `propose_intent_t`

Input attributes: `workspace_id`, `vault_id`, `intent_id`, `action`, `expires_at`.

Happy path:

- Reads workspace+vault existence.
- Reads active policy pointer on vault scope.
- Reads intent uniqueness by `(workspace_id, vault_id, intent_id)`.
- Resolves policy requirements for action.
- Enforces transfer asset onboarding gate:
  - asset exists,
  - asset is enabled.
- Enforces action-level policy checks:
  - per-transaction limit (`transfer_parameters_t.amount`),
  - whitelisted destination (if required),
  - velocity window limits.
- Computes state attributes:
  - `created_by = tx.signer`,
  - `created_at = now_ms`,
  - `not_before = now_ms + delay_ms`,
  - `status = executable` only when `required_threshold == 0` and timelock reached, otherwise `pending_approval`,
  - `policy_set_id`, `policy_version`, `required_threshold`, `approvals_count = 0`,
  - `claim_requirements` copied from resolved policy.
- Writes `intent_state_t`.

Operation-specific failures:

- `vault_scope_missing` (16): workspace/vault missing.
- `active_policy_missing` (17): no active policy pointer for vault scope.
- `intent_exists` (19): intent ID already present.
- `policy_resolution_failed` (20): active policy pointer invalid/unresolvable.
- `asset_missing` (40): transfer asset must be onboarded first.
- `asset_disabled` (41): transfer asset is currently disabled.
- `limit_exceeded` (28): transfer amount exceeds policy per-transaction limit.
- `destination_not_whitelisted` (29): destination required but disabled/missing.
- `velocity_limit_exceeded` (34): cumulative window amount exceeds maximum.

### `approve_intent_t`

Input attributes: `workspace_id`, `vault_id`, `intent_id`.

Happy path:

- Reads workspace+vault existence.
- Reads `intent_state_t`.
- Reads duplicate approval key `(intent_id, tx.signer)`.
- Resolves policy requirements.
- Enforces SoD rule `require_distinct_from_initiator` when configured.
- Writes `approval_state_t` with attributes:
  - `intent_id`,
  - `signer = tx.signer`,
  - `signed_at = now_ms`.
- Mutates and writes `intent_state_t`:
  - increments `approvals_count`,
  - sets `status = executable` when threshold met and timelock satisfied,
  - otherwise `status = pending_approval`.

Operation-specific failures:

- `vault_scope_missing` (16): workspace/vault missing.
- `intent_missing` (21): intent not found.
- `intent_not_approvable` (22): intent already `executed` or `cancelled`.
- `intent_expired` (23): approval attempted after `expires_at`.
  - failure side effect: intent `status` is first set to `expired` and persisted.
- `duplicate_approval` (24): signer already approved this intent.
- `policy_resolution_failed` (20): active policy pointer invalid/unresolvable.
- `separation_of_duties_violated` (35): signer equals intent initiator when distinctness required.

### `cancel_intent_t`

Input attributes: `workspace_id`, `vault_id`, `intent_id`.

Happy path:

- Reads workspace+vault existence.
- Reads `intent_state_t`.
- Mutates and writes `intent_state_t.status = cancelled`.

Operation-specific failures:

- `vault_scope_missing` (16): workspace/vault missing.
- `intent_missing` (21): intent not found.
- `intent_already_executed` (25): executed intents cannot be cancelled.

### `execute_intent_t`

Input attributes: `workspace_id`, `vault_id`, `intent_id`.

Happy path:

- Reads workspace+vault existence.
- Reads `intent_state_t`.
- Verifies executable conditions:
  - `approvals_count >= required_threshold`,
  - `now_ms >= not_before`.
- Resolves policy requirements.
- Enforces transfer asset onboarding gate:
  - asset exists,
  - asset is enabled.
- Enforces SoD rule `require_distinct_from_executor` by checking executor is not in approval set.
- Enforces velocity limits.
- Validates every `claim_requirement` against active, non-expired attestations.
- Mutates and writes `intent_state_t.status = executed`.
- Applies velocity counters by writing/updating `velocity_counter_state_t`:
  - `workspace_id`, `vault_id`, `asset_id`, `window`, `window_start`,
  - increments `used_amount` and `tx_count`.

Operation-specific failures:

- `vault_scope_missing` (16): workspace/vault missing.
- `intent_missing` (21): intent not found.
- `intent_expired` (23): execution attempted after `expires_at`.
  - failure side effect: intent `status` is first set to `expired` and persisted.
- `intent_not_executable` (26): threshold/timelock requirements not met.
- `policy_resolution_failed` (20): active policy pointer invalid/unresolvable.
- `asset_missing` (40): transfer asset must be onboarded first.
- `asset_disabled` (41): transfer asset is currently disabled.
- `separation_of_duties_violated` (35): executor is also an approver where forbidden.
- `velocity_limit_exceeded` (34): cumulative window amount exceeds maximum.
- `claim_requirement_unsatisfied` (30): required attestation claim missing/expired.

### `upsert_attestation_t`

Input attributes: `workspace_id`, `subject`, `claim`, `issuer`, `expires_at`, `reference_hash`.

Happy path:

- Reads workspace existence.
- Writes `attestation_record_t` via attestation key `(workspace_id, subject, claim, issuer)` with attributes:
  - `workspace_id`, `subject`, `claim`, `issuer`,
  - `issued_at = now_ms`,
  - `expires_at = operation.expires_at`,
  - `status = active`,
  - `reference_hash`.

Operation-specific failures:

- `workspace_missing_for_operation` (18): workspace does not exist.

### `revoke_attestation_t`

Input attributes: `workspace_id`, `subject`, `claim`, `issuer`.

Happy path:

- Reads workspace existence.
- Reads existing `attestation_record_t`.
- Mutates and writes `attestation_record_t.status = revoked`.

Operation-specific failures:

- `workspace_missing_for_operation` (18): workspace does not exist.
- `attestation_missing` (27): target attestation record not found.

### `propose_destination_update_t`

Input attributes: `workspace_id`, `destination_id`, `update_id`, `type`, `chain_type`, `address_or_contract`, `enabled`, `label`, `required_approvals`, `delay_ms`.

Happy path:

- Reads workspace existence.
- Reads destination update uniqueness by `(workspace_id, destination_id, update_id)`.
- Writes `destination_update_state_t` with attributes:
  - copied from operation for destination payload fields,
  - `created_by = tx.signer`,
  - `created_at = now_ms`,
  - `not_before = now_ms + delay_ms`,
  - `required_approvals = max(1, operation.required_approvals)`,
  - `approvals_count = 0`,
  - `status = pending_approval`.

Operation-specific failures:

- `workspace_missing` (11): workspace does not exist.
- `destination_update_exists` (36): update ID already present.

### `approve_destination_update_t`

Input attributes: `workspace_id`, `destination_id`, `update_id`.

Happy path:

- Reads `destination_update_state_t`.
- Reads duplicate approval key `(update_id, tx.signer)`.
- Writes `approval_state_t` (reused for destination updates) with attributes:
  - `intent_id = update_id` (reused field),
  - `signer = tx.signer`,
  - `signed_at = now_ms`.
- Mutates and writes destination update:
  - increments `approvals_count`,
  - sets `status = executable` if approvals and timelock are both satisfied.

Operation-specific failures:

- `destination_update_missing` (37): update not found.
- `destination_update_finalized` (38): update already `applied`.
- `duplicate_approval` (24): signer already approved this update.

### `apply_destination_update_t`

Input attributes: `workspace_id`, `destination_id`, `update_id`.

Happy path:

- Reads `destination_update_state_t`.
- Ensures update executable conditions:
  - `approvals_count >= required_approvals`,
  - `now_ms >= not_before`.
- Writes `destination_state_t` from destination update payload attributes:
  - `workspace_id`, `destination_id`, `type`, `chain_type`,
  - `address_or_contract`, `enabled`, `label`.
- Mutates and writes `destination_update_state_t.status = applied`.

Operation-specific failures:

- `destination_update_missing` (37): update not found.
- `destination_update_not_executable` (39): threshold/timelock requirements not met.

### `upsert_role_assignment_t`

Input attributes: `scope`, `subject`, `role`, `enabled`, `not_before`, `expires_at`, `note`.

Happy path:

- Writes `role_assignment_state_t` as full operation payload using `(scope, subject, role)` key.
- Appends security event `role_assignment_updated` (severity `info`).

Operation-specific failures:

- none in payload execution path (only common validation gates can fail).

### `upsert_signer_quarantine_t`

Input attributes: `signer`, `quarantined`, `until`, `reason`.

Happy path:

- Writes `signer_quarantine_state_t` as full operation payload.
- Appends security event `signer_quarantine_updated` (severity `warning`).

Operation-specific failures:

- none in payload execution path (only common validation gates can fail).

### `set_degraded_mode_t`

Input attributes: `mode`, `effective_at`, `reason`.

Happy path:

- Writes `degraded_mode_state_t` as full operation payload.
- Appends security event `degraded_mode_updated` (severity `warning`).

Operation-specific failures:

- none in payload execution path (only common validation gates can fail).

## High-Level Workflow Mapping (Schema -> Real World)

This maps schema families to the operational workflows a custody team actually runs.

| Real-world workflow | Schema types that drive it | What this models operationally |
| --- | --- | --- |
| Tenant/account onboarding | `create_workspace_t`, `workspace_state_t`, `upsert_role_assignment_t`, `role_assignment_state_t` | Creating a customer/treasury boundary and assigning who can initiate, approve, execute, administer, and respond to incidents. |
| Vault/account provisioning | `create_vault_t`, `vault_state_t` | Opening a governed custody account under a tenant. |
| Asset onboarding and lifecycle control | `upsert_asset_t`, `disable_asset_t`, `asset_state_t`, `asset_kind_t`, `asset_ref_t` | Registering which assets are transferable in the custody domain and suspending assets during incidents or policy changes. |
| Beneficiary/destination management | `upsert_destination_t`, `destination_state_t`, `propose_destination_update_t`, `approve_destination_update_t`, `apply_destination_update_t`, `destination_update_state_t` | Managing withdrawal destinations, including staged approval for risky destination changes. |
| Policy authoring and activation | `create_policy_set_t`, `activate_policy_set_t`, `policy_set_state_t`, `active_policy_pointer_t`, `policy_rule_t`, `approval_rule_t`, `time_lock_rule_t`, `limit_rule_t`, `destination_rule_t`, `velocity_limit_rule_t`, `claim_requirement_t` | Defining and activating governance rules that determine whether movement is allowed. |
| Payment/transfer request lifecycle | `propose_intent_t`, `approve_intent_t`, `execute_intent_t`, `cancel_intent_t`, `intent_state_t`, `approval_state_t`, `intent_status_t` | Request -> approval collection -> execution/cancel state machine for moving funds. |
| Compliance and eligibility checks | `upsert_attestation_t`, `revoke_attestation_t`, `attestation_record_t`, `claim_requirement_t`, `claim_type_t` | KYC/KYB/travel-rule or risk attestations used as preconditions for execution. |
| Spend velocity risk control | `velocity_limit_rule_t`, `velocity_counter_state_t`, `velocity_window_t` | Preventing rapid cumulative outflows even when individual transfers are valid. |
| Incident response and kill switches | `upsert_signer_quarantine_t`, `signer_quarantine_state_t`, `set_degraded_mode_t`, `degraded_mode_state_t` | Blocking compromised actors and constraining system behavior during active incidents. |
| Audit, evidence, and investigations | `transaction_result_t`, `transaction_event_t`, `security_event_record_t`, `security_event_type_t`, `security_event_severity_t`, `history_entry_t` | Durable evidence trail for why actions succeeded/failed and what was changed. |
| Deterministic recovery and continuity | `snapshot_descriptor_t`, `offer_snapshot_result_t`, `apply_snapshot_chunk_result_t`, `replay_result_t`, backup/export payloads | Rebuilding state and proving deterministic replay after outages or migration. |

### Operational Narrative

At a high level, the model is:

1. `transaction_t` is the request envelope submitted by an actor.
2. Role and emergency-control state decides whether the actor can act now.
3. Policy state decides whether the requested action is allowed.
4. Intent and approval state tracks custody workflow progress over time.
5. Compliance and velocity state apply ongoing risk constraints.
6. Event/history state provides regulator- and audit-grade evidence.
