# Schema Type Index (Deduplicated)

Date: 2026-02-28  
Purpose: keep one index of schema families and avoid duplicating workflow behavior text across docs.

## Canonical Doc Ownership

| Concern | Canonical doc |
| --- | --- |
| Per-operation happy/failure paths, state mutations, and failure side effects | `doc/operation_happy_failure_paths.md` |
| Compact operation matrix for test/checklist usage | `doc/transaction_workflow_matrix.md` |
| Operator runbooks (bootstrap, transfer, emergency, recovery) | `doc/workflow_playbooks.md` |
| Query/key contracts | `doc/query_and_keyspace_contract.md` |
| Error and security event compatibility contract | `doc/error_codes_and_events_contract.md` |
| Demo freeze workflow and expected proof outputs | `doc/golden_workflow_contract.md` |

## Schema Families (What They Represent)

| Schema family | Representative types | Real workflow domain |
| --- | --- | --- |
| Transaction envelope and scope primitives | `transaction_t`, `transaction_payload_t`, `signer_id_t`, `policy_scope_t`, `vault_t`, `workspace_scope_t` | Signed intent submission and authorization boundary modeling |
| Tenant and vault state | `create_workspace_t`, `workspace_state_t`, `create_vault_t`, `vault_state_t` | Tenant onboarding and custody account provisioning |
| Asset registry and lifecycle | `upsert_asset_t`, `disable_asset_t`, `asset_state_t`, `asset_kind_t`, `asset_ref_t` | Onboarding transferable assets and disabling assets when governance/risk policy requires it |
| Destination state and staged destination governance | `upsert_destination_t`, `destination_state_t`, `propose_destination_update_t`, `approve_destination_update_t`, `apply_destination_update_t`, `destination_update_state_t` | Beneficiary lifecycle and controlled destination mutation |
| Policy definition and activation | `create_policy_set_t`, `policy_set_state_t`, `activate_policy_set_t`, `active_policy_pointer_t`, `policy_rule_t`, `approval_rule_t`, `time_lock_rule_t`, `limit_rule_t`, `destination_rule_t`, `velocity_limit_rule_t`, `claim_requirement_t` | Governance rules that gate custody movement |
| Intent lifecycle state machine | `propose_intent_t`, `approve_intent_t`, `execute_intent_t`, `cancel_intent_t`, `intent_state_t`, `approval_state_t`, `intent_status_t` | Request -> approve -> execute/cancel transfer workflow |
| Compliance and attestations | `upsert_attestation_t`, `revoke_attestation_t`, `attestation_record_t`, `claim_type_t` | Eligibility/compliance evidence required by policy |
| Access control and emergency controls | `upsert_role_assignment_t`, `role_assignment_state_t`, `upsert_signer_quarantine_t`, `signer_quarantine_state_t`, `set_degraded_mode_t`, `degraded_mode_state_t` | Role governance, incident containment, degraded operation |
| Audit and observability | `transaction_result_t`, `transaction_event_t`, `security_event_record_t`, `security_event_type_t`, `security_event_severity_t`, `history_entry_t` | Forensics, evidence, and operator/regulator visibility |
| Recovery and replication artifacts | `snapshot_descriptor_t`, `offer_snapshot_result_t`, `apply_snapshot_chunk_result_t`, `replay_result_t` | Snapshot sync, replay, and deterministic recovery |
| Encoding layer | `encoding/encoder.hpp`, `encoding/scale/*` | Canonical wire/storage serialization |

## Change Management Rules

When touching schema or engine routing:

1. If a payload variant is added/removed/changed, update:
   - `transaction_payload_t`,
   - `engine::execute_operation`,
   - `doc/operation_happy_failure_paths.md`,
   - `doc/transaction_workflow_matrix.md`.
2. If error semantics change, update `doc/error_codes_and_events_contract.md`.
3. If query/key behavior changes, update `doc/query_and_keyspace_contract.md`.
4. Keep this file as an index only; avoid repeating per-operation execution details here.
