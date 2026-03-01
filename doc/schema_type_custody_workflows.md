# Schema Types to Custody Workflows

This reference ties each schema header/type to the operational custody workflow it represents in the PoC.

## Schema Types

| Schema Type (Header) | Workflow Role |
|---|---|
| `activate_policy_set` | Policy change control: promotes a policy set version to active enforcement for its scope. |
| `active_policy_pointer` | Policy activation index: points each scope to the currently enforced policy set/version. |
| `app_info` | Node/app introspection: reports latest committed height and state root for handshake/status. |
| `apply_destination_update` | Destination change rollout: applies an approved destination update to live destination state. |
| `apply_snapshot_chunk_result` | Snapshot import enum: response to applying received snapshot chunk data. |
| `approval_rule` | Approval policy rule: defines thresholds and separation-of-duties constraints. |
| `approval_state` | Approval ledger state: tracks which signer approved which intent and when. |
| `approve_destination_update` | Destination change approval: records approval toward a proposed destination update. |
| `approve_intent` | Approval collection: records an approver decision toward policy threshold satisfaction. |
| `asset_kind` | Asset classification enum: distinguishes native/token/NFT styles for policy and tooling. |
| `asset_ref` | Chain-specific asset locator: maps custody asset identity to on-chain symbol/contract references. |
| `asset_state` | Asset registry state: canonical record for onboarded assets and current enablement. |
| `attestation_record` | Attestation evidence state: stores issuer/subject/claim validity used in compliance gating. |
| `attestation_status` | Attestation lifecycle enum: active vs revoked compliance evidence state. |
| `block_result` | Finalize output: returns per-transaction results plus candidate post-block state root. |
| `cancel_intent` | Operational abort: stops a pending intent before execution when user/operator intent changes. |
| `chain` | Settlement chain identifier: normalized chain type used in asset/address semantics. |
| `claim_requirement` | Compliance requirement rule: requires attestable claims from trusted issuers. |
| `claim_type` | Claim classification type: canonical or custom claim identifiers for attestations. |
| `commit_result` | Commit output: records finalized height/state_root persistence metadata for consensus handoff. |
| `create_policy_set` | Policy authoring: defines approval, limits, destination, claim, and velocity controls for a scope. |
| `create_vault` | Vault provisioning: creates an account/container under a workspace before assets or intents can reference it. |
| `create_workspace` | Tenant/workspace onboarding: establishes the custody domain, initial admins, quorum, and optional jurisdiction metadata. |
| `degraded_mode` | Operational mode enum: normal vs restricted execution states for incident handling. |
| `destination_rule` | Destination policy rule: enforces whitelisting and destination safety constraints. |
| `destination_type` | Destination classification enum: address vs contract semantics for destination controls. |
| `destination_update_state` | Destination change-management state: tracks pending and approved destination updates. |
| `destination_update_status` | Destination update lifecycle enum: state machine for proposed/approved/applied updates. |
| `disable_asset` | Asset risk control: disables an onboarded asset from future intent activity. |
| `enum_string` | Enum conversion utility: centralized string<->enum mapping used by tooling and CLI. |
| `execute_intent` | Release execution: attempts to move an approved intent into executed state once all guards pass. |
| `history_entry` | Audit history row: stores ordered transaction bytes plus execution code for replay/export. |
| `intent_action` | Action variant envelope: allows intent workflow evolution beyond transfer-only actions. |
| `intent_state` | Intent lifecycle state: tracks proposed/approved/executed/cancelled transfer requests. |
| `intent_status` | Intent lifecycle enum: proposed, approved, executed, cancelled, expired-style states. |
| `jurisdiction` | Regulatory metadata: tags workspace policy context with jurisdiction identifiers. |
| `limit_rule` | Single-transaction limit rule: caps transfer value per intent. |
| `offer_snapshot_result` | Snapshot negotiation enum: response to offered snapshot during state sync. |
| `operation_type` | Policy operation classifier: maps actions (for now transfer) to rule selection in policy sets. |
| `policy_rule` | Composite policy clause: bundles operation-specific approval/limit/claim/destination constraints. |
| `policy_set` | Policy state container: stores executable governance rules used for intent authorization. |
| `primitives` | Foundational primitives: shared binary IDs, signer/signature variants, and byte helpers. |
| `propose_destination_update` | Destination change request: proposes a controlled update to an existing destination configuration. |
| `propose_intent` | Transfer initiation: creates a pending intent describing asset, destination, and amount under policy checks. |
| `query_error_code` | Query failure taxonomy: stable numeric codes for read-path diagnostics and client behavior. |
| `query_result` | Read API envelope: returns deterministic query output, key echo, height, and error metadata. |
| `replay_result` | Audit and determinism result: summarizes history replay verification against committed state. |
| `revoke_attestation` | Compliance revocation: invalidates previously issued attestations for risk or expiry events. |
| `role_id` | Custody role enum: models operator responsibilities (admin, initiator, approver, executor, etc.). |
| `security_event_record` | Security telemetry row: records authz/policy/validation/degraded-mode events for monitoring. |
| `security_event_severity` | Security criticality scale: standardizes event severity for escalation workflows. |
| `security_event_type` | Security taxonomy: classifies custody security event categories for alerting and triage. |
| `set_degraded_mode` | Incident response control: toggles chain execution mode to restrict operations during incidents. |
| `snapshot_descriptor` | State sync metadata: describes snapshot height/format/hash/chunks for node bootstrap and recovery. |
| `time_lock_rule` | Settlement delay rule: enforces minimum wait before execution for additional controls. |
| `transaction` | Canonical transaction envelope: signer, nonce, chain binding, payload, and signature. |
| `transaction_error_code` | Transaction failure taxonomy: stable numeric codes for client handling and policy/audit analytics. |
| `transaction_event` | Event stream item: indexed emission for observability, indexing, and post-trade analytics. |
| `transaction_event_attribute` | Event attribute tuple: key/value/index metadata used by event consumers. |
| `transaction_result` | Write API envelope: returns transaction outcome code/log/info/events and gas accounting. |
| `transfer_parameters` | Transfer action payload: asset and amount details for value movement intents. |
| `upsert_attestation` | Compliance attestation issuance/update: records KYB/KYC/other claims used by policy checks. |
| `upsert_destination` | Destination onboarding and maintenance: registers/updates withdrawal targets and enablement state. |
| `upsert_role_assignment` | RBAC administration: grants/revokes scoped signer roles for custody operations. |
| `upsert_signer_quarantine` | Threat containment: quarantines/unquarantines a signer to block suspicious transaction activity. |
| `vault_model` | Custody account model enum: segregated vs omnibus vault operation style. |
| `velocity_counter_state` | Rate-limit accumulator state: tracks consumed amount/count per velocity window bucket. |
| `velocity_limit_rule` | Cumulative velocity rule: caps aggregate value across rolling/deterministic windows. |
| `velocity_window` | Velocity bucket enum: daily/weekly/monthly windows for cumulative transfer controls. |

## Key Types

| Key Type (Header) | Workflow Role |
|---|---|
| `active_policy_pointer` | Active policy pointer key codec used to resolve current policy for a scope. |
| `approval_state` | Approval state key codec used for threshold counting and separation-of-duties checks. |
| `asset_state` | Asset state key codec used in asset onboarding, disablement, and intent checks. |
| `attestation_record` | Attestation key codec used for claim verification in compliance-gated workflows. |
| `destination_state` | Destination state key codec used in whitelisting and destination control workflows. |
| `engine_keys` | Defines canonical key prefixes and key codecs for custody state, history, snapshots, and events. |
| `intent_state` | Intent state key codec used for lifecycle transitions and execution checks. |
| `key` | Shared key helper utilities for deterministic key construction and parsing. |
| `nonce_record` | Signer nonce keyspace used for anti-replay sequencing in transaction admission. |
| `policy_set_state` | Policy set key codec used for policy authoring/versioning and enforcement lookups. |
| `vault_state` | Vault state key codec used in vault provisioning and intent scoping workflows. |
| `workspace_state` | Workspace state key codec used in onboarding and workspace lookup workflows. |
