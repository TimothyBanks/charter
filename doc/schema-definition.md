# Custody Protocol Schema Definition

Date: 2026-02-27
Source of truth: `include/charter/schema/*.hpp`, `include/charter/schema/encoding/*`, `src/execution/engine.cpp`

This document replaces the raw PDF extraction with a clean, implementation-aligned schema map.

## 1. Encoding And Key Conventions

### 1.1 Encoding
- All on-chain payloads and persisted values use canonical SCALE encoding via `charter::schema::encoding::encoder<...>`.
- Variants are encoded with a deterministic tag + payload order.
- Struct fields are encoded in declaration order.
- Collections in policy/state that affect consensus must be deterministically ordered by caller/engine.

### 1.2 Key Building
- Engine keyspaces are prefix-partitioned in RocksDB and built by deterministic byte concatenation.
- Prefixes in current engine:
  - `SYS|STATE|NONCE|`
  - `SYS|STATE|WORKSPACE|`
  - `SYS|STATE|VAULT|`
  - `SYS|STATE|DESTINATION|`
  - `SYS|STATE|POLICY_SET|`
  - `SYS|STATE|ACTIVE_POLICY|`
  - `SYS|STATE|INTENT|`
  - `SYS|STATE|APPROVAL|`
  - `SYS|STATE|DESTINATION_UPDATE|`
  - `SYS|STATE|ATTEST|`
  - `SYS|STATE|ROLE_ASSIGNMENT|`
  - `SYS|STATE|SIGNER_QUARANTINE|`
  - `SYS|STATE|DEGRADED_MODE|`
  - `SYS|STATE|EVENT_SEQ|`
  - `SYS|STATE|VELOCITY|`
  - `SYS|HISTORY|TX|`
  - `SYS|EVENT|`
  - `SYS|SNAP|`

## 2. Core Primitives

Defined in `include/charter/schema/primitives.hpp`.

```cpp
using bytes_t = std::vector<uint8_t>;
using hash32_t = std::array<uint8_t, 32>;
using amount_t = boost::multiprecision::uint256_t;
using timestamp_milliseconds_t = uint64_t;
using duration_milliseconds_t = uint64_t;
```

### Purpose
- Shared deterministic value model for all payloads and state.

### Controls
- Prevents host/runtime-dependent representation drift.

## 3. Identity And Transaction Envelope

### 3.1 `signer_id_t`
- Type: `std::variant<ed25519_signer_id, secp256k1_signer_id, named_signer_t>`
- Purpose: actor identity for authz, approvals, attestations, admin actions.
- Controls: role membership, nonce replay protection, audit attribution.
- Storage touchpoints: nonce key and role/quarantine/event linkage.

### 3.2 `signature_t`
- Type: `std::variant<ed25519_signature_t, secp256k1_signature_t>`
- Purpose: cryptographic authenticity of transaction envelope.
- Controls: validation codes `5`/`6` on type mismatch or failed verification.

### 3.3 `transaction_t`
Defined in `include/charter/schema/transaction.hpp`:

```cpp
struct transaction<1> final {
  uint16_t version{1};
  hash32_t chain_id{};
  uint64_t nonce{};
  signer_id_t signer{};
  transaction_payload_t payload{};
  signature_t signature;
};
```

### Purpose
- Single signed envelope for every state mutation.

### Controls
- Version, chain domain, signer/signature compatibility, signature validity, nonce ordering.

### Storage
- Nonce state: `SYS|STATE|NONCE|<canon(signer)>`.
- History row for every finalized tx (success/failure): `SYS|HISTORY|TX|...`.

## 4. Governance Boundary Types

### 4.1 Workspace
- Types: `create_workspace_t`, `workspace_state_t`
- File: `include/charter/schema/create_workspace.hpp`
- Purpose: top-level tenant/admin boundary.
- Controls: admin set + quorum for workspace governance operations, plus optional jurisdiction context.
- Storage: `SYS|STATE|WORKSPACE|<workspace_id>`
- Workflow: bootstrap before vaults/policies/destinations.

### 4.2 Vault
- Types: `create_vault_t`, `vault_state_t`, `vault_model_t`
- File: `include/charter/schema/create_vault.hpp`, `vault_model.hpp`
- Purpose: custody partition under workspace.
- Controls: policy scoping, intent execution context, and optional jurisdiction context.
- Storage: `SYS|STATE|VAULT|<workspace_id,vault_id>`
- Workflow: required before vault-scoped policies/intents.
- Jurisdiction rule:
  - If workspace jurisdiction is set and vault omits jurisdiction, it is inherited.
  - If vault specifies a different jurisdiction than workspace, creation fails with tx code `42`.

### 4.3 Destination
- Types: `upsert_destination_t`, `destination_state_t`, `destination_type_t`, `chain_type_t`
- File: `include/charter/schema/upsert_destination.hpp`, `destination_type.hpp`, `chain.hpp`
- Purpose: transfer target registry.
- Controls: whitelist gate (`enabled`) and chain/type metadata.
- Storage: `SYS|STATE|DESTINATION|<workspace_id,destination_id>`
- Workflow: used by propose/execute transfer policy checks.

### 4.4 Asset
- Types: `asset_state_t` (`upsert_asset_t` alias), `disable_asset_t`, `asset_kind_t`, `asset_ref_t`
- File: `include/charter/schema/asset_state.hpp`, `disable_asset.hpp`, `asset_kind.hpp`, `asset_ref.hpp`
- Purpose: canonical asset identity and interpretation metadata.
- Controls: asset enablement and deterministic amount semantics.
- Storage: not currently wired in `src/execution/engine.cpp` keyspace handlers.
- Workflow: schema-defined for future registry support, but currently not part of `transaction_payload_t` and not executable through tx flow.

## 5. Policy Model

### 5.1 Scope And IDs
- Types: `policy_scope_t`, `role_id_t`, `operation_type_t`
- Files: `primitives.hpp`, `role_id.hpp`, `operation_type.hpp`
- Purpose: target where policy applies and what operations it governs.

### 5.2 Rules
- Types: `policy_rule_t`, `approval_rule_t`, `limit_rule_t`, `time_lock_rule_t`, `destination_rule_t`, `claim_requirement_t`, `velocity_limit_rule_t`
- Files: `policy_rule.hpp` + related rule headers

`policy_rule_t` includes:
- approvals
- limits
- optional time locks
- destination rules
- required claims
- velocity limits

### Purpose
- Encodes deterministic approval, amount, timelock, destination, claim, and velocity controls.

### Controls
- Proposal denials (`28`, `29`, `34`) and execution denials (`26`, `30`, `35`) depending on rule set.

### Storage
- Policy set row: `SYS|STATE|POLICY_SET|<policy_set_id,version>`
- Active pointer row: `SYS|STATE|ACTIVE_POLICY|<scope>`

### Workflow
- `create_policy_set_t` creates versioned policy.
- `activate_policy_set_t` binds active policy to scope.

## 6. Intent Lifecycle Types

### Types
- `propose_intent_t`, `approve_intent_t`, `execute_intent_t`, `cancel_intent_t`
- `intent_state_t`, `intent_status_t`
- `approval_state_t`
- `intent_action_t` currently `variant<transfer_parameters_t>`

### Purpose
- Represents end-to-end custody operation execution pipeline.

### Controls
- Approval threshold, timelock, claim gate, expiry, SoD constraints.

### Storage
- Intent: `SYS|STATE|INTENT|<workspace_id,vault_id,intent_id>`
- Approval: `SYS|STATE|APPROVAL|<intent_id,signer>`

### Workflow
1. Propose: validates policy and creates pending intent.
2. Approve: records approval and transitions status as thresholds are met.
3. Execute: enforces executable state + policy constraints.
4. Cancel: terminates non-executed intent.

## 7. Attestation And Compliance Types

### Types
- `upsert_attestation_t`, `revoke_attestation_t`
- `attestation_record_t`, `attestation_status_t`
- `claim_type_t`, `claim_requirement_t`

### Purpose
- Claims-based compliance gate (KYB/sanctions/etc.).

### Controls
- Execution denied when required claims are missing/invalid/expired/revoked.

### Storage
- `SYS|STATE|ATTEST|<workspace_id,subject,claim,issuer>`

### Workflow
- Attestations are written/revoked via tx and consumed during execute checks.

## 8. New Destination Governance Types

### 8.1 Proposal/Approval/Apply Commands
- `propose_destination_update_t`
- `approve_destination_update_t`
- `apply_destination_update_t`

### 8.2 State And Status
- `destination_update_state_t`
- `destination_update_status_t`:
  - `pending_approval`
  - `executable`
  - `applied`
  - `cancelled`

### Purpose
- Adds controlled, auditable destination mutation workflow.

### Controls
- Approval threshold + delay before activation.
- Denial codes include `36..39` for lifecycle errors.

### Storage
- `SYS|STATE|DESTINATION_UPDATE|<workspace_id,destination_id,update_id>`

### Workflow
1. Propose destination update with `required_approvals` and `delay_ms`.
2. Approve update until threshold reached.
3. Apply only when executable.

## 9. New Authorization And Safety Types

### 9.1 Role Assignment
- Types: `upsert_role_assignment_t`, `role_assignment_state_t`
- Purpose: runtime role grants/revocations by scope and validity window.
- Controls: operation-level authorization and admin governance.
- Storage: `SYS|STATE|ROLE_ASSIGNMENT|<scope,subject,role>`
- Workflow: updated by governance tx, read in auth checks.

### 9.2 Signer Quarantine
- Types: `upsert_signer_quarantine_t`, `signer_quarantine_state_t`
- Purpose: emergency signer blocking.
- Controls: blocks tx intake for quarantined signers (`code=31`).
- Storage: `SYS|STATE|SIGNER_QUARANTINE|<signer>`
- Workflow: updated via admin tx, enforced at tx validation.

### 9.3 Degraded Mode
- Types: `set_degraded_mode_t`, `degraded_mode_state_t`, `degraded_mode_t`
- Purpose: emergency chain operation mode switch.
- Controls: restricts allowed operations while degraded (`code=32` in read-only mode path).
- Storage: `SYS|STATE|DEGRADED_MODE|CURRENT`
- Workflow: managed by governance tx, enforced during tx validation/execution.

## 10. New Velocity Types

### Types
- `velocity_limit_rule_t`, `velocity_window_t`
- `velocity_counter_state_t`

### Purpose
- Cumulative spend/rate limiting over deterministic windows.

### Controls
- Proposal deny when window budget exceeded (`code=34`).

### Storage
- Counters: `SYS|STATE|VELOCITY|<workspace_id,vault_id,asset?,window,window_start>`

### Workflow
- Rules are configured in policy.
- Counters are read/updated by engine during proposal flow.

## 11. New Security Event Types

### Types
- `security_event_type_t`
- `security_event_severity_t`
- `security_event_record_t`

### Event Type Enum
- `tx_validation_failed = 1`
- `tx_execution_denied = 2`
- `authz_denied = 3`
- `policy_denied = 4`
- `replay_checkpoint_mismatch = 5`
- `snapshot_rejected = 6`
- `snapshot_applied = 7`
- `backup_import_failed = 8`
- `role_assignment_updated = 9`
- `signer_quarantine_updated = 10`
- `degraded_mode_updated = 11`

### Purpose
- Durable, queryable audit/security stream.

### Controls
- Supports triage, compliance evidence, replay/snapshot incident visibility.

### Storage
- Event rows: `SYS|EVENT|<event_id>`
- Event sequence state: `SYS|STATE|EVENT_SEQ|...`
- Query path: `/events/range`

### Workflow
- Emitted by engine for relevant failures/state changes and exported in backup/history flows.

## 12. Transaction Payload Catalog (Current)

From `transaction_payload_t`:
- `activate_policy_set_t`
- `apply_destination_update_t`
- `approve_destination_update_t`
- `approve_intent_t`
- `cancel_intent_t`
- `create_policy_set_t`
- `create_workspace_t`
- `create_vault_t`
- `execute_intent_t`
- `propose_destination_update_t`
- `propose_intent_t`
- `revoke_attestation_t`
- `set_degraded_mode_t`
- `upsert_attestation_t`
- `upsert_destination_t`
- `upsert_role_assignment_t`
- `upsert_signer_quarantine_t`

Not in current payload catalog (schema exists but not wired to tx execution yet):
- `upsert_asset_t`
- `disable_asset_t`

## 13. Workflow Mapping (By Domain)

### Workspace/Vault Bootstrapping
- `create_workspace_t` -> workspace state row
- `create_vault_t` -> vault state row

### Policy Governance
- `create_policy_set_t` -> versioned policy row
- `activate_policy_set_t` -> active pointer row

### Destination Governance (New)
- `propose_destination_update_t` -> destination update state (pending)
- `approve_destination_update_t` -> increments approvals, may become executable
- `apply_destination_update_t` -> applies destination mutation and finalizes update

### Transfer Intent Lifecycle
- `propose_intent_t` -> intent state + policy checks
- `approve_intent_t` -> approval state + threshold progression
- `execute_intent_t` -> final policy + claim + timelock checks
- `cancel_intent_t` -> final state transition (non-executed)

### Compliance
- `upsert_attestation_t` / `revoke_attestation_t` -> attestation rows used during execution

### Security Administration (New)
- `upsert_role_assignment_t` -> role assignment state
- `upsert_signer_quarantine_t` -> signer quarantine state
- `set_degraded_mode_t` -> degraded mode state

## 14. Notes For Implementers

- Keep policy vectors deterministically sorted before encoding.
- Keep `transaction_t.version == 1` and enforce strict chain_id domain.
- Treat RocksDB key composition as consensus-critical behavior.
- When adding future schema versions, preserve decode compatibility and document migration path explicitly.
- Before documenting a type as active, verify it appears in both:
  - `include/charter/schema/transaction.hpp` (`transaction_payload_t`)
  - `src/execution/engine.cpp` (`execute_operation` handling + state key path)
