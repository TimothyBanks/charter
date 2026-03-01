# Transaction Workflow Matrix (PoC)

Date: 2026-02-27  
Scope: Current behavior in `src/execution/engine.cpp` and query/event contracts.
Canonical demo freeze contract: `doc/golden_workflow_contract.md`.

## Usage

This matrix is intended as an implementation and test checklist.  
For each transaction type, it captures:
- Preconditions
- Primary state writes
- Known failure outcomes (`code`)
- Security/audit signals

## Global Transaction Guards (Applied Before Payload Logic)

Applied in validation paths (`check_tx`, proposal, finalize):
- decode success (`code=1` on failure)
- version == 1 (`code=2`)
- chain id matches local chain (`code=3`)
- nonce correctness (`code=4`)
- signer/signature type compatibility (`code=5`)
- signature verification (`code=6`)
- degraded mode gate (`code=32`)
- signer quarantine gate (`code=31`)
- role authorization gate where configured (`code=33`)

## Payload Matrix

### `create_workspace_t`
- Preconditions:
  - workspace id not already present
- Writes:
  - `workspace_state_t`
  - bootstrap admin role assignments (for `admin_set`)
- Failures:
  - `10` workspace already exists
- Events:
  - failure -> execution denial event

### `create_vault_t`
- Preconditions:
  - workspace exists
  - vault id unique under workspace
  - if workspace jurisdiction is set:
    - vault may omit jurisdiction (inherits workspace jurisdiction), or
    - vault jurisdiction must match workspace jurisdiction
- Writes:
  - `vault_state_t` (including inherited jurisdiction when omitted on payload)
- Failures:
  - `11` workspace missing
  - `12` vault already exists
  - `42` jurisdiction mismatch
- Events:
  - failure -> execution denial event

### `upsert_destination_t`
- Preconditions:
  - workspace exists
- Writes:
  - `destination_state_t` (upsert)
- Failures:
  - `11` workspace missing
- Events:
  - failure -> execution denial event

### `upsert_asset_t`
- Preconditions:
  - none beyond global guards
- Writes:
  - `asset_state_t` (upsert)
- Failures:
  - path-specific validation failures only (authorization, etc.)
- Events:
  - failure -> execution denial event

### `disable_asset_t`
- Preconditions:
  - asset exists
- Writes:
  - `asset_state_t.enabled = false`
- Failures:
  - `40` asset missing
- Events:
  - failure -> execution denial event

### `create_policy_set_t`
- Preconditions:
  - scope target exists (workspace or vault)
  - `(policy_set_id, policy_version)` unique
- Writes:
  - `policy_set_state_t`
- Failures:
  - `13` policy scope missing
  - `14` policy set already exists
- Events:
  - failure -> execution denial event

### `activate_policy_set_t`
- Preconditions:
  - scope target exists
  - referenced policy set exists
- Writes:
  - `active_policy_pointer_t`
- Failures:
  - `13` policy scope missing
  - `15` policy set missing
- Events:
  - failure -> execution denial event

### `propose_intent_t`
- Preconditions:
  - workspace/vault exist
  - active policy pointer exists on vault scope
  - intent id unique
  - policy resolution succeeds
  - transfer asset is onboarded and enabled
  - per-tx limit passes
  - destination whitelist requirement passes
  - velocity limits pass
- Writes:
  - `intent_state_t` (initial status)
- Failures:
  - `16` vault scope missing
  - `17` active policy missing
  - `19` intent already exists
  - `20` policy resolution failed
  - `40` asset missing
  - `41` asset disabled
  - `28` limit exceeded
  - `29` destination not whitelisted
  - `34` velocity limit exceeded
- Events:
  - failure -> policy/tx execution denial event

### `approve_intent_t`
- Preconditions:
  - workspace/vault exist
  - intent exists
  - intent not finalized
  - intent not expired
  - no duplicate approval by signer
  - policy resolution succeeds
  - SoD rule passes when enabled
- Writes:
  - `approval_state_t`
  - `intent_state_t` approval count/status update
- Failures:
  - `16` vault scope missing
  - `21` intent missing
  - `22` intent not approvable
  - `23` intent expired
  - `24` duplicate approval
  - `20` policy resolution failed
  - `35` separation-of-duties violated
- Events:
  - failure -> policy/tx execution denial event

### `cancel_intent_t`
- Preconditions:
  - workspace/vault exist
  - intent exists
  - intent not already executed
- Writes:
  - `intent_state_t` status -> cancelled
- Failures:
  - `16` vault scope missing
  - `21` intent missing
  - `25` intent already executed
- Events:
  - failure -> execution denial event

### `execute_intent_t`
- Preconditions:
  - workspace/vault exist
  - intent exists
  - intent not expired
  - intent executable (threshold + timelock met)
  - transfer asset is onboarded and enabled
  - claim requirements satisfied
- Writes:
  - `intent_state_t` status -> executed
  - `velocity_counter_state_t` increments
- Failures:
  - `16` vault scope missing
  - `21` intent missing
  - `23` intent expired
  - `26` intent not executable
  - `40` asset missing
  - `41` asset disabled
  - `30` claim requirement unsatisfied
- Events:
  - failure -> policy/tx execution denial event

### `upsert_attestation_t`
- Preconditions:
  - workspace exists
- Writes:
  - `attestation_record_t` status active
- Failures:
  - `18` workspace missing
- Events:
  - failure -> execution denial event

### `revoke_attestation_t`
- Preconditions:
  - workspace exists
  - attestation exists
- Writes:
  - `attestation_record_t` status revoked
- Failures:
  - `18` workspace missing
  - `27` attestation missing
- Events:
  - failure -> execution denial event

### `upsert_role_assignment_t`
- Preconditions:
  - none beyond global guards (scope resolution is data-driven)
- Writes:
  - `role_assignment_state_t`
- Failures:
  - path-specific validation failures only (authorization, etc.)
- Events:
  - role-assignment-updated event on mutation

### `upsert_signer_quarantine_t`
- Preconditions:
  - none beyond global guards
- Writes:
  - `signer_quarantine_state_t`
- Failures:
  - path-specific validation failures only (authorization, etc.)
- Events:
  - signer-quarantine-updated event on mutation

### `set_degraded_mode_t`
- Preconditions:
  - none beyond global guards
- Writes:
  - `degraded_mode_state_t`
- Failures:
  - path-specific validation failures only (authorization, etc.)
- Events:
  - degraded-mode-updated event on mutation

### `propose_destination_update_t`
- Preconditions:
  - workspace exists
  - update id unique for `(workspace,destination,update)`
- Writes:
  - `destination_update_state_t` status pending approval
- Failures:
  - `11` workspace missing
  - `36` destination update exists
- Events:
  - failure -> execution denial event

### `approve_destination_update_t`
- Preconditions:
  - destination update exists
  - update not finalized
  - no duplicate approver action
- Writes:
  - `destination_update_state_t` approvals count/status
- Failures:
  - `37` destination update missing
  - `38` destination update finalized
  - `24` duplicate approval
- Events:
  - failure -> execution denial event

### `apply_destination_update_t`
- Preconditions:
  - destination update exists
  - update is executable/finalizable
- Writes:
  - `destination_state_t`
  - `destination_update_state_t` status finalized
- Failures:
  - `37` destination update missing
  - `39` destination update not executable
- Events:
  - failure -> execution denial event

## Operational Artifacts Updated By Block Processing

- tx history row persisted for each processed tx (success and failure)
- app hash fold update for successful txs
- committed height/app hash on `commit`
- snapshots based on configured interval
- security event stream updates for defined failure/security state transitions

## Notes For Test Design

Minimum test shape per payload:
1. one happy-path mutation test
2. one primary-precondition failure test
3. one policy/security gate failure (if applicable)
4. one query assertion on resulting state
5. one event-range assertion for emitted denial/update event
