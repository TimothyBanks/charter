# Workflow Playbooks (PoC)

This is an operator/developer playbook view of custody workflows implemented in the current PoC.

Reference matrix:
- For per-transaction failure and state-write details, see `doc/transaction_workflow_matrix.md`.

## 1) Bootstrap A New Tenant

Inputs:
- workspace id
- admin signer set

Transactions:
1. `create_workspace`
2. `create_vault`
3. `upsert_destination`
4. `create_policy_set`
5. `activate_policy_set`

Success criteria:
- workspace/vault/policy queries return `code=0`
- active policy pointer is present for target scope

## 2) Execute A Transfer

Inputs:
- workspace/vault/intent ids
- transfer action (`asset_id`, `destination_id`, `amount`)

Transactions:
1. `propose_intent`
2. `approve_intent` (repeat as needed)
3. `execute_intent`

Policy gates checked:
- destination whitelist
- threshold approvals
- timelock
- per-tx amount limit
- claim requirements
- velocity windows
- SoD role restrictions
- signer quarantine / degraded mode

## 3) Emergency Controls

Transactions:
- `upsert_signer_quarantine`
- `set_degraded_mode`
- `upsert_role_assignment` (rapid role correction)

Expected behavior:
- new risky tx paths fail with explicit error code
- security events are emitted and queryable via `/events/range`

## 4) Destination Mutation Governance

Transactions:
1. `propose_destination_update`
2. `approve_destination_update`
3. `apply_destination_update`

Expected behavior:
- direct destination changes can be guarded by staged proposal/approval/apply flow
- status transitions are queryable using `/state/destination_update`

## 5) Backup / Restore / Replay

Operations:
1. `export_backup`
2. `import_backup`
3. `replay_history`

Validation checks:
- replay reports `ok=true`
- `/history/export` parity with source node
- app hash parity at final height

## 6) Snapshot Sync (ABCI)

ABCI flow:
1. `ListSnapshots`
2. `OfferSnapshot`
3. `LoadSnapshotChunk`
4. `ApplySnapshotChunk`

Expected behavior:
- only supported format/chunk model accepted
- hash mismatches rejected
- successful chunk apply updates state and emits audit events when needed
