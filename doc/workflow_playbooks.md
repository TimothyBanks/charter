# Workflow Playbooks (PoC)

This is an operator/developer playbook view of custody workflows implemented in the current PoC.

Reference matrix:
- For canonical per-operation happy/failure behavior and state mutations, see `doc/operation_happy_failure_paths.md`.
- For a compact checklist view, see `doc/transaction_workflow_matrix.md`.
- For the frozen demo contract (expected tx codes + report format), see `doc/golden_workflow_contract.md`.
- For ABCI callback semantics and mutation expectations, see `doc/abci_quick_reference.md`.

## 1) Bootstrap A New Tenant

Inputs:
- workspace id
- admin signer set
- jurisdiction profile id (optional, but recommended for regulated deployments)

Transactions:
1. `create_workspace`
2. `create_vault`
3. `upsert_asset`
4. `upsert_destination`
5. `create_policy_set`
6. `activate_policy_set`

Success criteria:
- workspace/vault/asset/policy queries return `code=0`
- active policy pointer is present for target scope
- if workspace jurisdiction is set, vault jurisdiction is either inherited or explicitly matched

## 2) Execute A Transfer

Inputs:
- workspace/vault/intent ids
- transfer action (`asset_id`, `destination_id`, `amount`)
- onboarded asset state (`asset_id` exists and `enabled=true`)

Transactions:
1. `propose_intent`
2. `approve_intent` (repeat as needed)
3. `execute_intent`

Policy gates checked:
- destination whitelist
- asset onboarding gate (asset exists and is enabled)
- threshold approvals
- timelock
- per-tx amount limit
- claim requirements
- velocity windows
- SoD role restrictions
- signer quarantine / degraded mode

Policy merge semantics (as implemented in engine):
- matching `policy_rule` entries are merged per operation type
- `threshold` uses max across rules (strictest approval count)
- `timelock` uses max across rules (longest delay)
- per-transaction `limit` uses min across rules (tightest cap)
- whitelist and SoD booleans are OR-ed (any rule can require)
- required claims are unioned by claim id
- velocity limits are accumulated and each rule is enforced in its own deterministic bucket

Authorization precedence:
- scoped role override (`upsert_role_assignment`) is checked first
- if override exists and is disabled, it is an explicit deny
- otherwise active policy-set role mapping is used
- vault scope can inherit workspace-level role grants
- role `admin` acts as scoped superuser fallback for operation roles

Freeze note:
- Use `doc/golden_workflow_contract.md` as the canonical acceptance contract for demo/proof runs.

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
- apply requires both approval threshold and timelock maturity (`not_before`)

## 5) Backup / Restore / Replay

Operations:
1. `export_backup`
2. `import_backup`
3. `replay_history`

Validation checks:
- replay reports `ok=true`
- `/history/export` parity with source node
- app hash parity at final height

Evidence note:
- Include these checks in the canonical report format defined in `doc/golden_workflow_contract.md`.

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

## 7) Policy Enforcement Timeline (Intent)

`propose_intent`:
- validates scope exists and active policy pointer exists
- resolves and freezes policy identity/version onto intent state
- enforces per-tx limit, destination whitelist, and velocity pre-check
- computes `not_before` from merged timelock and sets initial status

`approve_intent`:
- records approval row and increments `approvals_count`
- enforces SoD constraint `require_distinct_from_initiator` when configured
- transitions to `executable` only when threshold and timelock are both satisfied

`execute_intent`:
- re-resolves active policy requirements for dynamic guards
- enforces SoD constraint `require_distinct_from_executor` when configured
- enforces velocity checks and claim requirements at execution time
- marks intent executed, then applies velocity counters
