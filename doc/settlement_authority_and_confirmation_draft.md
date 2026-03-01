# Draft: Settlement Authority and External Confirmation Model

Date: March 1, 2026  
Status: Draft design (not yet implemented)

## Why This Change

Current PoC `execute_intent` transitions intent state to `executed` after policy
checks, but it does not submit or confirm the actual origin-chain settlement.

For institutional production workflows, we need explicit modeling for:
- who is authorized to sign/submit origin-chain transfer transactions
- whether settlement was submitted/confirmed/failed on the origin chain

## Design Goals

- Support both custody authority modes:
  - custodian-signing mode
  - client-signing mode
- Separate policy authorization from external settlement finality.
- Keep evidence deterministic and queryable.
- Preserve backward compatibility during migration.

## Authority Modes

Proposed enum: `settlement_authority_mode_t`
- `custodian_signed`
- `client_signed`

Meaning:
- `custodian_signed`: custodian execution service signs/submits origin-chain tx.
- `client_signed`: client signs origin-chain tx; executor/orchestrator may relay.

## Settlement Lifecycle

Proposed enum: `settlement_status_t`
- `none` (default / not yet authorized)
- `authorized` (Charter policy approved for settlement)
- `submitted` (origin-chain tx broadcast observed)
- `confirmed` (origin-chain settlement confirmed)
- `failed` (submission/settlement failed)
- `expired` (authorization window expired before settlement)

Important distinction:
- policy lifecycle status and settlement lifecycle status should be separate.

## Schema Draft Changes

### 1) Extend `intent_state_t`

Proposed new fields (v2 draft):
- `settlement_authority_mode_t settlement_mode`
- `settlement_status_t settlement_status`
- `std::optional<hash32_t> settlement_tx_hash`
- `std::optional<uint64_t> settlement_block_height`
- `std::optional<timestamp_milliseconds_t> settlement_submitted_at`
- `std::optional<timestamp_milliseconds_t> settlement_confirmed_at`
- `std::optional<std::string> settlement_failure_reason`

Notes:
- `settlement_tx_hash` should be canonical hash bytes (not hex string) in state.
- If external chain id is required, prefer deriving from asset/destination first.

### 2) Add New Transactions (Draft)

1. `submit_settlement_t`
- emitted by custody execution/orchestration service
- inputs:
  - intent scope ids
  - origin-chain tx hash
  - optional submit metadata
- transition:
  - `authorized -> submitted`

2. `confirm_settlement_t`
- emitted by oracle/monitoring attestor set
- inputs:
  - intent scope ids
  - origin-chain tx hash
  - confirmation metadata (height/timestamp/status proof reference)
- transition:
  - `submitted -> confirmed`
  - optionally `submitted -> failed`

3. Optional: `mark_settlement_failed_t`
- explicit failure path if submission fails before confirmation.

## Workflow Draft

1. `propose_intent`
2. `approve_intent`
3. `execute_intent` (policy authorization complete)
   - sets `settlement_status=authorized`
4. Settlement execution
   - custodian-signed or client-signed depending on `settlement_mode`
5. `submit_settlement`
6. `confirm_settlement` (oracle-attested)

Result:
- policy approval and chain settlement become independently auditable.

## Backward-Compatible Migration Plan

### Phase 1 (No behavior break)
- Add new enums/types and optional fields.
- Keep current PoC behavior of `execute_intent` as-is.
- Expose new query fields with defaults.

### Phase 2 (Dual mode)
- Add new tx payloads (`submit_settlement`, `confirm_settlement`).
- Update integrations to write settlement observations.
- Keep old interpretation available behind compatibility flag.

### Phase 3 (Strict mode)
- Redefine `execute_intent` semantic to policy authorization only.
- Treat completed settlement as `settlement_status=confirmed`.
- Update docs/contracts/tests accordingly.

## Query Contract Draft Additions

`/state/intent` payload should include:
- settlement mode
- settlement status
- tx hash / confirmation metadata when available

Potential explorer additions:
- settlement status timeline per intent
- origin-chain tx hash reference and confirmation depth

## Security/Trust Notes

- Oracle confirmations should be threshold-attested or verifiable against
  independent chain data.
- Client-signed mode should include anti-replay binding (intent id and chain id
  in signed payload or deterministic mapping).
- Custodian-signed mode should require explicit key-management policy controls.

## Open Questions

1. Should `execute_intent` be renamed to `authorize_settlement` in next major
   schema version?
2. Is a separate `intent_lifecycle_status_t` + `settlement_status_t` pair
   preferable to extending existing intent status enum?
3. How many oracle attestations are required before `confirmed`?
4. Should settlement failure be reversible (retry) or terminal per intent?
5. Do we need destination-side acknowledgment events in addition to chain
   confirmation?

## Immediate Next Step

Implement Phase 1 as additive schema/query changes only, then add integration
tests for both `custodian_signed` and `client_signed` authority modes before
changing existing `execute_intent` semantics.
