# Charter PoC: CometBFT Workflow Exercise Guide

This file shows how to exercise Charter end-to-end through CometBFT RPC.

## Assumptions

- `charter` app running on `127.0.0.1:26658` (ABCI gRPC).
- `cometbft` running on `127.0.0.1:26657` (RPC).
- Comet config:
  - `abci = "grpc"`
  - `proxy_app = "127.0.0.1:26658"`
- You have a small helper to SCALE-encode `transaction_t` and base64 it.

## RPC Endpoints Used

- Broadcast tx:
  - `POST /broadcast_tx_sync`
  - `POST /broadcast_tx_commit`
- Query app state:
  - `POST /abci_query`
- Chain status:
  - `POST /status`
- Block txs:
  - `POST /block_results`

## JSON-RPC Templates

### Broadcast transaction (`broadcast_tx_commit`)

```bash
curl -s http://127.0.0.1:26657 \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"broadcast_tx_commit",
    "params":{"tx":"<BASE64_SCALE_TX_BYTES>"}
  }'
```

### ABCI query

```bash
curl -s http://127.0.0.1:26657 \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"abci_query",
    "params":{
      "path":"<PATH>",
      "data":"<HEX_SCALE_QUERY_KEY_BYTES>"
    }
  }'
```

### Status

```bash
curl -s http://127.0.0.1:26657 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"status","params":{}}'
```

## Charter Query Paths

- `/engine/info`
- `/engine/keyspaces`
- `/state/workspace`
- `/state/asset`
- `/state/vault`
- `/state/destination`
- `/state/policy_set`
- `/state/active_policy`
- `/state/intent`
- `/state/approval`
- `/state/attestation`
- `/state/role_assignment`
- `/state/signer_quarantine`
- `/state/degraded_mode`
- `/state/destination_update`
- `/history/range`
- `/history/export`
- `/events/range`

## Suggested End-to-End Flow

Use one signer identity and monotonic nonce per tx.

1. `create_workspace`
2. `create_vault`
3. `upsert_asset` (enabled=true)
4. `upsert_destination` (enabled=true)
5. `create_policy_set` with:
   - approvals threshold
   - timelock
   - limit rule
   - destination rule (`require_whitelisted=true`)
   - required claims
6. `activate_policy_set`
7. `propose_intent` transfer (`asset_id`, `destination_id`, `amount`)
8. `approve_intent`
9. `execute_intent` (expected fail if claim missing/timelock not passed)
10. `upsert_attestation` for required claim
11. `execute_intent` again (expected success once requirements satisfied)

## Example Result Checks

Use `block_results` to inspect tx codes by height:

```bash
curl -s http://127.0.0.1:26657 \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"block_results",
    "params":{"height":"<HEIGHT>"}
  }'
```

Expected Charter tx codes:

- `0`: success
- `26`: threshold/timelock not met
- `28`: limit exceeded
- `29`: destination not whitelisted
- `30`: claim requirement unsatisfied
- `40`: asset missing (not onboarded)
- `41`: asset disabled

## Example Query Keys (SCALE Encoded)

Use SCALE-encoded key payload bytes. For CometBFT JSON-RPC, pass query `data`
as plain hex (no `0x` prefix). The proof script will attempt hex first and fall back to
base64 when needed for compatibility.

- `/state/workspace`:
  - raw 32-byte `workspace_id` (not tuple)
- `/state/asset`:
  - raw 32-byte `asset_id` (not tuple)
- `/state/vault`:
  - SCALE tuple `(workspace_id, vault_id)`
- `/state/policy_set`:
  - SCALE tuple `(policy_set_id, policy_version)`
- `/state/active_policy`:
  - SCALE `policy_scope_t` variant
- `/state/intent`:
  - SCALE tuple `(workspace_id, vault_id, intent_id)`
- `/state/approval`:
  - SCALE tuple `(intent_id, signer_id_t)`
- `/state/attestation`:
  - SCALE tuple `(workspace_id, subject, claim_type_t, issuer)`
- `/history/range`:
  - SCALE tuple `(from_height, to_height)`

## Practical TX Builder Approaches

You can build tx bytes via:

- A tiny C++ utility in `tools/` that links your schema/encoder and prints base64.
- A test helper that serializes tx fixtures and dumps base64 blobs.

This repo now includes `transaction_builder`:

```bash
./build.debug/transaction_builder --help
```

Example tx build:

```bash
./build.debug/transaction_builder transaction \
  --payload create_workspace \
  --chain-id <CHAIN_ID_HEX32> \
  --nonce 1 \
  --signer <SIGNER_HEX32> \
  --workspace-id <WORKSPACE_HEX32>
```

Example query key build:

```bash
./build.debug/transaction_builder query-key \
  --path /state/vault \
  --workspace-id <WORKSPACE_HEX32> \
  --vault-id <VAULT_HEX32>
```

## One-Command Proof Script

This repo also includes:

```bash
tests/run_proof_first_demo.sh
```

### Strict Crypto Note (Important)

The proof script currently builds transactions with a `named_signer_t` identity
and placeholder signature bytes. That is fine for PoC mode with
`ALLOW_INSECURE_CRYPTO=1`, but it will fail in strict mode.

If you run local services with strict crypto enabled, `CheckTx` will reject txs
with:

- code `6`
- log `signature verification failed`

Reason: strict verification expects a real public-key signer variant
(`ed25519_signer_id` or `secp256k1_signer_id`) and a valid signature over the
transaction signing bytes.

Defaults:
- uses `build.debug/transaction_builder`
- expects Comet RPC at `http://127.0.0.1:26657`
- writes a timestamped report under `tests/`

Examples:

```bash
# Use already-running charter/cometbft
tests/run_proof_first_demo.sh

# Ask script to start local services (requires cometbft available)
# PoC default: use insecure crypto mode because demo tx signatures are placeholders
START_LOCAL=1 ALLOW_INSECURE_CRYPTO=1 tests/run_proof_first_demo.sh
```

Each tx must include:

- `version = 1`
- `chain_id = /engine/info` chain id
- `nonce` (strictly increasing per signer)
- `signer`
- `payload`
- `signature` matching signer type (or insecure mode for local testing)

## Minimal Workflow Matrix

- Timelock check:
  - execute before `not_before` => code `26`
  - execute after delay => code `0`
- Limit check:
  - propose amount above policy limit => code `28`
- Destination check:
  - propose with disabled destination => code `29`
- Claim gating:
  - execute before attestation => code `30`
  - execute after attestation => code `0`
