#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/build.debug}"
TX_BUILDER="${TX_BUILDER:-$BUILD_DIR/tx_builder}"
CHARTER_BIN="${CHARTER_BIN:-$BUILD_DIR/charter}"
COMET_BIN="${COMET_BIN:-cometbft}"
COMET_RPC="${COMET_RPC:-http://127.0.0.1:26657}"
ALLOW_INSECURE_CRYPTO="${ALLOW_INSECURE_CRYPTO:-1}"
START_LOCAL="${START_LOCAL:-0}"
REPORT_PATH="${REPORT_PATH:-$ROOT_DIR/tests/proof_report_$(date +%Y%m%d_%H%M%S).txt}"

mkdir -p "$(dirname "$REPORT_PATH")"
: >"$REPORT_PATH"

log() {
  echo "[$(date +%H:%M:%S)] $*" | tee -a "$REPORT_PATH"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    log "missing command: $1"
    exit 1
  fi
}

require_cmd curl
require_cmd python3
require_cmd "$TX_BUILDER"

charter_pid=""
comet_pid=""

cleanup() {
  if [[ -n "$comet_pid" ]]; then
    kill "$comet_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$charter_pid" ]]; then
    kill "$charter_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [[ "$START_LOCAL" == "1" ]]; then
  require_cmd "$COMET_BIN"
  log "starting local charter + cometbft"
  if [[ "$ALLOW_INSECURE_CRYPTO" == "1" ]]; then
    "$CHARTER_BIN" --allow-insecure-crypto >/tmp/charter_demo.log 2>&1 &
  else
    "$CHARTER_BIN" >/tmp/charter_demo.log 2>&1 &
  fi
  charter_pid="$!"
  "$COMET_BIN" node >/tmp/comet_demo.log 2>&1 &
  comet_pid="$!"
  sleep 3
fi

rpc() {
  local payload="$1"
  curl -sS "$COMET_RPC" -H "Content-Type: application/json" -d "$payload"
}

parse_broadcast() {
  python3 - "$1" <<'PY'
import json, sys
obj = json.loads(sys.argv[1])
r = obj.get("result", {})
check = r.get("check_tx", {}).get("code", 0)
deliver = r.get("tx_result", r.get("deliver_tx", {})).get("code", 0)
txhash = r.get("hash", "")
height = r.get("height", "")
print(f"{check} {deliver} {txhash} {height}")
PY
}

parse_query_code() {
  python3 - "$1" <<'PY'
import json, sys
obj = json.loads(sys.argv[1])
print(obj.get("result", {}).get("response", {}).get("code", 0))
PY
}

broadcast_tx() {
  local expected="$1"
  shift
  local tx_b64
  tx_b64="$("$TX_BUILDER" tx "$@")"
  local response
  response="$(rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"broadcast_tx_commit\",\"params\":{\"tx\":\"$tx_b64\"}}")"
  read -r check_code deliver_code txhash height <<<"$(parse_broadcast "$response")"
  log "broadcast payload=$(printf '%q ' "$@") -> check=$check_code deliver=$deliver_code height=$height hash=$txhash"
  if [[ "$check_code" != "0" ]]; then
    log "check_tx failed unexpectedly"
    log "$response"
    exit 1
  fi
  if [[ "$deliver_code" != "$expected" ]]; then
    log "deliver code mismatch, expected=$expected actual=$deliver_code"
    log "$response"
    exit 1
  fi
}

query_path() {
  local path="$1"
  local key_b64="$2"
  local response
  response="$(rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"abci_query\",\"params\":{\"path\":\"$path\",\"data\":\"$key_b64\"}}")"
  local code
  code="$(parse_query_code "$response")"
  log "query path=$path code=$code"
  if [[ "$code" != "0" ]]; then
    log "$response"
    exit 1
  fi
}

CHAIN_ID="$("$TX_BUILDER" chain-id)"
SIGNER="1111111111111111111111111111111111111111111111111111111111111111"
WORKSPACE_ID="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
VAULT_ID="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
POLICY_SET_ID="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
INTENT_ID="dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
ASSET_ID="eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
DEST_ID="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

log "chain_id=$CHAIN_ID"
log "starting golden workflow proof run"

broadcast_tx 0 --payload create_workspace --chain-id "$CHAIN_ID" --nonce 1 --signer "$SIGNER" --workspace-id "$WORKSPACE_ID"
broadcast_tx 0 --payload create_vault --chain-id "$CHAIN_ID" --nonce 2 --signer "$SIGNER" --workspace-id "$WORKSPACE_ID" --vault-id "$VAULT_ID"
broadcast_tx 0 --payload upsert_destination --chain-id "$CHAIN_ID" --nonce 3 --signer "$SIGNER" --workspace-id "$WORKSPACE_ID" --destination-id "$DEST_ID" --destination-enabled false --address-or-contract-hex aabb
broadcast_tx 0 --payload create_policy_set --chain-id "$CHAIN_ID" --nonce 4 --signer "$SIGNER" --workspace-id "$WORKSPACE_ID" --vault-id "$VAULT_ID" --policy-set-id "$POLICY_SET_ID" --asset-id "$ASSET_ID" --threshold 1 --timelock-ms 0 --limit-amount 10 --require-whitelisted-destination true --required-claim kyb_verified --approver "$SIGNER"
broadcast_tx 0 --payload activate_policy_set --chain-id "$CHAIN_ID" --nonce 5 --signer "$SIGNER" --workspace-id "$WORKSPACE_ID" --vault-id "$VAULT_ID" --policy-set-id "$POLICY_SET_ID"

# Negative path checks
broadcast_tx 28 --payload propose_intent --chain-id "$CHAIN_ID" --nonce 6 --signer "$SIGNER" --workspace-id "$WORKSPACE_ID" --vault-id "$VAULT_ID" --intent-id 0101010101010101010101010101010101010101010101010101010101010101 --asset-id "$ASSET_ID" --destination-id "$DEST_ID" --amount 11
broadcast_tx 29 --payload propose_intent --chain-id "$CHAIN_ID" --nonce 7 --signer "$SIGNER" --workspace-id "$WORKSPACE_ID" --vault-id "$VAULT_ID" --intent-id 0202020202020202020202020202020202020202020202020202020202020202 --asset-id "$ASSET_ID" --destination-id "$DEST_ID" --amount 5

# Positive path setup
broadcast_tx 0 --payload upsert_destination --chain-id "$CHAIN_ID" --nonce 8 --signer "$SIGNER" --workspace-id "$WORKSPACE_ID" --destination-id "$DEST_ID" --destination-enabled true --address-or-contract-hex aabb
broadcast_tx 0 --payload propose_intent --chain-id "$CHAIN_ID" --nonce 9 --signer "$SIGNER" --workspace-id "$WORKSPACE_ID" --vault-id "$VAULT_ID" --intent-id "$INTENT_ID" --asset-id "$ASSET_ID" --destination-id "$DEST_ID" --amount 5
broadcast_tx 0 --payload approve_intent --chain-id "$CHAIN_ID" --nonce 10 --signer "$SIGNER" --workspace-id "$WORKSPACE_ID" --vault-id "$VAULT_ID" --intent-id "$INTENT_ID"
broadcast_tx 30 --payload execute_intent --chain-id "$CHAIN_ID" --nonce 11 --signer "$SIGNER" --workspace-id "$WORKSPACE_ID" --vault-id "$VAULT_ID" --intent-id "$INTENT_ID"
broadcast_tx 0 --payload upsert_attestation --chain-id "$CHAIN_ID" --nonce 12 --signer "$SIGNER" --workspace-id "$WORKSPACE_ID" --subject-id "$WORKSPACE_ID" --claim kyb_verified --issuer "$SIGNER" --attestation-expires-at 999999999999
broadcast_tx 0 --payload execute_intent --chain-id "$CHAIN_ID" --nonce 13 --signer "$SIGNER" --workspace-id "$WORKSPACE_ID" --vault-id "$VAULT_ID" --intent-id "$INTENT_ID"

intent_key="$("$TX_BUILDER" query-key --path /state/intent --workspace-id "$WORKSPACE_ID" --vault-id "$VAULT_ID" --intent-id "$INTENT_ID")"
history_key="$("$TX_BUILDER" query-key --path /history/range --from-height 1 --to-height 100)"
query_path /state/intent "$intent_key"
query_path /history/range "$history_key"

log "proof run completed successfully"
log "report: $REPORT_PATH"
