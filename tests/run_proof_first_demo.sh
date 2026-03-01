#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_VERSION="2026-03-01-demo-hardening-v2"
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/build.debug}"
TX_BUILDER="${TX_BUILDER:-$BUILD_DIR/transaction_builder}"
CHARTER_BIN="${CHARTER_BIN:-$BUILD_DIR/charter}"
AUTO_BUILD="${AUTO_BUILD:-1}"
COMET_BIN="${COMET_BIN:-cometbft}"
COMET_RPC="${COMET_RPC:-http://127.0.0.1:26657}"
CHARTER_GRPC_ADDR="${CHARTER_GRPC_ADDR:-127.0.0.1:26658}"
ALLOW_INSECURE_CRYPTO="${ALLOW_INSECURE_CRYPTO:-1}"
START_LOCAL="${START_LOCAL:-0}"
KEEP_LOCAL_STATE="${KEEP_LOCAL_STATE:-0}"
RPC_TIMEOUT_SECONDS="${RPC_TIMEOUT_SECONDS:-15}"
BROADCAST_RETRIES="${BROADCAST_RETRIES:-3}"
CLEAN_STALE_LOCAL_PROCESSES="${CLEAN_STALE_LOCAL_PROCESSES:-0}"
AUTO_NONCE_RECOVERY="${AUTO_NONCE_RECOVERY:-1}"
VERIFY_WORKSPACE_ADMIN_QUERY="${VERIFY_WORKSPACE_ADMIN_QUERY:-0}"
REPORT_PATH="${REPORT_PATH:-$ROOT_DIR/tests/proof_report_$(date +%Y%m%d_%H%M%S).txt}"
CHARTER_LOG="${CHARTER_LOG:-/tmp/charter_demo.log}"
COMET_LOG="${COMET_LOG:-/tmp/comet_demo.log}"
COMET_INIT_LOG="${COMET_INIT_LOG:-/tmp/comet_init_demo.log}"

# PoC caveat: transaction_builder currently emits demo placeholder signatures.
# For local scripted runs this requires ALLOW_INSECURE_CRYPTO=1 unless real
# signing keys/signatures are wired into the workflow.

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

report_line() {
  echo "$*" >>"$REPORT_PATH"
}

is_truthy() {
  local value="${1:-}"
  value="${value,,}"
  case "$value" in
    1|true|yes|on)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

extract_arg_value() {
  local key="$1"
  shift
  local prev=""
  for token in "$@"; do
    if [[ "$prev" == "$key" ]]; then
      echo "$token"
      return 0
    fi
    prev="$token"
  done
  echo ""
}

pick_free_port() {
  for _ in $(seq 1 200); do
    local port=$((RANDOM % 20000 + 30000))
    if ! port_in_use "127.0.0.1" "$port"; then
      echo "$port"
      return 0
    fi
  done
  log "failed to find free local TCP port"
  exit 1
}

port_in_use() {
  local _host="$1"
  local port="$2"
  local port_hex
  port_hex="$(printf '%04X' "$port")"
  awk -v port_hex="$port_hex" '
    NR > 1 {
      split($2, addr, ":")
      if ($4 == "0A" && toupper(addr[2]) == port_hex) {
        found = 1
        exit 0
      }
    }
    END {
      if (found == 1) {
        exit 0
      }
      exit 1
    }
  ' /proc/net/tcp /proc/net/tcp6 2>/dev/null
  return $?
}

resolve_path() {
  local path="$1"
  if command -v realpath >/dev/null 2>&1; then
    realpath "$path" 2>/dev/null || echo "$path"
    return
  fi
  readlink -f "$path" 2>/dev/null || echo "$path"
}

file_sha256() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print $1}'
    return
  fi
  echo "unavailable"
}

pids_listening_on_port() {
  local port="$1"
  if ! command -v ss >/dev/null 2>&1; then
    return 0
  fi
  ss -ltnp "sport = :$port" 2>/dev/null | awk '
    {
      line=$0
      while (match(line, /pid=[0-9]+/)) {
        pid=substr(line, RSTART+4, RLENGTH-4)
        print pid
        line=substr(line, RSTART+RLENGTH)
      }
    }
  ' | sort -u
}

kill_listeners_on_port() {
  local port="$1"
  local label="$2"
  local pids
  pids="$(pids_listening_on_port "$port")"
  if [[ -z "$pids" ]]; then
    return 0
  fi
  log "cleaning stale listeners on $label port $port: $pids"
  for pid in $pids; do
    if [[ "$pid" == "$$" ]]; then
      continue
    fi
    kill "$pid" >/dev/null 2>&1 || true
  done
  sleep 0.5

  pids="$(pids_listening_on_port "$port")"
  if [[ -n "$pids" ]]; then
    log "forcing stale listener shutdown on $label port $port: $pids"
    for pid in $pids; do
      if [[ "$pid" == "$$" ]]; then
        continue
      fi
      kill -9 "$pid" >/dev/null 2>&1 || true
    done
  fi
}

rpc_try() {
  local payload="$1"
  curl -sS --connect-timeout 2 --max-time "$RPC_TIMEOUT_SECONDS" "$COMET_RPC" \
    -H "Content-Type: application/json" -d "$payload"
}

rpc() {
  local payload="$1"
  local response
  if ! response="$(rpc_try "$payload")"; then
    log "rpc call failed: method payload=$payload"
    return 1
  fi
  echo "$response"
}

parse_broadcast() {
  python3 - "$1" <<'PY'
import json
import sys
sep = "\x1f"
raw = sys.argv[1] if len(sys.argv) > 1 else ""
try:
    obj = json.loads(raw)
except Exception as exc:
    msg = f"parse_error: {exc}".replace("\n", " ").replace("\t", " ")
    print(sep.join(["rpc_error", "rpc_error", "-", "-", "", msg, "", "", "", ""]))
    raise SystemExit(0)
if obj.get("error") is not None:
    print(sep.join(["rpc_error", "rpc_error", "-", "-", "-", "-", "-", "-", "-", "-"]))
    raise SystemExit(0)
r = obj.get("result", {})
check = r.get("check_tx", {}).get("code", 0)
deliver = r.get("tx_result", r.get("deliver_tx", {})).get("code", 0)
txhash = r.get("hash", "")
height = r.get("height", "")
check_log = r.get("check_tx", {}).get("log", "") or ""
check_codespace = r.get("check_tx", {}).get("codespace", "") or ""
check_info = r.get("check_tx", {}).get("info", "") or ""
deliver_node = r.get("tx_result", r.get("deliver_tx", {}))
deliver_log = deliver_node.get("log", "") or ""
deliver_codespace = deliver_node.get("codespace", "") or ""
deliver_info = deliver_node.get("info", "") or ""
check_log = str(check_log).replace("\n", " ").replace("\t", " ")
check_info = str(check_info).replace("\n", " ").replace("\t", " ")
deliver_log = str(deliver_log).replace("\n", " ").replace("\t", " ")
deliver_info = str(deliver_info).replace("\n", " ").replace("\t", " ")
print(sep.join([str(check), str(deliver), str(txhash), str(height), str(check_codespace), str(check_log), str(check_info), str(deliver_codespace), str(deliver_log), str(deliver_info)]))
PY
}

parse_query_fields() {
  python3 - "$1" <<'PY'
import json
import sys
sep = "\x1f"
raw = sys.argv[1] if len(sys.argv) > 1 else ""
try:
    obj = json.loads(raw)
except Exception:
    print(sep.join(["rpc_error", ""]))
    raise SystemExit(0)
if obj.get("error") is not None:
    print(sep.join(["rpc_error", ""]))
    raise SystemExit(0)
r = obj.get("result", {}).get("response", {})
value = r.get("value", "") or ""
print(sep.join([str(r.get("code", 0)), str(value)]))
PY
}

parse_jsonrpc_error_message() {
  python3 - "$1" <<'PY'
import json
import sys
raw = sys.argv[1] if len(sys.argv) > 1 else ""
try:
    obj = json.loads(raw)
except Exception:
    print("")
    raise SystemExit(0)
err = obj.get("error")
if not isinstance(err, dict):
    print("")
    raise SystemExit(0)
msg = str(err.get("message", "") or "")
data = str(err.get("data", "") or "")
combined = (msg + " " + data).strip().replace("\n", " ").replace("\t", " ")
print(combined)
PY
}

base64_to_hex() {
  python3 - "$1" <<'PY'
import base64
import binascii
import sys
value = sys.argv[1] if len(sys.argv) > 1 else ""
if value == "":
    print("")
    raise SystemExit(0)
try:
    decoded = base64.b64decode(value, validate=True)
except Exception:
    print("")
    raise SystemExit(1)
print(binascii.hexlify(decoded).decode("ascii"))
PY
}

wait_for_rpc_ready() {
  local attempts=80
  local payload='{"jsonrpc":"2.0","id":1,"method":"status","params":{}}'
  for _ in $(seq 1 "$attempts"); do
    if [[ -n "$charter_pid" ]] && ! kill -0 "$charter_pid" >/dev/null 2>&1; then
      return 2
    fi
    if [[ -n "$comet_pid" ]] && ! kill -0 "$comet_pid" >/dev/null 2>&1; then
      return 3
    fi
    local response
    if response="$(rpc_try "$payload" 2>/dev/null || true)"; then
      if [[ -n "$response" ]]; then
        if python3 - "$response" <<'PY'
import json
import sys
obj = json.loads(sys.argv[1])
raise SystemExit(0 if obj.get("result", {}).get("sync_info") is not None else 1)
PY
        then
          return 0
        fi
      fi
    fi
    sleep 0.25
  done
  return 1
}

rpc_status_ready() {
  local payload='{"jsonrpc":"2.0","id":1,"method":"status","params":{}}'
  local response
  response="$(rpc_try "$payload" 2>/dev/null || true)"
  if [[ -z "$response" ]]; then
    return 1
  fi
  if python3 - "$response" <<'PY'
import json
import sys
obj = json.loads(sys.argv[1])
raise SystemExit(0 if obj.get("result", {}).get("sync_info") is not None else 1)
PY
  then
    return 0
  fi
  return 1
}

ensure_rpc_ready_or_fail() {
  local attempts="${1:-8}"
  local delay_s="${2:-0.5}"
  for _ in $(seq 1 "$attempts"); do
    if rpc_status_ready; then
      return 0
    fi
    sleep "$delay_s"
  done
  local status_probe
  status_probe="$(rpc_try '{"jsonrpc":"2.0","id":1,"method":"status","params":{}}' 2>&1 || true)"
  log "diagnostic: status probe to COMET_RPC=$COMET_RPC -> ${status_probe:-<empty>}"
  fail "comet rpc not reachable/ready at $COMET_RPC"
}

charter_pid=""
comet_pid=""
local_run_dir=""
local_comet_home=""
local_backup_file=""
overall_verdict="PASS"
failure_reason=""
report_finalized="0"

run_start_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
declare -a tx_rows
declare -a query_rows
history_range_value_len="0"
history_export_value_len="0"
last_query_value_b64=""
last_query_value_len="0"
NONCE_DELTA=0

finalize_report() {
  if [[ "$report_finalized" == "1" ]]; then
    return
  fi

  local backup_size="n/a"
  if [[ -n "$local_backup_file" && -f "$local_backup_file" ]]; then
    backup_size="$(wc -c <"$local_backup_file" | tr -d ' ')"
  fi

  local charter_log_tail="n/a"
  local comet_log_tail="n/a"
  if [[ -f "$CHARTER_LOG" ]]; then
    charter_log_tail="$CHARTER_LOG"
  fi
  if [[ -f "$COMET_LOG" ]]; then
    comet_log_tail="$COMET_LOG"
  fi

  {
    echo
    echo "Run Metadata"
    echo "------------"
    echo "script_version: $SCRIPT_VERSION"
    echo "start_utc: $run_start_utc"
    echo "end_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "start_local: $START_LOCAL"
    echo "allow_insecure_crypto: $ALLOW_INSECURE_CRYPTO"
    echo "comet_rpc: $COMET_RPC"
    echo "charter_grpc_addr: $CHARTER_GRPC_ADDR"
    echo "tx_builder: $TX_BUILDER"
    echo "charter_bin: $CHARTER_BIN"
    echo "comet_bin: $COMET_BIN"
    echo "report_path: $REPORT_PATH"
    echo "charter_log: $charter_log_tail"
    echo "comet_log: $comet_log_tail"
    echo "chain_id: ${CHAIN_ID:-unset}"
    echo "signer: ${SIGNER:-unset}"

    echo
    echo "Transaction Results"
    echo "-------------------"
    echo "nonce | payload | expected_deliver | observed_check | observed_deliver | height | hash | status"
    if [[ "${tx_rows+set}" != "set" || "${#tx_rows[@]}" -eq 0 ]]; then
      echo "(none)"
    else
      for row in "${tx_rows[@]}"; do
        echo "$row"
      done
    fi

    echo
    echo "Query Assertions"
    echo "----------------"
    echo "path | expected | observed_code | value_len | status"
    if [[ "${query_rows+set}" != "set" || "${#query_rows[@]}" -eq 0 ]]; then
      echo "(none)"
    else
      for row in "${query_rows[@]}"; do
        echo "$row"
      done
    fi

    echo
    echo "Export/Backup Summary"
    echo "---------------------"
    echo "history_range_value_len: $history_range_value_len"
    echo "history_export_value_len: $history_export_value_len"
    echo "backup_file_size_bytes: $backup_size"

    echo
    echo "Overall Verdict"
    echo "---------------"
    echo "$overall_verdict"
    if [[ -n "$failure_reason" ]]; then
      echo "reason: $failure_reason"
    fi
  } >>"$REPORT_PATH"

  report_finalized="1"
}

cleanup() {
  if [[ -n "$comet_pid" ]]; then
    kill "$comet_pid" >/dev/null 2>&1 || true
    wait "$comet_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$charter_pid" ]]; then
    kill "$charter_pid" >/dev/null 2>&1 || true
    wait "$charter_pid" >/dev/null 2>&1 || true
  fi
  if [[ "$KEEP_LOCAL_STATE" != "1" ]]; then
    if [[ -n "$local_run_dir" && -d "$local_run_dir" ]]; then
      rm -rf "$local_run_dir"
    fi
    if [[ -n "$local_comet_home" && -d "$local_comet_home" ]]; then
      rm -rf "$local_comet_home"
    fi
  fi
}

on_exit() {
  local exit_code=$?
  if [[ "$exit_code" -ne 0 ]]; then
    overall_verdict="FAIL"
  fi
  cleanup
  finalize_report
}
trap on_exit EXIT

fail() {
  overall_verdict="FAIL"
  failure_reason="$*"
  log "ERROR: $*"
  if [[ -f "$CHARTER_LOG" ]]; then
    log "last charter log lines:"
    tail -n 40 "$CHARTER_LOG" | tee -a "$REPORT_PATH"
  fi
  if [[ -f "$COMET_LOG" ]]; then
    log "last comet log lines:"
    tail -n 40 "$COMET_LOG" | tee -a "$REPORT_PATH"
  fi
  exit 1
}

ensure_local_processes_alive() {
  if [[ "$START_LOCAL" != "1" ]]; then
    return 0
  fi
  if [[ -n "$charter_pid" ]] && ! kill -0 "$charter_pid" >/dev/null 2>&1; then
    fail "charter process exited unexpectedly"
  fi
  if [[ -n "$comet_pid" ]] && ! kill -0 "$comet_pid" >/dev/null 2>&1; then
    fail "cometbft process exited unexpectedly"
  fi
}

record_tx_result() {
  local nonce="$1"
  local payload="$2"
  local expected="$3"
  local observed_check="$4"
  local observed_deliver="$5"
  local height="$6"
  local txhash="$7"
  local status="$8"
  tx_rows+=("$nonce | $payload | $expected | $observed_check | $observed_deliver | $height | $txhash | $status")
}

record_query_result() {
  local path="$1"
  local expected="$2"
  local observed_code="$3"
  local value_len="$4"
  local status="$5"
  query_rows+=("$path | $expected | $observed_code | $value_len | $status")
}

broadcast_transaction() {
  ensure_local_processes_alive
  local expected="$1"
  shift
  local -a base_args=("$@")
  local base_nonce
  base_nonce="$(extract_arg_value --nonce "${base_args[@]}")"
  local payload
  payload="$(extract_arg_value --payload "${base_args[@]}")"
  local nonce_recovery_tries=0

  while true; do
    local -a tx_args=("${base_args[@]}")
    local nonce="$base_nonce"
    if [[ -n "$base_nonce" ]]; then
      nonce=$((base_nonce + NONCE_DELTA))
      for i in "${!tx_args[@]}"; do
        if [[ "${tx_args[$i]}" == "--nonce" ]] && (( i + 1 < ${#tx_args[@]} )); then
          tx_args[$((i + 1))]="$nonce"
          break
        fi
      done
    fi

    local transaction_b64
    transaction_b64="$($TX_BUILDER transaction "${tx_args[@]}")"

    local response=""
    local broadcast_ok="0"
    local sent=0
    while [[ "$sent" -lt "$BROADCAST_RETRIES" ]]; do
      if response="$(rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"broadcast_tx_commit\",\"params\":{\"tx\":\"$transaction_b64\"}}")"; then
        broadcast_ok="1"
        break
      fi
      sent=$((sent + 1))
      log "broadcast rpc retry $sent/$BROADCAST_RETRIES for payload=$payload nonce=$nonce"
      sleep 0.5
    done
    if [[ "$broadcast_ok" != "1" ]]; then
      local status_probe
      status_probe="$(rpc_try '{"jsonrpc":"2.0","id":1,"method":"status","params":{}}' 2>&1 || true)"
      log "diagnostic: status probe to COMET_RPC=$COMET_RPC -> ${status_probe:-<empty>}"
      record_tx_result "$nonce" "$payload" "$expected" "rpc_error" "rpc_error" "-" "-" "FAIL"
      fail "broadcast rpc call failed for payload=$payload nonce=$nonce"
    fi

    local parsed_broadcast
    parsed_broadcast="$(parse_broadcast "$response" || true)"
    local check_code deliver_code txhash height check_codespace check_log check_info deliver_codespace deliver_log deliver_info
    IFS=$'\x1f' read -r check_code deliver_code txhash height check_codespace check_log check_info deliver_codespace deliver_log deliver_info <<<"${parsed_broadcast}" || true
    if [[ -z "${check_code:-}" ]]; then
      record_tx_result "$nonce" "$payload" "$expected" "rpc_error" "rpc_error" "-" "-" "FAIL"
      log "broadcast parse failure: parsed='${parsed_broadcast}' response='${response}'"
      fail "broadcast parse failed for payload=$payload nonce=$nonce"
    fi
    log "broadcast payload=$(printf '%q ' "${tx_args[@]}") -> check=$check_code deliver=$deliver_code height=$height hash=$txhash check_codespace='$check_codespace' check_log='$check_log'"

    if [[ "$check_code" == "4" && -n "$base_nonce" && "$nonce_recovery_tries" -lt 2 ]] && is_truthy "$AUTO_NONCE_RECOVERY"; then
      local expected_nonce_text="$check_info $check_log"
      if [[ "$expected_nonce_text" =~ expected[[:space:]]nonce[[:space:]]([0-9]+) ]]; then
        local expected_nonce="${BASH_REMATCH[1]}"
        local new_delta=$((expected_nonce - base_nonce))
        if [[ "$new_delta" != "$NONCE_DELTA" ]]; then
          log "nonce recovery: payload=$payload base_nonce=$base_nonce old_delta=$NONCE_DELTA new_delta=$new_delta (expected_nonce=$expected_nonce)"
          NONCE_DELTA="$new_delta"
          nonce_recovery_tries=$((nonce_recovery_tries + 1))
          continue
        fi
      fi
    fi

    if [[ "$check_code" == "rpc_error" ]]; then
      record_tx_result "$nonce" "$payload" "$expected" "$check_code" "$deliver_code" "$height" "$txhash" "FAIL"
      log "broadcast raw response: $response"
      fail "broadcast rpc returned error for payload=$payload nonce=$nonce"
    fi

    if [[ "$check_code" != "0" ]]; then
      record_tx_result "$nonce" "$payload" "$expected" "$check_code" "$deliver_code" "$height" "$txhash" "FAIL"
      if [[ "$check_code" == "6" ]]; then
        log "diagnostic: code=6 indicates strict signature verification is active for the app handling CheckTx."
        if [[ "$START_LOCAL" != "1" ]]; then
          log "diagnostic: START_LOCAL=$START_LOCAL, so this script is not launching charter; ALLOW_INSECURE_CRYPTO only affects charter started by this script."
          log "diagnostic: you are likely connected to an external comet/charter pair at COMET_RPC=$COMET_RPC running strict crypto."
        else
          log "diagnostic: START_LOCAL=$START_LOCAL; verify local charter startup logs include strict_crypto=false and '--allow-insecure-crypto enabled'."
          if [[ -f "$CHARTER_LOG" ]] && grep -q "strict_crypto=false" "$CHARTER_LOG"; then
            log "diagnostic: local charter log shows strict_crypto=false; if CheckTx still returns code=6, COMET_RPC may not be connected to this charter instance."
          fi
        fi
      fi
      log "check_tx details: codespace='$check_codespace' log='$check_log' info='$check_info'"
      log "broadcast raw response: $response"
      fail "check_tx failed unexpectedly for payload=$payload nonce=$nonce"
    fi

    if [[ "$deliver_code" != "$expected" ]]; then
      record_tx_result "$nonce" "$payload" "$expected" "$check_code" "$deliver_code" "$height" "$txhash" "FAIL"
      log "deliver details: codespace='$deliver_codespace' log='$deliver_log' info='$deliver_info'"
      log "broadcast raw response: $response"
      fail "deliver code mismatch for payload=$payload nonce=$nonce expected=$expected actual=$deliver_code"
    fi

    record_tx_result "$nonce" "$payload" "$expected" "$check_code" "$deliver_code" "$height" "$txhash" "PASS"
    return 0
  done
}

query_path_expect_ok() {
  ensure_local_processes_alive
  local path="$1"
  local key_b64="$2"
  local require_non_empty="$3"

  local key_hex=""
  if ! key_hex="$(base64_to_hex "$key_b64")"; then
    record_query_result "$path" "code=0" "rpc_error" "0" "FAIL"
    fail "failed to decode query key base64 for path=$path"
  fi

  local -a query_data_values=()
  local -a query_data_labels=()
  if [[ "$key_hex" == "" ]]; then
    query_data_values+=("")
    query_data_labels+=("empty")
  else
    query_data_values+=("$key_hex")
    query_data_labels+=("hex")
  fi
  if [[ "$key_b64" != "" ]]; then
    query_data_values+=("$key_b64")
    query_data_labels+=("base64")
  fi

  local response=""
  local parsed_query=""
  local code=""
  local value_b64=""
  local query_ok="0"
  local query_attempt=0
  local max_query_attempts="$BROADCAST_RETRIES"
  if [[ "$max_query_attempts" -lt 1 ]]; then
    max_query_attempts=1
  fi

  while [[ "$query_attempt" -lt "$max_query_attempts" ]]; do
    for i in "${!query_data_values[@]}"; do
      local data_value="${query_data_values[$i]}"
      local data_label="${query_data_labels[$i]}"
      local payload
      payload="{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"abci_query\",\"params\":{\"path\":\"$path\",\"data\":\"$data_value\"}}"
      log "query attempt $((query_attempt + 1))/$max_query_attempts path=$path data_format=$data_label"
      if ! response="$(rpc "$payload")"; then
        continue
      fi

      parsed_query="$(parse_query_fields "$response" || true)"
      IFS=$'\x1f' read -r code value_b64 <<<"${parsed_query}" || true
      if [[ -z "${code:-}" ]]; then
        continue
      fi
      if [[ "$code" == "rpc_error" ]]; then
        local rpc_error_message
        rpc_error_message="$(parse_jsonrpc_error_message "$response" || true)"
        log "query path=$path data_format=$data_label returned rpc_error: ${rpc_error_message:-unknown error}"
        log "query raw response: $response"
        continue
      fi

      query_ok="1"
      break 2
    done
    query_attempt=$((query_attempt + 1))
    log "query retry $query_attempt/$max_query_attempts for path=$path"
    sleep 0.5
  done

  if [[ "$query_ok" != "1" ]]; then
    record_query_result "$path" "code=0" "rpc_error" "0" "FAIL"
    fail "query rpc returned error for path=$path"
  fi

  local value_len
  value_len="${#value_b64}"
  last_query_value_b64="$value_b64"
  last_query_value_len="$value_len"
  log "query path=$path code=$code value_len=$value_len"

  if [[ "$code" != "0" ]]; then
    record_query_result "$path" "code=0" "$code" "$value_len" "FAIL"
    log "query raw response: $response"
    fail "query returned non-zero code for path=$path"
  fi

  if [[ "$require_non_empty" == "1" && "$value_len" == "0" ]]; then
    record_query_result "$path" "code=0, non-empty value" "$code" "$value_len" "FAIL"
    fail "query returned empty value for path=$path"
  fi

  local expected_label="code=0"
  if [[ "$require_non_empty" == "1" ]]; then
    expected_label="code=0, non-empty value"
  fi
  record_query_result "$path" "$expected_label" "$code" "$value_len" "PASS"
}

require_cmd curl
require_cmd python3

if is_truthy "$AUTO_BUILD"; then
  require_cmd cmake
  log "building demo binaries (AUTO_BUILD=$AUTO_BUILD)"
  build_jobs=4
  if command -v nproc >/dev/null 2>&1; then
    build_jobs="$(nproc)"
  fi
  if ! cmake --build "$BUILD_DIR" --target transaction_builder charter -- -j"$build_jobs"; then
    fail "failed to build transaction_builder/charter in $BUILD_DIR"
  fi
fi

require_cmd "$TX_BUILDER"

log "mode: START_LOCAL=$START_LOCAL COMET_RPC=$COMET_RPC CHARTER_GRPC_ADDR=$CHARTER_GRPC_ADDR ALLOW_INSECURE_CRYPTO=$ALLOW_INSECURE_CRYPTO AUTO_BUILD=$AUTO_BUILD"
log "mode: RPC_TIMEOUT_SECONDS=$RPC_TIMEOUT_SECONDS BROADCAST_RETRIES=$BROADCAST_RETRIES CLEAN_STALE_LOCAL_PROCESSES=$CLEAN_STALE_LOCAL_PROCESSES AUTO_NONCE_RECOVERY=$AUTO_NONCE_RECOVERY VERIFY_WORKSPACE_ADMIN_QUERY=$VERIFY_WORKSPACE_ADMIN_QUERY"

if [[ "$START_LOCAL" == "1" ]] && ! is_truthy "$ALLOW_INSECURE_CRYPTO"; then
  log "ERROR: START_LOCAL=1 with ALLOW_INSECURE_CRYPTO='$ALLOW_INSECURE_CRYPTO' runs strict signature verification."
  log "ERROR: demo transactions use placeholder signatures, so CheckTx will fail with code=6."
  log "ERROR: rerun with ALLOW_INSECURE_CRYPTO=1, or wire real signatures into transaction_builder/demo flow."
  exit 1
fi

if [[ "$START_LOCAL" != "1" ]]; then
  log "info: START_LOCAL=$START_LOCAL, using external comet/charter at COMET_RPC=$COMET_RPC."
  log "info: ALLOW_INSECURE_CRYPTO=$ALLOW_INSECURE_CRYPTO does not reconfigure external charter; it only affects charter launched by this script."
fi

if [[ "$START_LOCAL" == "1" ]]; then
  require_cmd "$COMET_BIN"
  require_cmd "$CHARTER_BIN"

  resolved_charter_bin="$(resolve_path "$CHARTER_BIN")"
  resolved_tx_builder="$(resolve_path "$TX_BUILDER")"
  charter_sha="$(file_sha256 "$CHARTER_BIN")"
  tx_builder_sha="$(file_sha256 "$TX_BUILDER")"
  log "binary: charter=$resolved_charter_bin sha256=$charter_sha"
  log "binary: transaction_builder=$resolved_tx_builder sha256=$tx_builder_sha"
  if command -v strings >/dev/null 2>&1; then
    if strings "$CHARTER_BIN" | grep -q "set_signature_verifier ignored because strict crypto is disabled"; then
      log "binary check: charter includes non-strict signature-bypass guard"
    else
      log "WARNING: charter binary does not contain expected non-strict signature-bypass marker"
    fi
  fi

  local_rpc_hostport="${COMET_RPC#http://}"
  local_rpc_hostport="${local_rpc_hostport#https://}"
  local_rpc_hostport="${local_rpc_hostport%%/*}"
  comet_rpc_host="${local_rpc_hostport%:*}"
  comet_rpc_port="${local_rpc_hostport##*:}"
  if [[ "$comet_rpc_host" == "$comet_rpc_port" ]]; then
    comet_rpc_host="127.0.0.1"
  fi

  charter_host="${CHARTER_GRPC_ADDR%:*}"
  charter_port="${CHARTER_GRPC_ADDR##*:}"
  if [[ "$charter_host" == "$charter_port" ]]; then
    charter_host="127.0.0.1"
  fi

  comet_connect_host="$comet_rpc_host"
  if [[ "$comet_connect_host" == "0.0.0.0" ]]; then
    comet_connect_host="127.0.0.1"
  fi
  charter_connect_host="$charter_host"
  if [[ "$charter_connect_host" == "0.0.0.0" ]]; then
    charter_connect_host="127.0.0.1"
  fi

  if is_truthy "$CLEAN_STALE_LOCAL_PROCESSES"; then
    kill_listeners_on_port "$comet_rpc_port" "comet-rpc"
    kill_listeners_on_port "$charter_port" "charter-grpc"
  fi

  if port_in_use "$comet_connect_host" "$comet_rpc_port"; then
    old_port="$comet_rpc_port"
    comet_rpc_port="$(pick_free_port)"
    COMET_RPC="http://127.0.0.1:${comet_rpc_port}"
    log "comet rpc port ${old_port} busy, switched to ${comet_rpc_port}"
  fi

  # if port_in_use "$charter_connect_host" "$charter_port"; then
  #   old_port="$charter_port"
  #   charter_port="$(pick_free_port)"
  #   CHARTER_GRPC_ADDR="127.0.0.1:${charter_port}"
  #   log "charter grpc port ${old_port} busy, switched to ${charter_port}"
  # fi

  comet_p2p_port="$(pick_free_port)"

  local_run_dir="$(mktemp -d /tmp/charter_demo_run.XXXXXX)"
  local_comet_home="$(mktemp -d /tmp/charter_comet_home.XXXXXX)"
  local_backup_file="$local_run_dir/charter.backup"
  : >"$CHARTER_LOG"
  : >"$COMET_LOG"
  : >"$COMET_INIT_LOG"

  if ! "$COMET_BIN" --home "$local_comet_home" init >"$COMET_INIT_LOG" 2>&1; then
    log "comet init log:"
    if [[ -f "$COMET_INIT_LOG" ]]; then
      tail -n 80 "$COMET_INIT_LOG" | tee -a "$REPORT_PATH"
    fi
    fail "cometbft init failed for home=$local_comet_home"
  fi

  if ! python3 - "$local_comet_home/config/config.toml" "$CHARTER_GRPC_ADDR" "$comet_rpc_port" "$comet_p2p_port" <<'PY'
import sys
from pathlib import Path

config_path = Path(sys.argv[1])
proxy_app = sys.argv[2]
rpc_port = sys.argv[3]
p2p_port = sys.argv[4]

section = ""
out = []
for line in config_path.read_text().splitlines(keepends=True):
    stripped = line.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        section = stripped.strip("[]")
    if section == "" and stripped.startswith("abci ="):
        out.append('abci = "grpc"\n')
        continue
    if section == "" and stripped.startswith("proxy_app ="):
        out.append(f'proxy_app = "{proxy_app}"\n')
        continue
    if section == "rpc" and stripped.startswith("laddr ="):
        out.append(f'laddr = "tcp://127.0.0.1:{rpc_port}"\n')
        continue
    if section == "p2p" and stripped.startswith("laddr ="):
        out.append(f'laddr = "tcp://127.0.0.1:{p2p_port}"\n')
        continue
    out.append(line)
config_path.write_text("".join(out))
PY
  then
    fail "failed to patch comet config.toml in $local_comet_home"
  fi

  log "starting local charter + cometbft"
  log "local_run_dir=$local_run_dir"
  log "local_comet_home=$local_comet_home"

  if is_truthy "$ALLOW_INSECURE_CRYPTO"; then
    (
      cd "$local_run_dir"
      "$CHARTER_BIN" --grpc-port "$CHARTER_GRPC_ADDR" --backup-file "$local_backup_file" --allow-insecure-crypto >"$CHARTER_LOG" 2>&1
    ) &
  else
    (
      cd "$local_run_dir"
      "$CHARTER_BIN" --grpc-port "$CHARTER_GRPC_ADDR" --backup-file "$local_backup_file" >"$CHARTER_LOG" 2>&1
    ) &
  fi
  charter_pid="$!"

  "$COMET_BIN" --home "$local_comet_home" node >"$COMET_LOG" 2>&1 &
  comet_pid="$!"

  sleep 5
  if ! kill -0 "$charter_pid" >/dev/null 2>&1; then
    fail "charter exited during startup"
  fi
  if ! kill -0 "$comet_pid" >/dev/null 2>&1; then
    fail "cometbft exited during startup"
  fi

  wait_result=0
  if ! wait_for_rpc_ready; then
    wait_result=$?
  fi
  if [[ "$wait_result" -eq 2 ]]; then
    fail "charter exited before comet rpc became ready"
  fi
  if [[ "$wait_result" -eq 3 ]]; then
    fail "cometbft exited before rpc became ready"
  fi
  if [[ "$wait_result" -ne 0 ]]; then
    fail "comet rpc not ready at $COMET_RPC"
  fi
fi

ensure_rpc_ready_or_fail 8 0.5

CHAIN_ID="$($TX_BUILDER chain-id)"
SIGNER="${SIGNER:-1111111111111111111111111111111111111111111111111111111111111111}"
WORKSPACE_ID="${WORKSPACE_ID:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"
VAULT_ID="${VAULT_ID:-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb}"
POLICY_SET_ID="${POLICY_SET_ID:-cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc}"
INTENT_ID="${INTENT_ID:-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd}"
ASSET_ID="${ASSET_ID:-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee}"
DEST_ID="${DEST_ID:-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff}"

log "chain_id=$CHAIN_ID"
log "run ids: signer=$SIGNER workspace_id=$WORKSPACE_ID vault_id=$VAULT_ID policy_set_id=$POLICY_SET_ID intent_id=$INTENT_ID asset_id=$ASSET_ID destination_id=$DEST_ID"
log "starting golden workflow proof run"

broadcast_transaction 0 --payload create_workspace --chain-id "$CHAIN_ID" --nonce 1 --signer "$SIGNER" --workspace-id "$WORKSPACE_ID" --admin "$SIGNER"

if is_truthy "$VERIFY_WORKSPACE_ADMIN_QUERY"; then
  log "phase: building workspace admin query key"
  workspace_admin_key="$($TX_BUILDER query-key --path /state/role_assignment --scope-type workspace --workspace-id "$WORKSPACE_ID" --subject-signer "$SIGNER" --role admin)"
  log "phase: querying workspace admin role assignment"
  query_path_expect_ok /state/role_assignment "$workspace_admin_key" 1
  log "phase: workspace admin role assignment confirmed"
else
  log "phase: skipping workspace admin query verification (VERIFY_WORKSPACE_ADMIN_QUERY=$VERIFY_WORKSPACE_ADMIN_QUERY)"
fi

broadcast_transaction 0 --payload create_vault --chain-id "$CHAIN_ID" --nonce 2 --signer "$SIGNER" --workspace-id "$WORKSPACE_ID" --vault-id "$VAULT_ID"
broadcast_transaction 0 --payload upsert_asset --chain-id "$CHAIN_ID" --nonce 3 --signer "$SIGNER" --asset-id "$ASSET_ID" --chain ethereum --asset-kind erc20 --address-or-contract-hex aabbccdd --asset-symbol-hex 55534443 --asset-name-hex 55534420436f696e --asset-decimals 6 --asset-enabled true
broadcast_transaction 0 --payload upsert_destination --chain-id "$CHAIN_ID" --nonce 4 --signer "$SIGNER" --workspace-id "$WORKSPACE_ID" --destination-id "$DEST_ID" --destination-enabled false --address-or-contract-hex aabb
broadcast_transaction 0 --payload create_policy_set --chain-id "$CHAIN_ID" --nonce 5 --signer "$SIGNER" --workspace-id "$WORKSPACE_ID" --vault-id "$VAULT_ID" --policy-set-id "$POLICY_SET_ID" --asset-id "$ASSET_ID" --threshold 1 --timelock-ms 0 --limit-amount 10 --require-whitelisted-destination true --required-claim kyb_verified --approver "$SIGNER"
broadcast_transaction 0 --payload activate_policy_set --chain-id "$CHAIN_ID" --nonce 6 --signer "$SIGNER" --workspace-id "$WORKSPACE_ID" --vault-id "$VAULT_ID" --policy-set-id "$POLICY_SET_ID"

broadcast_transaction 28 --payload propose_intent --chain-id "$CHAIN_ID" --nonce 7 --signer "$SIGNER" --workspace-id "$WORKSPACE_ID" --vault-id "$VAULT_ID" --intent-id 0101010101010101010101010101010101010101010101010101010101010101 --asset-id "$ASSET_ID" --destination-id "$DEST_ID" --amount 11
broadcast_transaction 29 --payload propose_intent --chain-id "$CHAIN_ID" --nonce 8 --signer "$SIGNER" --workspace-id "$WORKSPACE_ID" --vault-id "$VAULT_ID" --intent-id 0202020202020202020202020202020202020202020202020202020202020202 --asset-id "$ASSET_ID" --destination-id "$DEST_ID" --amount 5

broadcast_transaction 0 --payload upsert_destination --chain-id "$CHAIN_ID" --nonce 9 --signer "$SIGNER" --workspace-id "$WORKSPACE_ID" --destination-id "$DEST_ID" --destination-enabled true --address-or-contract-hex aabb
broadcast_transaction 0 --payload propose_intent --chain-id "$CHAIN_ID" --nonce 10 --signer "$SIGNER" --workspace-id "$WORKSPACE_ID" --vault-id "$VAULT_ID" --intent-id "$INTENT_ID" --asset-id "$ASSET_ID" --destination-id "$DEST_ID" --amount 5
broadcast_transaction 0 --payload approve_intent --chain-id "$CHAIN_ID" --nonce 11 --signer "$SIGNER" --workspace-id "$WORKSPACE_ID" --vault-id "$VAULT_ID" --intent-id "$INTENT_ID"
broadcast_transaction 30 --payload execute_intent --chain-id "$CHAIN_ID" --nonce 12 --signer "$SIGNER" --workspace-id "$WORKSPACE_ID" --vault-id "$VAULT_ID" --intent-id "$INTENT_ID"
broadcast_transaction 0 --payload upsert_attestation --chain-id "$CHAIN_ID" --nonce 13 --signer "$SIGNER" --workspace-id "$WORKSPACE_ID" --subject-id "$WORKSPACE_ID" --claim kyb_verified --issuer "$SIGNER" --attestation-expires-at 999999999999
broadcast_transaction 0 --payload execute_intent --chain-id "$CHAIN_ID" --nonce 14 --signer "$SIGNER" --workspace-id "$WORKSPACE_ID" --vault-id "$VAULT_ID" --intent-id "$INTENT_ID"

asset_key="$($TX_BUILDER query-key --path /state/asset --asset-id "$ASSET_ID")"
intent_key="$($TX_BUILDER query-key --path /state/intent --workspace-id "$WORKSPACE_ID" --vault-id "$VAULT_ID" --intent-id "$INTENT_ID")"
history_key="$($TX_BUILDER query-key --path /history/range --from-height 1 --to-height 100)"
history_export_key="$($TX_BUILDER query-key --path /history/export)"

query_path_expect_ok /state/asset "$asset_key" 0
query_path_expect_ok /state/intent "$intent_key" 1
intent_status="$($TX_BUILDER decode-intent-state --value-base64 "$last_query_value_b64")"
log "intent status decoded=$intent_status"
if [[ "$intent_status" != "executed" ]]; then
  record_query_result "/state/intent.status" "executed" "$intent_status" "${#intent_status}" "FAIL"
  fail "decoded intent status is not executed"
fi
record_query_result "/state/intent.status" "executed" "$intent_status" "${#intent_status}" "PASS"
query_path_expect_ok /history/range "$history_key" 1
history_range_value_len="$last_query_value_len"
query_path_expect_ok /history/export "$history_export_key" 1
history_export_value_len="$last_query_value_len"

log "proof run completed successfully"
log "report: $REPORT_PATH"
