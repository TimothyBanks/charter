#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_FILE_DEFAULT="$ROOT_DIR/doc/chat_history.md"

title=""
summary=""
decisions=""
next_steps=""
log_file="$LOG_FILE_DEFAULT"

usage() {
  cat <<'EOF'
Usage:
  scripts/chatlog.sh --title "..." --summary "..." [--decisions "..."] [--next "..."] [--log-file /path/to/file]

Example:
  scripts/chatlog.sh \
    --title "Engine error/event contract review" \
    --summary "Rebuilt context from docs and tests, confirmed tx code matrix coverage." \
    --decisions "Treat doc/error_codes_and_events_contract.md as pilot contract draft." \
    --next "Complete freeze checklist and add remaining event coverage tests."
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --title)
      title="${2:-}"
      shift 2
      ;;
    --summary)
      summary="${2:-}"
      shift 2
      ;;
    --decisions)
      decisions="${2:-}"
      shift 2
      ;;
    --next)
      next_steps="${2:-}"
      shift 2
      ;;
    --log-file)
      log_file="${2:-}"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$title" || -z "$summary" ]]; then
  echo "Both --title and --summary are required." >&2
  usage >&2
  exit 1
fi

mkdir -p "$(dirname "$log_file")"
if [[ ! -f "$log_file" ]]; then
  cat >"$log_file" <<'EOF'
# Chat History

This file is a durable context log for recovering from lost chat sessions.
Append entries with `scripts/chatlog.sh`.
EOF
fi

timestamp_utc="$(date -u +"%Y-%m-%d %H:%M:%SZ")"
git_branch="$(git -C "$ROOT_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")"
git_head="$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")"

{
  echo
  echo "## $timestamp_utc - $title"
  echo "- Branch: \`$git_branch\`"
  echo "- Commit: \`$git_head\`"
  echo "- Summary: $summary"
  if [[ -n "$decisions" ]]; then
    echo "- Decisions: $decisions"
  fi
  if [[ -n "$next_steps" ]]; then
    echo "- Next: $next_steps"
  fi
} >>"$log_file"

echo "Appended chat history entry to $log_file"
