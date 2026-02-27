# Low-Hanging Fruit Status (Items 2-8)

This tracks the quick-win hardening pass requested before deeper productionization.

## 2) Error-Code Normalization

Implemented:
- Velocity-limit denial path now uses shared `make_error_tx_result(...)`.
- Shared codespace constants are used for `check_tx`, proposal processing, execute, and query.

Result:
- Error logging and envelope shape are more consistent across failure paths.

## 3) Query Contract Consistency

Implemented:
- `query()` now uses a shared local error helper.
- Error results always echo the request key bytes.
- `codespace` is consistently `charter.query`.
- Added `/engine/keyspaces` introspection endpoint.

Result:
- Client behavior can assume stable envelope semantics regardless of path outcome.

## 4) Determinism Guardrails

Implemented:
- Integration test runs two independent nodes through the same sequence and asserts deterministic reproducibility signals:
  - both exports/backups are non-empty
  - restored node can import backup and replay successfully
  - restored export is non-empty and queryable

Result:
- Provides practical determinism/replay smoke coverage without brittle byte-for-byte assumptions across independent runs.

## 5) Replay/Backup Smoke Coverage

Implemented:
- Integration test imports backup into a new node, replays history, and verifies exported history parity.

Result:
- Validates practical restore-and-replay behavior for PoC demos and failure drills.

## 6) Storage Keyspace Audit

Implemented:
- Canonical keyspace list centralized in engine constants.
- Added docs in `doc/query_and_keyspace_contract.md`.
- Added runtime introspection query `/engine/keyspaces`.

Result:
- Reduces risk of accidental key collisions and improves operator visibility.

## 7) Minimal Encoding Golden Vectors

Implemented:
- Unit test added for a fixed, deterministic `transaction_t` (`create_workspace`) encoded byte vector.

Result:
- Catches accidental schema/encoding drift.

## 8) Startup Diagnostics

Implemented:
- Main startup logs runtime config and crypto backend availability.
- Engine initialization logs db path, snapshot interval, strict crypto mode, and chain id.

Result:
- Faster bring-up triage and clearer run configuration in logs.

## Remaining Easy Follow-Ups

These are still low effort and can be done next without deep refactors:
- Add golden vectors for one `intent_state_t` and one `policy_set_state_t`.
- Add query-path fixture tests for all supported paths’ error envelopes.
- Add startup metric counters (tx accepted/denied, replay applied, snapshot count) in periodic logs.
