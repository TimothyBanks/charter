# Matrix Coverage Status

Date: 2026-02-27

## Scope
This file maps the policy/error matrix and security-event matrix to runnable tests.

## Tx Error Code Coverage
Covered by `tests/src/execution/engine_integration_test.cpp`:

- `engine_integration.tx_error_code_matrix_coverage`
  - Asserts coverage of all current tx denial/validation codes:
  - `1,2,3,4,5,6,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39`

Additional focused integration tests (behavior-specific):

- `engine_integration.timelock_blocks_then_allows_execute` (`26 -> 0` path)
- `engine_integration.limit_and_whitelist_are_enforced` (`28`, `29`)
- `engine_integration.claim_gating_blocks_until_attested` (`30 -> 0`)
- `engine_integration.query_errors_echo_key_and_codespace` (query contract error path)

## Security Event Coverage
Covered by `tests/src/execution/engine_integration_test.cpp`:

- `engine_integration.security_event_type_coverage`
  - Validates persisted event type IDs:
  - `1,2,4,6,7,8,9,10,11`
- `engine_integration.authz_denied_emits_type3_event`
  - Validates event type:
  - `3`
- `engine_integration.replay_mismatch_emits_type5_event`
  - Validates event type:
  - `5`

Notes:
- Event assertions are based on numeric type IDs to avoid enum-value drift issues while retaining deterministic validation.

## Replay/Snapshot/Backup Coverage
Covered by:

- `engine_integration.backup_replay_and_state_queries_work`
- `engine_integration.deterministic_history_export_matches_across_nodes`
- `engine_integration.security_event_type_coverage`

These cover backup import/export, replay behavior, and snapshot offer/apply surfaces.

## Current Gaps
- No additional gap in current tx code matrix (`1..39` where defined) from test perspective.
- Event-stream semantics still rely on implemented event IDs and should be revalidated if enum contract changes.
