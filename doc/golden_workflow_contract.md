# Golden Workflow Contract (PoC Freeze)

Date: 2026-02-27  
Status: `v1-poc-freeze-draft`

## Purpose

Define one canonical, repeatable custody workflow for:
- demo reproducibility
- regression checks
- external observer validation

If this workflow passes, the PoC is considered behaviorally intact for pilot-facing demonstrations.

## Canonical Workflow

### Scope

Treasury transfer request with policy controls:
- threshold approval
- timelock (optional in positive run, required in timelock variant)
- per-transaction limit
- destination whitelist gate
- claim/attestation gate
- deterministic history/replay evidence

### Canonical Transaction Sequence

1. `create_workspace`
2. `create_vault`
3. `upsert_asset` (`enabled=true`; required onboarding gate)
4. `upsert_destination` (`enabled=false` for negative-path check)
5. `create_policy_set`
6. `activate_policy_set`
7. `propose_intent` (limit-fail case)
8. `propose_intent` (whitelist-fail case)
9. `upsert_destination` (`enabled=true`)
10. `propose_intent` (valid case)
11. `approve_intent`
12. `execute_intent` (claim-fail case)
13. `upsert_attestation`
14. `execute_intent` (success case)

The default executable reference is:
- `tests/run_proof_first_demo.sh`

Jurisdiction behavior note:
- `create_workspace` and `create_vault` may include optional jurisdiction context.
- If workspace jurisdiction is set and vault omits jurisdiction, vault inherits it.
- If both are set and differ, `create_vault` fails with code `42`.

## Expected Result Codes (Canonical)

- Step 1: `0`
- Step 2: `0`
- Step 3: `0`
- Step 4: `0`
- Step 5: `0`
- Step 6: `0`
- Step 7: `28` (limit exceeded)
- Step 8: `29` (destination not whitelisted)
- Step 9: `0`
- Step 10: `0`
- Step 11: `0`
- Step 12: `30` (claim requirement unsatisfied)
- Step 13: `0`
- Step 14: `0`

Run fails if any observed code differs.

## Required Query Assertions

After step 14:
- `/state/asset` returns `code=0` for canonical asset key.
- `/state/intent` returns `code=0` for canonical intent key.
- decoded `intent_state.status == executed`.
- `/history/range` returns `code=0` and includes rows for current run height range.
- `/history/export` returns `code=0` and non-empty payload.

## Required Evidence Artifacts

Each canonical run must produce:
- timestamped run report (text or markdown)
- command/config summary (chain id, signer id, rpc target, script version)
- tx result table with `nonce`, payload type, expected code, observed code
- query assertion section with explicit pass/fail
- exported backup byte length and export byte length

Recommended location:
- `tests/proof_report_<timestamp>.txt`

## Canonical Report Format (Minimum Fields)

The report must include these sections in order:
1. `Run Metadata`
2. `Transaction Results`
3. `Query Assertions`
4. `Export/Backup Summary`
5. `Overall Verdict`

`Overall Verdict` is:
- `PASS` only if every expected code and every query assertion passed.
- `FAIL` otherwise.

## Acceptance Gate (PoC Freeze)

Golden workflow is considered frozen and acceptable when all are true:
- same script passes on clean environment 3 times consecutively
- at least one non-author can run it end-to-end
- report format matches this contract
- no undocumented manual interventions are required

## Change Control

Any change to:
- sequence,
- expected result codes,
- required assertions, or
- required report fields

must update this file and mention reason + date in the changelog section below.

## Changelog

- 2026-02-27: initial `v1-poc-freeze-draft`.
- 2026-03-01: added mandatory `upsert_asset` onboarding step and `/state/asset` query assertion.
- 2026-03-01: documented jurisdiction inheritance/mismatch behavior for workspace/vault bootstrap.
