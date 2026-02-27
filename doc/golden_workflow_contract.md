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
3. `upsert_destination` (`enabled=false` for negative-path check)
4. `create_policy_set`
5. `activate_policy_set`
6. `propose_intent` (limit-fail case)
7. `propose_intent` (whitelist-fail case)
8. `upsert_destination` (`enabled=true`)
9. `propose_intent` (valid case)
10. `approve_intent`
11. `execute_intent` (claim-fail case)
12. `upsert_attestation`
13. `execute_intent` (success case)

The default executable reference is:
- `tests/run_proof_first_demo.sh`

## Expected Result Codes (Canonical)

- Step 1: `0`
- Step 2: `0`
- Step 3: `0`
- Step 4: `0`
- Step 5: `0`
- Step 6: `28` (limit exceeded)
- Step 7: `29` (destination not whitelisted)
- Step 8: `0`
- Step 9: `0`
- Step 10: `0`
- Step 11: `30` (claim requirement unsatisfied)
- Step 12: `0`
- Step 13: `0`

Run fails if any observed code differs.

## Required Query Assertions

After step 13:
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
