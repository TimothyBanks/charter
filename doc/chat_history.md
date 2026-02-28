# Chat History

This file is a durable context log for recovering from lost chat sessions.
Append entries with `scripts/chatlog.sh`.

## 2026-02-27 04:53:17Z - Lost chat recovery baseline
- Branch: `main`
- Commit: `751a602`
- Summary: Established durable in-repo chat history logging. Reconstructed current project context from doc/, src/, and tests.
- Decisions: Use doc/chat_history.md as the canonical recovery log for future sessions.
- Next: Append an entry at the end of each substantial session or major decision.

## 2026-02-27 04:56:14Z - Unit test re-pass before weekend review
- Branch: `main`
- Commit: `751a602`
- Summary: Ran ctest and 3x shuffled gtest repeats; all tests passed.
- Decisions: No immediate additional unit-test pass required before manual code review.
- Next: Spend weekend on code review/refactor candidates; rerun tests after any non-trivial changes.

## 2026-02-27 05:01:56Z - Golden workflow tightened
- Branch: `main`
- Commit: `751a602`
- Summary: Added a frozen golden workflow contract with canonical tx sequence, expected result codes, required query assertions, and report schema.
- Decisions: Use doc/golden_workflow_contract.md as source of truth for PoC demo acceptance.
- Next: Align tests/run_proof_first_demo.sh output sections with the contract headings and run 3 consecutive proof runs.

## 2026-02-28 03:33:56Z - PoC build-system acceleration and modular target split
- Branch: `main`
- Commit: `59eaaa6`
- Summary: Reworked CMake to stop compiling shared sources per-target: first introduced a shared static core, then split it into layered libs (schema_core, crypto_core, storage_core, execution_core, abci_core). Rewired charter, transaction_builder, and charter_tests to link the layered libs and kept PCH usage for heavy scale headers.
- Decisions: Keep modular static-library layering as the default build graph for faster incremental rebuilds; transaction_builder should stay decoupled from execution/abci.
- Next: Run full configure/build+ctest on workstation with Boost 1.90+ available; if green, keep this as the PoC release build layout and finish weekend code review.
