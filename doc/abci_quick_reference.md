# ABCI Quick Reference

This is a practical quick reference for the ABCI callbacks used in Charter.

## Lifecycle Order (Typical)

1. `Info` / `InitChain` during startup and handshake.
2. `CheckTx` for mempool admission.
3. `PrepareProposal` on proposer.
4. `ProcessProposal` on validators.
5. `FinalizeBlock` on all validators.
6. `Commit` to persist the finalized state.

Snapshot/state-sync callbacks (`ListSnapshots`, `OfferSnapshot`, `LoadSnapshotChunk`, `ApplySnapshotChunk`) run when nodes sync state.

## Callback Semantics

| Callback | Primary Purpose | State Mutation Expected |
|---|---|---|
| `Echo` | Basic connectivity/liveness echo. | No |
| `Flush` | Request barrier/flush marker. | No |
| `Info` | Report app version, height, and app hash (`state_root`). | No |
| `InitChain` | Initialize chain-facing app state and initial app hash. | Usually no heavy mutation in this implementation |
| `CheckTx` | Mempool tx admission validation. | No |
| `Query` | Read committed application state. | No |
| `PrepareProposal` | Proposer-side tx selection/filtering under limits. | No |
| `ProcessProposal` | Validator-side whole-proposal accept/reject decision. | No |
| `FinalizeBlock` | Deterministically execute block txs and return `ExecTxResult[]` + `app_hash`. | Yes |
| `Commit` | Persist finalized state and return retain height. | Yes (persist only) |
| `ListSnapshots` | Advertise available snapshots for state sync. | No |
| `OfferSnapshot` | Accept/reject snapshot metadata before apply. | No |
| `LoadSnapshotChunk` | Return a specific snapshot chunk to peer. | No |
| `ApplySnapshotChunk` | Apply one chunk during snapshot restore flow. | Yes (restore path) |
| `ExtendVote` | Return validator-signed vote extension payload. | No |
| `VerifyVoteExtension` | Verify another validator's vote extension payload. | No |

## Charter Mapping Notes

- Wire field `app_hash` is treated as **state root** in Charter.
- `CheckTx` and `ProcessProposal` use the same core validation logic for consistency.
- `FinalizeBlock` is the only normal path where transaction execution mutates state.
- Vote extensions are treated as metadata/attestation channel; any enforcement should still happen through normal transactions.
