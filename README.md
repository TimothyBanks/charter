# Charter

A blockchain that embraces institutional custody instead of pretending it doesn’t exist.

A custody-native blockchain designed for regulated digital asset governance.

Most digital asset custody systems today rely on off-chain workflow engines, internal approval databases, and opaque operational processes. Even when exchanges and institutions use advanced MPC or multi-sig infrastructure, governance enforcement, compliance checks, and policy controls typically live outside the ledger.

The Custody Protocol rethinks this architecture.

Instead of treating governance and compliance as peripheral systems, this protocol embeds them directly into a deterministic state machine backed by BFT consensus.

Core principles

- Multi-party authorization enforced at the state machine level
- Deterministic policy execution (thresholds, timelocks, limits)
- Destination whitelisting
- Compliance attestation gating
- Immutable audit artifacts (approvals + attestations)
- Canonical binary encoding (SCALE)
- Deterministic RocksDB-backed state
- Consensus-agnostic design (CometBFT → Concord-BFT)

This project does not aim to eliminate centralized oversight.

It formalizes institutional control into programmable, auditable, cryptographically verifiable governance rules.

The goal is to create custody infrastructure that satisfies regulatory requirements without abandoning the transparency and determinism that make blockchain valuable.

# License
Proprietary — All rights reserved. See LICENSE.

# Building

```
$ git clone https://github.com/TimothyBanks/charter.git
$ git submodule update --init --recursive
$ cd charter
$ mkdir build.debug
$ cd build.debug
$ cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_PREFIX_PATH=/your/prefix/path/ -DWITH_PCH=ON ..
$ make
```

## Running

This project uses CometBFT. You will first want to update the CometBFT config file to use gRPC.
```
$ vim ~/.cometbft/config/config.toml
```
Set `abci = "grpc"`

Set `proxy_app = "127.0.0.1:26658"`

Save these changes.

Start the charter process. Assuming you are in the build folder.
```
$ ./charter
```

Then start CometBFT
```
$ cometbft node
```

You can also run the golden workflow for the PoC
```
$ REPORT_PATH=/tmp/proof_report.txt START_LOCAL=1 ALLOW_INSECURE_CRYPTO=1 CHARTER_GRPC_ADDR=127.0.0.1:36658 COMET_RPC=http://127.0.0.1:36657 bash ./tests/run_proof_first_demo.sh
```

## Onboarding Checklist

Use this as the default first-day setup and verification flow.

1. Build the project in `build.debug`.
2. Start `charter` and `cometbft` with gRPC ABCI settings.
3. Run the full test suite:
```
$ ./build.debug/charter_tests
```
4. Run the canonical PoC workflow script:
```
$ START_LOCAL=1 ALLOW_INSECURE_CRYPTO=1 tests/run_proof_first_demo.sh
```
5. Confirm the proof report is generated under `tests/` and ends in success.
6. Validate key state queries from the proof flow:
   - `/state/asset` returns `code=0`
   - `/state/intent` returns `code=0`
   - `/history/range` returns `code=0`
7. Review workflow and contract docs before making behavior changes:
   - `doc/workflow_playbooks.md`
   - `doc/golden_workflow_contract.md`
   - `doc/operation_happy_failure_paths.md`
   - `doc/transaction_workflow_matrix.md`

Note: asset onboarding (`upsert_asset`) is required before transfer intents; missing or disabled assets fail with codes `40`/`41`.
Note: strict crypto mode requires real public-key signers and valid signatures.
The current PoC script uses placeholder signatures, so strict mode will fail at
`CheckTx` with code `6` (`signature_verification_failed`).

## Chat Recovery Log

Use the in-repo history log to recover context after a lost chat session.

Log file:
`doc/chat_history.md`

Append an entry:
```
$ scripts/chatlog.sh \
    --title "Short session title" \
    --summary "What was done and what state we are in." \
    --decisions "Key decisions made in this session." \
    --next "Next concrete step."
```

Required args:
- `--title`
- `--summary`

## clang-format

```
$ ./run-clang-format.sh include src tests/include tests/src
```
