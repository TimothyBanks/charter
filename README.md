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
$ cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_PREFIX_PATH=/your/prefix/path/ ..
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

## clang-format

```
$ ./run-clang-format.sh include/ src/
```