# Query And Keyspace Contract

This document defines the current PoC query contract and the RocksDB keyspace domains used by the execution engine.

## Query Envelope Contract

All query responses use `query_result` with the same envelope semantics:
- `code`: `0` for success, non-zero for errors.
- `codespace`: always `charter.query`.
- `height`: last committed block height.
- `key`: echoes request query key bytes (including error cases).
- `value`: SCALE-encoded payload for successful responses.
- `log`/`info`: human-readable error context when `code != 0`.

Error codes currently used by query paths:
- `1`: invalid key size or invalid key encoding.
- `2`: not found.
- `3`: unsupported path.

## Supported Query Paths

Engine metadata:
- `/engine/info` -> `(last_height, app_hash, chain_id)`
- `/engine/keyspaces` -> `vector<string>` of key prefixes

State queries:
- `/state/workspace`
- `/state/asset`
- `/state/vault`
- `/state/destination`
- `/state/policy_set`
- `/state/active_policy`
- `/state/intent`
- `/state/approval`
- `/state/attestation`
- `/state/role_assignment`
- `/state/signer_quarantine`
- `/state/degraded_mode`
- `/state/destination_update`

History and audit:
- `/history/range`
- `/history/export`
- `/events/range`

## Engine Keyspace Prefixes

The execution engine currently uses these prefixes:
- `SYS|STATE|NONCE|`
- `SYS|STATE|`
- `SYS|STATE|WORKSPACE|`
- `SYS|STATE|ASSET|`
- `SYS|STATE|VAULT|`
- `SYS|STATE|DESTINATION|`
- `SYS|STATE|POLICY_SET|`
- `SYS|STATE|ACTIVE_POLICY|`
- `SYS|STATE|INTENT|`
- `SYS|STATE|APPROVAL|`
- `SYS|STATE|DESTINATION_UPDATE|`
- `SYS|STATE|ATTEST|`
- `SYS|STATE|ROLE_ASSIGNMENT|`
- `SYS|STATE|SIGNER_QUARANTINE|`
- `SYS|STATE|DEGRADED_MODE|`
- `SYS|STATE|EVENT_SEQ|`
- `SYS|STATE|VELOCITY|`
- `SYS|HISTORY|TX|`
- `SYS|EVENT|`
- `SYS|SNAP|`

## Operational Notes

- Prefixes are part of consensus-critical storage layout and should be versioned before changes.
- Query `code/log/info` values are external API surface for SDK/ops tooling and should be treated as compatibility-sensitive.
- `/history/export` is useful for deterministic parity checks across nodes and for backup validation tests.
