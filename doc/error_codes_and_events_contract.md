# Charter Error Codes And Events Contract

Date: 2026-02-27  
Status: `v1-contract-draft` (freeze target for pilot integrations)

## Purpose
Define stable, integration-facing behavior for:
- transaction result codes
- query result codes
- persisted security event types and severities

This document is the client/operator contract. Changes must be versioned.

## 1) Transaction Result Code Contract

Codespace values:
- `charter.checktx`
- `charter.proposal`
- `charter.finalize`
- `charter.execute`
- `charter.replay`

Code definitions:

- `0` success
- `1` invalid transaction (decode failed)
- `2` unsupported transaction version
- `3` invalid chain id
- `4` invalid nonce
- `5` invalid signature type
- `6` signature verification failed
- `10` workspace already exists
- `11` workspace missing
- `12` vault already exists
- `13` policy scope missing
- `14` policy set already exists
- `15` policy set missing
- `16` vault scope missing
- `17` active policy missing
- `18` workspace missing (attestation path)
- `19` intent already exists
- `20` policy resolution failed
- `21` intent missing
- `22` intent not approvable
- `23` intent expired
- `24` duplicate approval
- `25` intent already executed
- `26` intent not executable
- `27` attestation missing
- `28` limit exceeded
- `29` destination not whitelisted
- `30` claim requirement unsatisfied
- `31` signer quarantined
- `32` degraded mode active
- `33` authorization denied
- `34` velocity limit exceeded
- `35` separation-of-duties violated
- `36` destination update exists
- `37` destination update missing
- `38` destination update finalized
- `39` destination update not executable
- `40` asset missing
- `41` asset disabled

## 2) Query Result Code Contract

Codespace value:
- `charter.query`

Code definitions:
- `0` success
- `1` invalid key encoding or invalid key size
- `2` not found
- `3` unsupported path

Supported query paths:
- `/engine/info`
- `/engine/keyspaces`
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
- `/history/range`
- `/history/export`
- `/events/range`

## 3) Security Event Type Contract

Persisted in event stream under `/events/range`.

Event type enum (`security_event_type_t`):
- `1` `tx_validation_failed`
- `2` `tx_execution_denied`
- `3` `authz_denied`
- `4` `policy_denied`
- `5` `replay_checkpoint_mismatch`
- `6` `snapshot_rejected`
- `7` `snapshot_applied`
- `8` `backup_import_failed`
- `9` `role_assignment_updated`
- `10` `signer_quarantine_updated`
- `11` `degraded_mode_updated`

Event severity enum (`security_event_severity_t`):
- `0` `info`
- `1` `warning`
- `2` `error`
- `3` `critical`

## 4) Event Record Schema Contract

`security_event_record_t` fields:
- `version`
- `event_id`
- `height`
- `tx_index`
- `type`
- `severity`
- `code`
- `message`
- `signer` (optional)
- `workspace_id` (optional)
- `vault_id` (optional)
- `recorded_at`

Ordering contract:
- `event_id` is monotonically increasing.
- `/events/range` returns records in stored key order for requested id interval.

## 5) Emission Rules (Current Implementation)

Events are emitted for:
- tx validation failures in finalize flow
- tx execution denials
- replay checkpoint mismatch
- snapshot reject/apply outcomes
- backup import failures
- role assignment updates
- signer quarantine updates
- degraded mode updates

Notes:
- Authorization denials map to `authz_denied`.
- Policy-rule denials map to `policy_denied`.
- Integrators should key off both `type` and `code`.

## 6) Compatibility Rules

For pilot compatibility:
- Existing codes/events are append-only.
- Numeric meaning of existing codes/events must not change.
- New codes/events may be added, but never repurposed.
- Removing a code/event requires major contract version bump.

Contract versioning:
- This document version tag: `v1-contract-draft`.
- On freeze, promote to `v1`.

## 7) Client Guidance

Clients should:
- treat unknown non-zero tx code as failure, log full `(code, log, info, codespace)`.
- treat unknown query code as failure, log full `(code, log, info, codespace)`.
- tolerate unknown event `type` values by preserving raw record for forward compatibility.

## 8) Freeze Checklist

- [ ] All codes above covered by positive/negative tests.
- [ ] Event emission coverage tests for each event type.
- [ ] Docs and test fixtures reference same numeric constants.
- [ ] Sign-off completed for pilot contract freeze (`v1`).
