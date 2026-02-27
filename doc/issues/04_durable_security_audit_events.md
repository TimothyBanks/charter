# feat(events): durable security/audit event stream

## Type
Feature

## Priority
P1

## Sprint
S2

## Problem
Security and audit signals are mostly logs; they are not first-class queryable state.

## Scope
- define `event_record_t` and persistent event storage prefix
- emit events for:
  - transaction validation/execution failures
  - policy denials
  - replay mismatch
  - snapshot reject/restore outcomes
- add `/events/range` query endpoint

## Acceptance Criteria
- events are persisted with deterministic ordering and event type
- events are included in backup/export artifacts
- integration tests validate emitted events for negative workflow paths

## Deliverables
- schema/types
- storage and query implementation
- engine event emission wiring
- tests
- docs

