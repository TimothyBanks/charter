# feat(policy): cumulative velocity limits

## Type
Feature

## Priority
P1

## Sprint
S2

## Problem
Only per-transaction amount limits are enforced today.

## Scope
- add rolling or fixed window limits (daily/weekly/monthly)
- support per-asset and per-vault counters
- deterministic counter updates during finalize/commit and replay

## Acceptance Criteria
- transactions above window budget fail with deterministic code
- counters are replay-safe and snapshot/restore-safe
- tests cover window boundary and rollover behavior

## Deliverables
- schema for velocity rules
- counter storage keys/state
- engine checks and updates
- tests

