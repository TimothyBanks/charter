# feat(policy): actor authorization model and enforcement

## Type
Feature

## Priority
P0

## Sprint
S1

## Problem
Policy checks exist, but actor-role authorization is not enforced per operation.

## Scope
- add role model for workspace/vault (`initiator`, `approver`, `admin`)
- enforce role checks in:
  - `create_policy_set`
  - `activate_policy_set`
  - `propose_intent`
  - `approve_intent`
  - `execute_intent`
  - attestation operations
- add deterministic storage/query for role assignments

## Acceptance Criteria
- unauthorized actor attempts fail with explicit code and codespace
- unit/integration tests cover authorized and unauthorized paths
- docs include role matrix by operation

## Deliverables
- schema updates
- engine enforcement logic
- tests
- doc updates
