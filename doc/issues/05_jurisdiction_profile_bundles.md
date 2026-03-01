# feat(policy): jurisdiction profile bundles

## Type
Feature

## Priority
P2

## Sprint
S3

## Problem
Policy has claim gates but no jurisdiction-specific control bundles.

Current baseline already implemented:
- optional jurisdiction context on `create_workspace_t` / `create_vault_t`
- vault inherits workspace jurisdiction when omitted
- mismatched workspace/vault jurisdiction is rejected (`code=42`)

This issue tracks the next step: policy/profile bundles keyed by jurisdiction.

## Scope
- define profile object:
  - required claims
  - destination constraints
  - threshold templates
- attach profile to workspace/vault scope
- apply profile constraints during policy resolution
- support profile versioning

## Acceptance Criteria
- profile selection changes effective controls deterministically
- mismatched transactions fail with clear profile/policy denial reason
- tests cover at least two profile variants

## Deliverables
- profile schema
- engine merge/enforcement logic
- tests
- documentation with examples
