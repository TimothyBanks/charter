# feat(policy): jurisdiction profile bundles

## Type
Feature

## Priority
P2

## Sprint
S3

## Problem
Policy has claim gates but no jurisdiction-specific control bundles.

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

