# feat(export): regulator evidence bundle v1

## Type
Feature

## Priority
P2

## Sprint
S3

## Problem
Backup/export exists but lacks a regulator-targeted manifest and verification workflow.

## Scope
- define export manifest v1:
  - chain id
  - height range
  - hash commitments
  - replay checkpoint info
- include signed manifest hash support
- add verification utility/workflow

## Acceptance Criteria
- independent verifier can reproduce replay result from bundle
- bundle includes deterministic manifest and integrity hash
- workflow docs include end-to-end verification steps

## Deliverables
- schema/format docs
- engine export update
- verifier utility/tests

