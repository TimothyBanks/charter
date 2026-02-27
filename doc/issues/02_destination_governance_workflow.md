# feat(destination): governance workflow for whitelist entries

## Type
Feature

## Priority
P0

## Sprint
S1

## Problem
Destination upsert is direct; no approval/timelock governance flow for destination changes.

## Scope
- add destination governance transactions:
  - propose destination change
  - approve destination change
  - activate/disable destination
- add optional timelock on destination activation
- record proposer/approver and activation time

## Acceptance Criteria
- destination changes require configured approvals before becoming effective
- execution path reads only active destination state
- regression tests cover bypass attempts and timing/race edges

## Deliverables
- transaction/schema additions
- engine logic
- tests
- workflow doc updates

