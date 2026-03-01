# feat(ops): observability metrics and explorer/read stack

## Type
Feature

## Priority
P1

## Sprint
S2

## Problem
Public devnet requires credible visibility and read UX, but app-level metrics and explorer-oriented APIs were not previously formalized.

## Scope
- freeze app metrics payload contract exposed at `/metrics/engine`
- build reference exporter (`/metrics/engine` -> Prometheus text format)
- build minimal explorer/indexer using:
  - `/explorer/overview`
  - `/explorer/block`
  - `/explorer/transaction`
- publish Grafana baseline dashboard JSON

## Acceptance Criteria
- Prometheus can scrape app metrics via exporter on a fixed interval
- Grafana dashboard shows chain health + custody-policy indicators
- explorer/indexer can serve latest block + tx detail views without direct RocksDB access
- read API behavior documented with request/response encoding examples

## Deliverables
- exporter utility + tests
- indexer service + tests
- dashboard templates
- doc updates and runbook
