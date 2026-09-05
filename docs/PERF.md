# Performance envelope (`evaluate()`)

Published before Phase 2 graph work per NFR7. Numbers are **targets** plus a
small local smoke measurement on developer hardware; CI does not gate on them yet.

## Targets (embedded deployment)

| Metric | Target |
|--------|--------|
| `evaluate()` p99 latency | ≤ 1 ms for ≤ 200 policies, ≤ 20 rules/policy, empty context |
| `evaluate()` p99 latency | ≤ 5 ms for ≤ 2_000 policies (same rule depth) |
| Throughput | ≥ 50k decisions/sec single-threaded at 50 policies |
| Memory ceiling (engine + policy set) | ≤ 32 MiB RSS for 2_000 policies in embedded mode |

## Notes

- Session and graph crates **inject** flat context; they are not on the hot path
  inside `lovebird-engine`.
- Graph BFS / attack-path search cost scales with reachable edge count; keep
  online enrichment graphs under ~10k edges for sidecar use, or precompute
  blast-radius fields offline.
- Re-measure and update this doc when `#19` closes with a checked-in microbench.
