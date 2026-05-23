# Changelog

## Unreleased

### Added

- Standard `uv` project packaging with installable `log-audit` and `log-watch` entrypoints
- Release-grade docs:
  - `ARCHITECTURE.md`
  - `THREAT_MODEL.md`
  - `DETECTORS.md`
  - `CONFIG.md`
  - `OPERATIONS.md`
  - `PERFORMANCE.md`
  - `TESTING.md`
  - `CONTRIBUTING.md`
- Example site-specific detector config
- MIT license
- `tests/` suite covering live transitions, distributed detector degradation, and batch execution equivalence
- `tight-multifetch` and `cadenced-repeat` proof detectors for compact synthetic fetch clusters and long-gap scheduled same-path repeats
- Near-hour two-hit shortcut thresholds for `cadenced-repeat` so sparse scheduled refetches can be categorized without waiting for a third hit
- Synthetic scenario DSL, sanitizer, probe, coverage matrix, and catalog gate for detector proof workflows
- Detector catalog documenting proof kinds, threshold arguments, config dependencies, and live coverage requirements
- Optional provider IP range enrichment through pluggable local source adapters
- Explicit `--exclude-provider-traffic` mode for removing loaded provider-hosted ranges from filtered outputs
- Clear `--raw-filtered-lines` output-mode flag for exact raw log-line replay
- Default known-UA coverage for social preview fetchers whose user agents omit generic bot/crawler terms
- Exact-UA same-target distributed fanout mode under `coordinated-target-fanout` for tight cross-IP bursts
- `asset-primed-probe` proof detector for browser-like page dependency loads followed by exposed-file probing
- Local and CI detector-quality gate covering compile checks, linting, scenario catalog coverage, and pytest
- Detector sweep fixtures for threshold boundary variants
- End-to-end detector validation harness covering compile checks, catalog coverage, threshold sweeps, synthetic-data hygiene, linting, and pytest from one command
- Scenario execution, schema validation, unexpected-output drift checks, and catalog-backed sweep coverage metadata in the detector validation gate
- Detector confidence report and scenario intake workflow for example-driven detector development
- Heuristic and optional-provider detector coverage in the scenario catalog gate
- Threshold boundary sweeps for heuristic and provider-hosted activity rules, with policy-level deferred configuration knobs
- Additional proof threshold sweeps for repeated-pair gap, tight multi-fetch, cadenced-repeat, and fast-streak path diversity boundaries
- Policy-backed threshold sweeps for all numeric detector catalog arguments, including revisit, UA rotation, periodic polling, serial sweep, payload fuzzer, UA switch, coordinated UA, target fanout, and payload campaign rules
- Stricter detector validation that fails on any generated confidence-report task and rejects incomplete or inconsistent sweep-policy threshold classifications
- `low-context-fanout` and `low-context-revisit` proof detectors for distributed or repeated same-target content fetches with only direct/root referer context

### Changed

- Detector defaults moved into packaged JSON config instead of shipped hardcoded detector data
- Payload-marker handling generalized so site-specific query semantics are config-driven
- Strong proof ban policy now reads from the detector catalog instead of a local literal set
- Grouped recent view improved for readability and numbering
- `ARCHITECTURE.md` expanded with real dataflow, threat model, detector taxonomy, and future live-engine redesign

### Fixed

- `--bots-only` mode semantics
- `--emit-suspects` live suppression behavior
- stale live IP state retention
- distributed detector overload behavior so key detectors degrade instead of disappearing
- multiprocessing payload-marker configuration hazard
- repeated known-bot regex compilation in hot paths
- live engine architecture to use incremental per-IP state and incremental distributed windows instead of rescanning retained global history each event
- live operator status output and stronger suspicious-summary ordering
- runtime detector configuration to use explicit runtime objects instead of process-global mutable detector state

### Known limitations

- distributed overload handling is still recency-biased within bounded windows
- LGU is still tuned for scoped operator workflows rather than arbitrary unbounded event rates
