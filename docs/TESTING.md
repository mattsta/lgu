# Testing

## Purpose

This document explains how to validate LGU today and what classes of tests should exist as the system evolves.

## Baseline Checks

### Detector validation gate

```bash
uv sync --group dev
UV_CACHE_DIR=$PWD/.uv-cache uv run python tests/detector_validation.py
bash scripts/run_detector_quality.sh
```

`tests/detector_validation.py` is the top-level correctness gate. It compiles the detector entrypoints, validates scenario catalog coverage, executes every scenario with schema and unexpected-output drift checks, runs threshold sweeps with catalog-backed coverage metadata, checks that docs/examples/scenarios remain synthetic, runs the confidence report, runs lint, and executes the full xdist pytest suite. The confidence-report step fails on any generated task, including advisory threshold-expansion work; new detector catalog knobs must be sweep-covered or explicitly deferred before the gate is green. `scripts/run_detector_quality.sh` is the CI/local wrapper around the same gate.

The companion confidence report shows the current coverage state and generated work queue:

```bash
uv run python tests/detector_report.py
uv run python tests/detector_report.py --format json
```

### Pytest suite

```bash
uv sync --group dev
UV_CACHE_DIR=$PWD/.uv-cache uv run pytest -q
uv run pytest -n 20 -q
```

The project keeps `pytest`, `pytest-xdist`, and `hypothesis` in the `dev` dependency group so the release package stays lean while the test runner remains part of the supported development workflow.

## Detector Proof Workflow

Detector changes should move through one scenario pipeline instead of a series of ad hoc fixtures:

1. sanitize any real access-log snippet before it enters tests
2. encode the behavior as a JSON scenario under `tests/scenarios/`
3. assert both positive behavior and near-miss false-positive boundaries
4. inspect the scenario matrix for missing detector proof coverage
5. add sweep coverage metadata for threshold boundaries when a rule has tunable thresholds
6. run the detector validation gate

Useful commands:

```bash
uv run python tests/scenario_intake.py ./snippet.log --name new_shape
uv run python tests/scenario_intake.py ./snippet.log --name new_shape --scenario-only
uv run python tests/scenario_sanitize.py ./snippet.log --name new_shape
uv run python tests/scenario_probe.py tests/scenarios/per_ip.json
uv run python tests/scenario_matrix.py tests/scenarios
uv run python tests/scenario_matrix.py tests/scenarios --check-catalog
uv run python tests/scenario_matrix.py tests/scenarios --format json
uv run python tests/scenario_sweeps.py tests/sweeps --check
uv run python tests/detector_report.py --format json
uv run python tests/detector_validation.py --skip-runtime
uv run pytest -n 20 -q
uv run ruff check .
bash scripts/run_detector_quality.sh
```

Scenario fixtures must use synthetic data only:

- IPs should be RFC 5737 aliases such as `doc:1:40`
- paths should live under `/synthetic/`
- referers should be `-` or reserved `.example.test` hosts
- `args` overrides must match real batch or live parser destinations
- `detector_config` overrides must match `DetectorConfig` fields
- expectation actor references must name declared actors or use `*`

The intended review question for every detector rule is: which scenario proves the rule fires, which scenario proves it stays quiet just below threshold, which sweep locks the threshold edge, and which scenario proves live mode emits the expected action without unexpected proof or reason drift?

`tests/detector_validation.py --skip-runtime` is useful while editing scenarios because it still checks compilation, catalog coverage, sweeps, and synthetic hygiene while skipping subprocess-heavy lint and pytest runtime checks.

Threshold boundary work should use `tests/sweeps/` when one base behavior needs multiple near-threshold variants. Sweeps generate ordinary scenario cases, so they reuse the same synthetic-data validation and batch/live expectation checks.

## Recommended Test Layers

### Parser tests

Validate:

- access-log structure parsing
- malformed line handling
- request parsing
- timestamp parsing

### Aggregation tests

Validate:

- burst behavior
- HEAD burst behavior
- paced sweep behavior
- fast streak behavior
- known-bot signature tagging

### Proof detector tests

Each proof detector should have explicit fixtures.

Examples:

- repeated pair
- rotating UA
- periodic poller
- serial sweep
- payload fuzzer
- same-second UA swap
- rapid UA switch
- coordinated UA
- payload campaign

JSON scenario coverage should include at least one positive, one absent/negative, and one live-positive expectation for every cataloged detector kind: heuristics, proofs, and optional proofs. The matrix gate is the quick check for this:

```bash
uv run python tests/scenario_matrix.py tests/scenarios --check-catalog
```

Threshold sweeps should include `covers` metadata for the detector kind, threshold argument, and boundary type. The required boundary set lives in `tests/sweeps/coverage_policy.json`; policy validation rejects unknown detector kinds, unknown threshold arguments, duplicate classifications, missing boundaries, and catalog threshold arguments that are neither required nor deferred. Sweep coverage metadata must also match expectation semantics: `at` variants assert a positive proof/reason/live emission, while `below` and `above` variants assert an absent proof or reason. The policy can mark non-numeric configuration inputs as `deferred` so the task queue stays focused on tunable thresholds. Current required sweeps cover every numeric catalog threshold across heuristic rules, per-IP proof rules, distributed proof rules, and provider-hosted activity rules. The only deferred threshold arguments are configuration inputs such as regex lists and provider data source selection.

### Batch mode tests

Validate:

- grouped recent view
- `--bots-only`
- `--raw-filtered-lines`
- `--summary`

### Live transition tests

Validate:

- clean -> suspect
- clean -> ban
- suspect suppression
- suspect -> ban escalation
- cooldown suppression
- stale state eviction

### Equivalence tests

Validate:

- `jobs=1` vs `jobs>1`
- file input vs spooled `stdin`
- same config loaded through different supported paths

### Overload tests

Validate:

- bounded distributed detector behavior above caps
- no total detector disappearance under overload

## Fixture Design

Good fixtures should be:

- small
- explicit
- explainable by inspection
- tied to one behavior at a time

## Recommended Validation Workflow

Before shipping a detector change:

1. run `uv run python tests/detector_validation.py --skip-runtime`
2. run `uv run python tests/scenario_intake.py ./snippet.log --name new_shape` for any example-driven rule
3. encode or update a JSON scenario for the behavior
4. add or update threshold sweep metadata if a tunable threshold changed
5. run `uv run python tests/detector_report.py --format json` and resolve blocking tasks
6. compare pre/post batch summary output on a sanitized representative sample
7. compare pre/post live event behavior on the same sanitized sample
8. inspect one human-readable output mode and one machine-readable output mode
9. run `bash scripts/run_detector_quality.sh`
