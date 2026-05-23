# Detector Sweep Fixtures

Sweep fixtures generate scenario variants from one synthetic base case. They are
for threshold tuning boundaries where the important question is whether
`threshold - 1`, exact threshold, and nearby timing variants behave as intended.

Run them directly:

```bash
uv run python tests/scenario_sweeps.py tests/sweeps --check
uv run python tests/scenario_sweeps.py tests/sweeps --format json --check
```

Schema:

- `name`: stable sweep id
- `base`: a regular scenario object without a `name`
- `variants`: named variants
- `covers`: machine-readable coverage metadata with detector `kind`, threshold
  `args`, and `boundary` such as `below`, `at`, or `above`
- `set`: dotted paths to override in the generated scenario
- `merge`: optional nested object merge for larger expectation changes

`covers` is not just bookkeeping. Validation links it back to expectations:
`at` variants must assert the covered detector as a positive proof, reason, or
live emission; `below` and `above` variants must assert the covered detector as
an absent proof or reason.

`tests/sweeps/coverage_policy.json` defines the threshold boundaries that are
required by the validation gate. Numeric catalog threshold arguments should have
policy-backed sweep coverage. Use `deferred` only for configuration inputs that
are not meaningful numeric boundary sweeps, such as regex pattern lists or
provider data source selection. `tests/detector_report.py` should normally show
zero blocking or advisory tasks after policy-backed sweeps are current.
Policy validation also checks that every catalog threshold argument is classified
exactly once, so adding a detector knob without either sweep coverage or an
explicit deferral fails the gate.

Current sweep families cover:

- heuristic burst request count, path cardinality, and time window boundaries
- HEAD burst request count and path cardinality boundaries
- paced sweep count, path cardinality, referer dominance, and time window boundaries
- fast streak count and gap boundaries
- fast streak path-diversity boundaries
- repeated-pair count and gap boundaries
- tight multi-fetch count, path-cardinality, same-second, referer-ratio, and window boundaries
- cadenced-repeat count, min-gap, tolerance, near-hour shortcut, and referer-ratio boundaries
- redundant revisit path, repeat-count, and referer-ratio boundaries
- rotating UA raw-count and family-count boundaries
- periodic poller repeat-count and interval boundaries
- serial sweep count, path-cardinality, min-gap, and max-gap boundaries
- coordinated UA count, path-cardinality, IP-cardinality, max-share, and window boundaries
- target-fanout count, IP-cardinality, max-share, referer-ratio, and window boundaries
- payload campaign count, IP-cardinality, path-cardinality, and window boundaries
- payload-fuzzer, same-second UA swap, and rapid UA-switch proof boundaries
- provider-hosted activity request count, path cardinality, and minimum score boundaries

Sweep data follows the same safety rules as normal scenarios: RFC 5737
documentation IP aliases, `/synthetic/...` paths, and reserved `.example.test`
referers only.
