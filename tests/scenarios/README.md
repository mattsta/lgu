# Detector Scenario Fixtures

Scenario JSON files are test-only fixtures for locking detector behavior without
copying production logs into the repository.

Rules:

- Use RFC 5737 IP aliases such as `doc:1:44`, `doc:2:44`, or `doc:3:44`.
- Use `/synthetic/...` paths only.
- Use `.example.test` referer aliases such as `referrer` or `alt_referrer`.
- Preserve behavior shape: timing, path cardinality, referer dominance, UA family,
  and expected proof kinds.

Supported top-level fields:

- `name`: stable scenario id.
- `args`: optional CLI threshold overrides, including `detector_config`.
- `actors`: named traffic sources with `ip`, `ua`, `referer`, `method`, `status`.
- `events`: row definitions, including `repeat` and nested repeated `events`.
- `expect.batch`: `bots`, `clean`, `proofs`, `absent_proofs`, `reasons`,
  `absent_reasons`, `actions`, `max_action`, and `max_score`.
- `expect.live`: expected emitted `action` and `reasons`, plus guards such as
  `forbidden_actions`, `max_action`, `max_score`, and `absent_reasons`.

The harness lives in `tests/scenario_dsl.py`.

To inspect actual detector outcomes before locking expectations:

```bash
uv run python tests/scenario_probe.py tests/scenarios/per_ip.json
```

To sanitize a log snippet into a draft scenario:

```bash
uv run python tests/scenario_sanitize.py ./snippet.log --name new_bot_shape
```

To run the full intake loop in one command, including sanitation, probing, and
expectation-stub generation:

```bash
uv run python tests/scenario_intake.py ./snippet.log --name new_bot_shape
uv run python tests/scenario_intake.py ./snippet.log --name new_bot_shape --scenario-only
```

To see which detector expectations have positive, negative, and live coverage:

```bash
uv run python tests/scenario_matrix.py tests/scenarios
uv run python tests/scenario_matrix.py tests/scenarios --check-catalog
```

Scenario files are schema-checked by `tests/scenario_dsl.py`. Unknown keys,
unknown actor references, unknown detector kinds, empty event lists, and
unexpected proof/reason drift fail the validation gate.
