from __future__ import annotations

from pathlib import Path

import pytest
from scenario_dsl import (
    ScenarioCase,
    assert_batch_expectations,
    assert_live_expectations,
    assert_no_unexpected_drift,
    load_scenario_cases,
    validate_scenario_case,
)

SCENARIO_ROOT = Path(__file__).parent / "scenarios"
SCENARIOS = load_scenario_cases(SCENARIO_ROOT)


@pytest.mark.parametrize(
    "case",
    [pytest.param(case, id=case.id) for case in SCENARIOS],
)
def test_scenario_file(case: ScenarioCase) -> None:
    validate_scenario_case(case)
    assert_batch_expectations(case)
    assert_live_expectations(case)
    assert_no_unexpected_drift(case)
