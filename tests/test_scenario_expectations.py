from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from scenario_dsl import (
    ScenarioCase,
    assert_batch_expectations,
    assert_live_expectations,
    assert_no_unexpected_drift,
    validate_scenario_case,
)

CASE_PATH = Path("synthetic_expectations.json")


def make_case(expect: dict[str, Any]) -> ScenarioCase:
    return ScenarioCase(
        path=CASE_PATH,
        data={
            "name": "synthetic_expectation_primitives",
            "args": {"cadence_hour_repeat_count": 99},
            "actors": {
                "bot": {
                    "ip": "doc:2:90",
                    "ua": "chrome_133",
                    "referer": "-",
                },
                "human": {
                    "ip": "doc:1:90",
                    "ua": "chrome_120",
                    "referer": "https://reader.example.test/",
                },
            },
            "events": [
                {
                    "actor": "bot",
                    "repeat": 3,
                    "every": 3660,
                    "path": "/synthetic/expectation-cadence-target",
                },
                {
                    "actor": "human",
                    "at": 120,
                    "path": "/synthetic/expectation-human-read",
                },
            ],
            "expect": expect,
        },
    )


def complete_expectations() -> dict[str, Any]:
    return {
        "batch": {
            "bots": ["bot"],
            "clean": ["human"],
            "proofs": {"bot": ["cadenced-repeat"]},
            "reasons": {"bot": ["cadenced-repeat"]},
            "absent_reasons": {
                "bot": ["tight-multifetch"],
                "human": ["cadenced-repeat"],
            },
            "actions": {"bot": "ban", "human": "clean"},
            "max_action": {"bot": "ban", "human": "clean"},
            "max_score": {"*": 10.0},
        },
        "live": {
            "emission_count": 1,
            "emissions": [
                {"actor": "bot", "action": "ban", "reasons": ["cadenced-repeat"]}
            ],
            "no_emissions": ["human"],
            "forbidden_actions": {
                "bot": ["suspect"],
                "human": ["suspect", "ban"],
            },
            "max_action": {"*": "ban", "human": "clean"},
            "max_score": {"bot": 10.0},
            "absent_reasons": {
                "bot": ["tight-multifetch"],
                "human": ["cadenced-repeat"],
            },
        },
    }


def test_stronger_expectation_primitives_pass_for_synthetic_scenario() -> None:
    case = make_case(complete_expectations())

    validate_scenario_case(case)
    assert_batch_expectations(case)
    assert_live_expectations(case)
    assert_no_unexpected_drift(case)


def test_scenario_schema_rejects_unknown_expectation_key() -> None:
    expect = complete_expectations()
    expect["batch"]["botz"] = ["bot"]
    case = make_case(expect)

    with pytest.raises(ValueError, match="unknown keys"):
        validate_scenario_case(case)


def test_scenario_schema_rejects_unknown_arg_override() -> None:
    case = make_case(complete_expectations())
    case.data["args"] = {"burst_cuont": 12}

    with pytest.raises(ValueError, match="unknown keys"):
        validate_scenario_case(case)


def test_scenario_schema_rejects_unknown_detector_config_key() -> None:
    case = make_case(complete_expectations())
    case.data["args"] = {"detector_config": {"payload_marker_paterns": ["x"]}}

    with pytest.raises(ValueError, match="args.detector_config.*unknown keys"):
        validate_scenario_case(case)


def test_scenario_schema_rejects_unknown_expectation_actor() -> None:
    expect = complete_expectations()
    expect["batch"]["proofs"] = {"missing": ["cadenced-repeat"]}
    case = make_case(expect)

    with pytest.raises(ValueError, match="unknown actor 'missing'"):
        validate_scenario_case(case)


def test_drift_check_rejects_unexpected_live_reason_kind() -> None:
    expect = complete_expectations()
    expect["live"]["emissions"] = [{"actor": "bot", "action": "ban", "reasons": []}]
    case = make_case(expect)

    with pytest.raises(AssertionError, match="unexpected reasons"):
        assert_no_unexpected_drift(case)


def test_batch_max_action_failure_names_actor_and_actual_action() -> None:
    expect = deepcopy(complete_expectations())
    expect["batch"] = {"max_action": {"bot": "clean"}}
    case = make_case(expect)

    with pytest.raises(AssertionError, match="bot action ban exceeds max clean"):
        assert_batch_expectations(case)


def test_batch_max_score_failure_names_actor_and_limit() -> None:
    expect = deepcopy(complete_expectations())
    expect["batch"] = {"max_score": {"human": 1.0}}
    case = make_case(expect)

    with pytest.raises(AssertionError, match=r"human score .* exceeds max 1\.00"):
        assert_batch_expectations(case)


def test_batch_absent_reason_failure_names_forbidden_reason() -> None:
    expect = deepcopy(complete_expectations())
    expect["batch"] = {"absent_reasons": {"bot": ["cadenced-repeat"]}}
    case = make_case(expect)

    with pytest.raises(
        AssertionError, match=r"bot forbidden reasons \['cadenced-repeat'\]"
    ):
        assert_batch_expectations(case)


def test_live_forbidden_actions_failure_names_actor() -> None:
    expect = deepcopy(complete_expectations())
    expect["live"] = {"forbidden_actions": {"bot": ["ban"]}}
    case = make_case(expect)

    with pytest.raises(AssertionError, match="bot emitted forbidden actions"):
        assert_live_expectations(case)


def test_live_max_action_failure_names_limit() -> None:
    expect = deepcopy(complete_expectations())
    expect["live"] = {"max_action": {"bot": "suspect"}}
    case = make_case(expect)

    with pytest.raises(AssertionError, match="bot emitted action above max suspect"):
        assert_live_expectations(case)


def test_live_max_score_failure_names_limit() -> None:
    expect = deepcopy(complete_expectations())
    expect["live"] = {"max_score": {"bot": -1.0}}
    case = make_case(expect)

    with pytest.raises(AssertionError, match=r"bot emitted score above max -1\.00"):
        assert_live_expectations(case)
