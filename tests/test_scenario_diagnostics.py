from __future__ import annotations

from pathlib import Path

from scenario_dsl import ScenarioCase, scenario_diagnostics


def test_scenario_diagnostics_explain_cadenced_near_miss() -> None:
    case = ScenarioCase(
        path=Path("inline.json"),
        data={
            "name": "cadence_near_miss",
            "args": {"cadence_hour_repeat_count": 99},
            "actors": {
                "source": {"ip": "doc:1:10", "ua": "chrome_120", "referer": "none"}
            },
            "events": [
                {
                    "actor": "source",
                    "at": 0,
                    "path": "/synthetic/diagnostic-cadence",
                },
                {
                    "actor": "source",
                    "at": 3600,
                    "path": "/synthetic/diagnostic-cadence",
                },
                {
                    "actor": "source",
                    "at": 7212,
                    "path": "/synthetic/diagnostic-cadence",
                },
            ],
        },
    )

    diagnostics = scenario_diagnostics(case)

    assert any(
        "cadenced-repeat near miss" in message for message in diagnostics["source"]
    )


def test_scenario_diagnostics_explain_config_missing_payload_marker() -> None:
    case = ScenarioCase(
        path=Path("inline.json"),
        data={
            "name": "payload_marker_config_missing",
            "actors": {
                "source": {"ip": "doc:1:11", "ua": "chrome_120", "referer": "none"}
            },
            "events": [
                {
                    "actor": "source",
                    "repeat": 3,
                    "every": 1,
                    "path_template": "/synthetic/diagnostic-payload-{i}?render=full",
                }
            ],
        },
    )

    diagnostics = scenario_diagnostics(case)

    assert any(
        "payload detectors inert" in message for message in diagnostics["source"]
    )
