from __future__ import annotations

import io
import json
from pathlib import Path

from scenario_dsl import (
    ScenarioCase,
    assert_batch_expectations,
    assert_live_expectations,
)
from scenario_intake import build_intake_report, main
from synthetic_access import CHROME_120_UA, access_line


def test_intake_report_emits_synthetic_scenario_and_probe() -> None:
    snippet = "".join(
        access_line(
            ip="198.51.100.77",
            ts=f"08/Apr/2026:02:30:{second:02d} +0000",
            path=f"/source/private-{second}",
            referer="https://source.example.test/",
            ua=CHROME_120_UA,
        )
        for second in range(12)
    )

    report = build_intake_report(snippet, name="intake_case")

    scenario = report["scenario"]
    assert scenario["name"] == "intake_case"
    assert scenario["actors"]["source_01"]["ip"] == "doc:2:77"
    assert all(event["path"].startswith("/synthetic/") for event in scenario["events"])
    assert "expect" in scenario
    assert report["probe"]["id"] == "intake_case::intake_case"


def test_intake_scenario_expectations_are_dsl_compatible() -> None:
    snippet = "".join(
        access_line(
            ip="192.0.2.88",
            ts=f"08/Apr/2026:02:30:{second:02d} +0000",
            path=f"/source/private-{second}",
            referer="-",
            ua=CHROME_120_UA,
        )
        for second in range(12)
    )
    report = build_intake_report(snippet, name="compatible_case")
    case = ScenarioCase(
        path=Path("compatible_case.json"),
        data=report["scenario"],
    )

    assert_batch_expectations(case)
    assert_live_expectations(case)


def test_intake_cli_can_emit_scenario_only(tmp_path: Path) -> None:
    log_path = tmp_path / "snippet.log"
    log_path.write_text(
        access_line(
            ip="203.0.113.44",
            ts="08/Apr/2026:02:30:52 +0000",
            path="/private/source",
            referer="-",
            ua=CHROME_120_UA,
        ),
        encoding="utf-8",
    )
    stdout = io.StringIO()

    assert main([str(log_path), "--name", "cli_intake", "--scenario-only"], stdout) == 0

    payload = json.loads(stdout.getvalue())
    assert payload["name"] == "cli_intake"
    assert payload["actors"]["source_01"]["ip"] == "doc:3:44"
