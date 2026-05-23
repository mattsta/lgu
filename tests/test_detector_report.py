from __future__ import annotations

import io
import json
from pathlib import Path

from detector_report import build_detector_report, format_text_report, main


def test_detector_report_passes_without_generated_tasks() -> None:
    report = build_detector_report()

    assert report["status"] == "passed"
    assert report["summary"]["scenario_count"] >= 30
    assert report["summary"]["sweep_variant_count"] >= 30
    assert report["catalog_gaps"] == []
    assert report["sweep_errors"] == []
    assert report["tasks"] == []


def test_detector_report_includes_heuristic_and_provider_detectors() -> None:
    report = build_detector_report()
    detectors = {detector["kind"]: detector for detector in report["detectors"]}

    assert detectors["burst"]["coverage"]["batch_positive"] >= 1
    assert detectors["known-ua-or-referer"]["coverage"]["live_positive"] >= 1
    assert detectors["provider-hosted-activity"]["coverage"]["batch_positive"] >= 1
    burst_thresholds = {
        threshold["arg"]: threshold["boundaries"]
        for threshold in detectors["burst"]["thresholds"]
    }
    assert burst_thresholds["burst_count"] == ["at", "below"]
    provider_thresholds = {
        threshold["arg"]: threshold["boundaries"]
        for threshold in detectors["provider-hosted-activity"]["thresholds"]
    }
    assert provider_thresholds["provider_min_score"] == ["above", "at"]


def test_detector_report_suppresses_deferred_config_knobs_from_advisory_tasks() -> None:
    report = build_detector_report()
    advisory_keys = {
        (task.get("kind"), task.get("arg"))
        for task in report["tasks"]
        if task["severity"] == "advisory"
    }

    assert ("known-ua-or-referer", "known_bot_ua_patterns") not in advisory_keys
    assert ("provider-hosted-activity", "provider_watch") not in advisory_keys
    assert {item["arg"] for item in report["deferred_thresholds"]} >= {
        "known_bot_ua_patterns",
        "provider_watch",
    }


def test_text_report_is_operator_readable() -> None:
    text = format_text_report(build_detector_report())

    assert "Detector Confidence Report" in text
    assert "Blocking tasks: 0" in text
    assert "Advisory threshold tasks: 0" in text


def test_report_cli_emits_json() -> None:
    stdout = io.StringIO()

    assert main(["--format", "json"], stdout=stdout) == 0

    payload = json.loads(stdout.getvalue())
    assert payload["status"] == "passed"
    assert payload["summary"]["catalog_detector_count"] >= 19


def test_detector_report_uses_policy_from_custom_sweep_root(tmp_path: Path) -> None:
    sweep_root = tmp_path / "sweeps"
    sweep_root.mkdir()
    (sweep_root / "coverage_policy.json").write_text(
        json.dumps(
            {
                "required": [
                    {
                        "kind": "not-a-detector",
                        "args": ["threshold"],
                        "boundaries": ["at"],
                    }
                ],
                "deferred": [],
            }
        ),
        encoding="utf-8",
    )
    (sweep_root / "custom.json").write_text(
        json.dumps(
            {
                "name": "custom_burst_count",
                "base": {
                    "actors": {"source": {"ip": "doc:1:10", "ua": "chrome_120"}},
                    "events": [
                        {
                            "actor": "source",
                            "at": 0,
                            "path": "/synthetic/custom-burst",
                        }
                    ],
                    "expect": {
                        "batch": {"reasons": {"source": ["burst"]}},
                        "live": {
                            "emissions": [
                                {
                                    "actor": "source",
                                    "action": "suspect",
                                    "reasons": ["burst"],
                                }
                            ]
                        },
                    },
                },
                "variants": [
                    {
                        "name": "below",
                        "covers": [
                            {
                                "kind": "burst",
                                "args": ["burst_count"],
                                "boundary": "below",
                            }
                        ],
                        "set": {
                            "expect.batch.reasons": {},
                            "expect.batch.absent_reasons": {"source": ["burst"]},
                            "expect.live.emissions": [],
                            "expect.live.no_emissions": ["source"],
                        },
                    },
                    {
                        "name": "at",
                        "covers": [
                            {
                                "kind": "burst",
                                "args": ["burst_count"],
                                "boundary": "at",
                            }
                        ],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    report = build_detector_report(sweep_root=sweep_root)

    assert any(
        "unknown detector kind not-a-detector" in error
        for error in report["sweep_errors"]
    )
