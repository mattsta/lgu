from __future__ import annotations

import io
import json
from pathlib import Path

from scenario_matrix import (
    build_matrix,
    find_catalog_gaps,
    find_unknown_kinds,
    format_matrix,
    load_cases,
    main,
    matrix_to_jsonable,
)


def test_build_matrix_counts_batch_absent_and_live_expectations(
    tmp_path: Path,
) -> None:
    path = write_scenarios(
        tmp_path,
        {
            "scenarios": [
                {
                    "name": "alpha",
                    "expect": {
                        "batch": {
                            "proofs": {
                                "bot": ["cadenced-repeat", "payload-fuzzer"],
                                "other": ["cadenced-repeat"],
                            },
                            "absent_proofs": {
                                "human": ["cadenced-repeat"],
                            },
                        },
                        "live": {
                            "emissions": [
                                {
                                    "actor": "bot",
                                    "action": "ban",
                                    "reasons": ["cadenced-repeat"],
                                }
                            ]
                        },
                    },
                },
                {
                    "name": "beta",
                    "expect": {
                        "batch": {
                            "absent_proofs": {
                                "source": ["payload-fuzzer"],
                            }
                        },
                        "live": {
                            "emissions": [
                                {
                                    "actor": "source",
                                    "action": "ban",
                                    "reasons": [
                                        "payload-fuzzer",
                                        "rapid-ua-switch",
                                    ],
                                }
                            ]
                        },
                    },
                },
            ]
        },
    )

    rows = {row.kind: row for row in build_matrix(load_cases(path))}

    cadenced = rows["cadenced-repeat"]
    assert cadenced.batch_positive.count == 2
    assert cadenced.batch_positive.scenario_ids == ("custom::alpha",)
    assert cadenced.batch_absent_negative.count == 1
    assert cadenced.batch_absent_negative.scenario_ids == ("custom::alpha",)
    assert cadenced.live_positive.count == 1
    assert cadenced.live_positive.scenario_ids == ("custom::alpha",)

    payload = rows["payload-fuzzer"]
    assert payload.batch_positive.count == 1
    assert payload.batch_absent_negative.count == 1
    assert payload.batch_absent_negative.scenario_ids == ("custom::beta",)
    assert payload.live_positive.count == 1

    rapid = rows["rapid-ua-switch"]
    assert rapid.batch_positive.count == 0
    assert rapid.batch_absent_negative.count == 0
    assert rapid.live_positive.count == 1
    assert rapid.live_positive.scenario_ids == ("custom::beta",)


def test_matrix_serialization_uses_stable_shape(tmp_path: Path) -> None:
    path = write_scenarios(
        tmp_path,
        {
            "name": "single",
            "expect": {
                "batch": {
                    "proofs": {"bot": ["coordinated-ua"]},
                    "absent_proofs": {"human": ["coordinated-ua"]},
                },
                "live": {
                    "emissions": [
                        {
                            "actor": "bot",
                            "action": "ban",
                            "reasons": ["coordinated-ua"],
                        }
                    ]
                },
            },
        },
    )

    assert matrix_to_jsonable(build_matrix(load_cases(path))) == [
        {
            "kind": "coordinated-ua",
            "batch_positive": {
                "count": 1,
                "scenario_ids": ["custom::single"],
            },
            "batch_absent_negative": {
                "count": 1,
                "scenario_ids": ["custom::single"],
            },
            "live_positive": {
                "count": 1,
                "scenario_ids": ["custom::single"],
            },
        }
    ]


def test_cli_json_output_supports_scenario_file(tmp_path: Path) -> None:
    path = write_scenarios(
        tmp_path,
        {
            "name": "cli",
            "actors": {"bot": {"ip": "doc:1:10", "ua": "chrome_120"}},
            "events": [{"actor": "bot", "at": 0, "path": "/synthetic/matrix-cli"}],
            "expect": {
                "batch": {"proofs": {"bot": ["tight-multifetch"]}},
                "live": {
                    "emissions": [
                        {
                            "actor": "bot",
                            "action": "ban",
                            "reasons": ["tight-multifetch"],
                        }
                    ]
                },
            },
        },
    )
    stdout = io.StringIO()

    assert main([str(path), "--format", "json"], stdout=stdout) == 0

    assert json.loads(stdout.getvalue()) == [
        {
            "kind": "tight-multifetch",
            "batch_positive": {
                "count": 1,
                "scenario_ids": ["custom::cli"],
            },
            "batch_absent_negative": {
                "count": 0,
                "scenario_ids": [],
            },
            "live_positive": {
                "count": 1,
                "scenario_ids": ["custom::cli"],
            },
        }
    ]


def test_text_report_includes_counts_and_scenario_ids(tmp_path: Path) -> None:
    path = write_scenarios(
        tmp_path,
        {
            "name": "text",
            "expect": {
                "batch": {"absent_proofs": {"source": ["serial-sweep"]}},
            },
        },
    )

    report = format_matrix(build_matrix(load_cases(path)))

    assert "detector/proof kind" in report
    assert "batch absent/negative" in report
    assert "serial-sweep" in report
    assert "1: custom::text" in report


def test_repository_scenarios_cover_catalog_proof_kinds() -> None:
    rows = build_matrix(load_cases(Path(__file__).parent / "scenarios"))

    assert find_unknown_kinds(rows) == []
    assert find_catalog_gaps(rows) == []


def test_catalog_gate_reports_missing_coverage(tmp_path: Path) -> None:
    path = write_scenarios(
        tmp_path,
        {
            "name": "partial",
            "actors": {"bot": {"ip": "doc:1:11", "ua": "chrome_120"}},
            "events": [{"actor": "bot", "at": 0, "path": "/synthetic/matrix-partial"}],
            "expect": {"batch": {"proofs": {"bot": ["cadenced-repeat"]}}},
        },
    )
    stdout = io.StringIO()

    assert main([str(path), "--check-catalog"], stdout=stdout) == 1

    report = stdout.getvalue()
    assert "Catalog coverage check failed." in report
    assert "cadenced-repeat" in report
    assert "batch_absent_negative" in report


def test_catalog_gate_reports_unknown_detector_kind(tmp_path: Path) -> None:
    path = write_scenarios(
        tmp_path,
        {
            "name": "unknown",
            "actors": {"bot": {"ip": "doc:1:12", "ua": "chrome_120"}},
            "events": [{"actor": "bot", "at": 0, "path": "/synthetic/matrix-unknown"}],
            "expect": {"batch": {"proofs": {"bot": ["not-a-detector"]}}},
        },
    )
    stdout = io.StringIO()

    assert main([str(path), "--check-catalog"], stdout=stdout) == 1

    assert "unknown detector kind 'not-a-detector'" in stdout.getvalue()


def write_scenarios(tmp_path: Path, data: object) -> Path:
    path = tmp_path / "custom.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path
