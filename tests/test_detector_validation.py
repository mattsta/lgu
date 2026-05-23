from __future__ import annotations

import io
import json
from pathlib import Path

from detector_validation import confidence_report_step, main, run_validation, sweep_step


def test_validation_gate_passes_without_runtime_subprocesses() -> None:
    steps = run_validation(run_ruff=False, run_pytest=False)

    assert [(step.name, step.status) for step in steps] == [
        ("compile", "passed"),
        ("scenario catalog", "passed"),
        ("scenario execution", "passed"),
        ("threshold sweeps", "passed"),
        ("synthetic hygiene", "passed"),
        ("confidence report", "passed"),
        ("ruff", "skipped"),
        ("pytest", "skipped"),
    ]


def test_validation_gate_fails_unknown_scenario_catalog_kind(tmp_path: Path) -> None:
    scenario_path = tmp_path / "bad.json"
    scenario_path.write_text(
        json.dumps(
            {
                "name": "bad",
                "expect": {
                    "batch": {
                        "proofs": {
                            "doc:actor": ["not-a-cataloged-detector"],
                        },
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    steps = run_validation(
        scenario_root=scenario_path,
        run_ruff=False,
        run_pytest=False,
    )

    assert ("scenario catalog", "failed") in [
        (step.name, step.status) for step in steps
    ]
    catalog_step = next(step for step in steps if step.name == "scenario catalog")
    assert any("Unknown detector kinds" in detail for detail in catalog_step.details)


def test_validation_cli_emits_json_without_runtime_subprocesses() -> None:
    stdout = io.StringIO()

    exit_code = main(["--skip-runtime", "--format", "json"], stdout=stdout)

    assert exit_code == 0
    payload = json.loads(stdout.getvalue())
    assert payload[-2]["name"] == "ruff"
    assert payload[-2]["status"] == "skipped"
    assert payload[-1]["name"] == "pytest"
    assert payload[-1]["status"] == "skipped"


def test_confidence_report_step_fails_any_generated_task(monkeypatch) -> None:
    def fake_report(**_kwargs):
        return {
            "summary": {
                "catalog_detector_count": 19,
                "task_count": 1,
            },
            "tasks": [
                {
                    "area": "threshold-expansion",
                    "kind": "synthetic-detector",
                    "arg": "synthetic_threshold",
                    "severity": "advisory",
                }
            ],
        }

    monkeypatch.setattr("detector_validation.build_detector_report", fake_report)

    step = confidence_report_step(Path("tests/scenarios"), Path("tests/sweeps"))

    assert step.status == "failed"
    assert "1 generated tasks must be resolved" in step.details[0]
    assert "advisory" in step.details[1]


def test_sweep_step_uses_policy_from_custom_sweep_root(tmp_path: Path) -> None:
    sweep_root = write_custom_sweep_root(
        tmp_path,
        {
            "required": [
                {
                    "kind": "not-a-detector",
                    "args": ["threshold"],
                    "boundaries": ["at"],
                }
            ],
            "deferred": [],
        },
    )

    step = sweep_step(sweep_root)

    assert step.status == "failed"
    assert any(
        "unknown detector kind not-a-detector" in detail for detail in step.details
    )


def write_custom_sweep_root(tmp_path: Path, policy: dict) -> Path:
    sweep_root = tmp_path / "sweeps"
    sweep_root.mkdir()
    (sweep_root / "coverage_policy.json").write_text(
        json.dumps(policy),
        encoding="utf-8",
    )
    (sweep_root / "custom.json").write_text(
        json.dumps(
            {
                "name": "custom_pair_count",
                "base": {
                    "actors": {
                        "source": {
                            "ip": "doc:1:10",
                            "ua": "chrome_120",
                            "referer": "none",
                        }
                    },
                    "events": [
                        {
                            "actor": "source",
                            "at": 0,
                            "path": "/synthetic/custom-pair",
                        }
                    ],
                    "expect": {
                        "batch": {
                            "bots": ["source"],
                            "proofs": {"source": ["repeated-pair"]},
                        },
                        "live": {
                            "emission_count": 1,
                            "emissions": [
                                {
                                    "actor": "source",
                                    "action": "ban",
                                    "reasons": ["repeated-pair"],
                                }
                            ],
                        },
                    },
                },
                "variants": [
                    {
                        "name": "below",
                        "covers": [
                            {
                                "kind": "repeated-pair",
                                "args": ["pair_repeat_count"],
                                "boundary": "below",
                            }
                        ],
                        "set": {
                            "expect.batch.bots": [],
                            "expect.batch.proofs": {},
                            "expect.batch.clean": ["source"],
                            "expect.batch.absent_proofs": {"source": ["repeated-pair"]},
                            "expect.live.emission_count": 0,
                            "expect.live.emissions": [],
                            "expect.live.no_emissions": ["source"],
                        },
                    },
                    {
                        "name": "at",
                        "covers": [
                            {
                                "kind": "repeated-pair",
                                "args": ["pair_repeat_count"],
                                "boundary": "at",
                            }
                        ],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    return sweep_root
