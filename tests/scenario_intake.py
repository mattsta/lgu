from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, TextIO

from scenario_dsl import ScenarioCase, validate_scenario_case
from scenario_probe import summarize_case
from scenario_sanitize import sanitize_log_snippet
from synthetic_hygiene import find_structured_synthetic_findings


def build_intake_report(
    snippet: str,
    *,
    name: str = "sanitized_access_log",
    include_expectations: bool = True,
) -> dict[str, Any]:
    scenario = sanitize_log_snippet(snippet, name=name)
    case = ScenarioCase(path=Path(f"{name}.json"), data=scenario)
    validate_scenario_case(case)
    hygiene_findings = find_structured_synthetic_findings(
        case.path, json.dumps(scenario, indent=2)
    )
    if hygiene_findings:
        raise ValueError(
            "sanitized scenario failed synthetic hygiene: "
            + "; ".join(finding.format() for finding in hygiene_findings)
        )

    probe = summarize_case(case)
    if include_expectations:
        scenario["expect"] = infer_expectations(probe)
    return {
        "scenario": scenario,
        "probe": probe,
        "tasks": intake_tasks(probe),
    }


def infer_expectations(probe: dict[str, Any]) -> dict[str, Any]:
    batch = probe.get("batch", {})
    live = probe.get("live", {})
    proofs = normalize_actor_mapping(batch.get("proofs", {}))
    reasons = {
        emission["actor"]: [
            reason_kind(reason) for reason in emission.get("reasons", [])
        ]
        for emission in live.get("emissions", [])
        if emission.get("reasons")
    }
    expect: dict[str, Any] = {
        "batch": {
            "bots": list(batch.get("bot_actors", [])),
        },
        "live": {
            "emission_count": len(live.get("emissions", [])),
            "emissions": [
                {
                    "actor": emission["actor"],
                    "action": emission["action"],
                    "reasons": [
                        reason_kind(reason) for reason in emission.get("reasons", [])
                    ],
                }
                for emission in live.get("emissions", [])
            ],
        },
    }
    if proofs:
        expect["batch"]["proofs"] = proofs
    if reasons:
        expect["batch"]["reasons"] = reasons
    return expect


def normalize_actor_mapping(raw: Any) -> dict[str, list[str]]:
    if not isinstance(raw, dict):
        return {}
    return {
        str(actor): [reason_kind(str(kind)) for kind in kinds]
        for actor, kinds in raw.items()
        if isinstance(kinds, list) and kinds
    }


def reason_kind(reason: str) -> str:
    return reason.split("=", 1)[0]


def intake_tasks(probe: dict[str, Any]) -> list[dict[str, object]]:
    tasks = []
    diagnostics = probe.get("diagnostics", {})
    if diagnostics:
        tasks.append(
            {
                "area": "near-miss-review",
                "description": "Review detector near-misses before accepting expectations.",
                "details": diagnostics,
            }
        )
    if not probe.get("batch", {}).get("bot_actors"):
        tasks.append(
            {
                "area": "classification",
                "description": "No batch bot actors were detected; decide whether this should be a clean false-positive guard or needs detector tuning.",
            }
        )
    return tasks


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Sanitize access-log examples, probe current detector output, and emit "
            "a synthetic scenario draft."
        )
    )
    parser.add_argument(
        "input",
        nargs="?",
        type=Path,
        help="Access-log snippet path. Reads stdin when omitted.",
    )
    parser.add_argument(
        "--name",
        default="sanitized_access_log",
        help="Scenario name for the emitted draft.",
    )
    parser.add_argument(
        "--no-expectations",
        action="store_true",
        help="Do not infer expectation stubs from current detector output.",
    )
    parser.add_argument(
        "--scenario-only",
        action="store_true",
        help="Print only the scenario JSON instead of the full intake report.",
    )
    return parser


def main(argv: Sequence[str] | None = None, stdout: TextIO | None = None) -> int:
    args = build_parser().parse_args(argv)
    text = (
        sys.stdin.read()
        if args.input is None
        else args.input.read_text(encoding="utf-8", errors="replace")
    )
    report = build_intake_report(
        text,
        name=args.name,
        include_expectations=not args.no_expectations,
    )
    output = stdout if stdout is not None else sys.stdout
    payload = report["scenario"] if args.scenario_only else report
    print(json.dumps(payload, indent=2), file=output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
