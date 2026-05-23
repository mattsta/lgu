from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, TextIO

from scenario_dsl import validate_scenario_case
from scenario_matrix import (
    build_matrix,
    find_catalog_gaps,
    find_unknown_kinds,
    load_cases,
)
from scenario_sweeps import (
    catalog_threshold_coverage,
    load_deferred_thresholds,
    load_sweep_variants,
    policy_path_for_sweep_root,
    validate_sweep_coverage,
)
from synthetic_hygiene import find_hygiene_findings

from lgu.detector_catalog import DETECTORS

DEFAULT_SCENARIO_ROOT = Path("tests/scenarios")
DEFAULT_SWEEP_ROOT = Path("tests/sweeps")


def build_detector_report(
    *,
    scenario_root: Path = DEFAULT_SCENARIO_ROOT,
    sweep_root: Path = DEFAULT_SWEEP_ROOT,
) -> dict[str, Any]:
    cases = load_cases(scenario_root)
    for case in cases:
        validate_scenario_case(case)
    rows = build_matrix(cases)
    rows_by_kind = {row.kind: row for row in rows}
    variants = load_sweep_variants(sweep_root)
    threshold_rows = catalog_threshold_coverage(variants)
    threshold_by_kind = {str(row["kind"]): row for row in threshold_rows}
    policy_path = policy_path_for_sweep_root(sweep_root)
    deferred_thresholds = (
        load_deferred_thresholds(policy_path) if policy_path is not None else {}
    )
    unknown = find_unknown_kinds(rows)
    catalog_gaps = find_catalog_gaps(rows)
    sweep_errors = validate_sweep_coverage(variants, policy_path=policy_path)
    hygiene_findings = find_hygiene_findings()
    tasks = build_tasks(
        unknown=unknown,
        catalog_gaps=catalog_gaps,
        sweep_errors=sweep_errors,
        threshold_rows=threshold_rows,
        deferred_thresholds=deferred_thresholds,
        hygiene_findings=[finding.format() for finding in hygiene_findings],
    )
    status = (
        "passed"
        if not (unknown or catalog_gaps or sweep_errors or hygiene_findings)
        else "failed"
    )
    return {
        "status": status,
        "summary": {
            "scenario_count": len(cases),
            "sweep_variant_count": len(variants),
            "catalog_detector_count": len(DETECTORS),
            "task_count": len(tasks),
        },
        "detectors": [
            detector_row(spec.kind, rows_by_kind.get(spec.kind), threshold_by_kind)
            for spec in DETECTORS
        ],
        "deferred_thresholds": [
            {"kind": kind, "arg": arg, "reason": reason}
            for (kind, arg), reason in sorted(deferred_thresholds.items())
        ],
        "unknown_detector_kinds": unknown,
        "catalog_gaps": [
            {"kind": gap.kind, "missing": list(gap.missing)} for gap in catalog_gaps
        ],
        "sweep_errors": sweep_errors,
        "hygiene_findings": [finding.format() for finding in hygiene_findings],
        "tasks": tasks,
    }


def detector_row(
    kind: str, row: Any, threshold_by_kind: dict[str, Any]
) -> dict[str, Any]:
    spec = next(spec for spec in DETECTORS if spec.kind == kind)
    thresholds = threshold_by_kind.get(kind, {}).get("thresholds", [])
    return {
        "kind": kind,
        "scope": spec.scope,
        "outcome": spec.outcome,
        "coverage": {
            "batch_positive": bucket_count(row, "batch_positive"),
            "batch_absent_negative": bucket_count(row, "batch_absent_negative"),
            "live_positive": bucket_count(row, "live_positive"),
        },
        "thresholds": thresholds,
    }


def bucket_count(row: Any, name: str) -> int:
    if row is None:
        return 0
    return getattr(row, name).count


def build_tasks(
    *,
    unknown: list[str],
    catalog_gaps: Any,
    sweep_errors: list[str],
    threshold_rows: list[dict[str, object]],
    deferred_thresholds: dict[tuple[str, str], str],
    hygiene_findings: list[str],
) -> list[dict[str, object]]:
    tasks: list[dict[str, object]] = []
    for kind in unknown:
        tasks.append(
            {
                "area": "catalog",
                "kind": kind,
                "action": "Add the detector kind to src/lgu/detector_catalog.py or remove the scenario expectation.",
                "severity": "blocking",
            }
        )
    for gap in catalog_gaps:
        tasks.append(
            {
                "area": "scenario-coverage",
                "kind": gap.kind,
                "missing": list(gap.missing),
                "action": "Add or update synthetic scenarios for the missing coverage buckets.",
                "severity": "blocking",
            }
        )
    for error in sweep_errors:
        tasks.append(
            {
                "area": "sweep-coverage",
                "detail": error,
                "action": "Add or correct threshold sweep coverage metadata and variants.",
                "severity": "blocking",
            }
        )
    for finding in hygiene_findings:
        tasks.append(
            {
                "area": "synthetic-hygiene",
                "detail": finding,
                "action": "Replace live identifiers with synthetic documentation-safe values.",
                "severity": "blocking",
            }
        )
    for row in threshold_rows:
        for threshold in row["thresholds"]:
            key = (str(row["kind"]), str(threshold["arg"]))
            if not threshold["boundaries"] and key not in deferred_thresholds:
                tasks.append(
                    {
                        "area": "threshold-expansion",
                        "kind": row["kind"],
                        "arg": threshold["arg"],
                        "action": "Add below/at or at/above sweep variants when this threshold becomes policy-critical.",
                        "severity": "advisory",
                    }
                )
    return tasks


def format_text_report(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "Detector Confidence Report",
        f"status: {report['status']}",
        (
            "coverage: "
            f"{summary['scenario_count']} scenarios, "
            f"{summary['sweep_variant_count']} sweep variants, "
            f"{summary['catalog_detector_count']} catalog detectors"
        ),
        f"tasks: {summary['task_count']}",
        "",
        "Detector coverage:",
    ]
    for detector in report["detectors"]:
        coverage = detector["coverage"]
        covered_thresholds = sum(
            1 for threshold in detector["thresholds"] if threshold["boundaries"]
        )
        total_thresholds = len(detector["thresholds"])
        lines.append(
            f"- {detector['kind']} [{detector['outcome']}]: "
            f"batch+={coverage['batch_positive']} "
            f"batch-={coverage['batch_absent_negative']} "
            f"live+={coverage['live_positive']} "
            f"thresholds={covered_thresholds}/{total_thresholds}"
        )
    blocking = [task for task in report["tasks"] if task["severity"] == "blocking"]
    advisory = [task for task in report["tasks"] if task["severity"] == "advisory"]
    lines.extend(["", f"Blocking tasks: {len(blocking)}"])
    lines.extend(format_task(task) for task in blocking)
    lines.extend(["", f"Advisory threshold tasks: {len(advisory)}"])
    lines.extend(format_task(task) for task in advisory[:20])
    if len(advisory) > 20:
        lines.append(f"- ... {len(advisory) - 20} more advisory threshold tasks")
    return "\n".join(lines)


def format_task(task: dict[str, object]) -> str:
    target = task.get("kind") or task.get("detail") or task.get("area")
    arg = f".{task['arg']}" if "arg" in task else ""
    return f"- {task['area']}: {target}{arg}: {task['action']}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Report detector confidence, coverage gaps, and generated tasks."
    )
    parser.add_argument(
        "--scenario-root",
        type=Path,
        default=DEFAULT_SCENARIO_ROOT,
        help="Scenario JSON file or directory. Defaults to tests/scenarios.",
    )
    parser.add_argument(
        "--sweep-root",
        type=Path,
        default=DEFAULT_SWEEP_ROOT,
        help="Sweep JSON file or directory. Defaults to tests/sweeps.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format.",
    )
    return parser


def main(argv: Sequence[str] | None = None, stdout: TextIO | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = build_detector_report(
        scenario_root=args.scenario_root,
        sweep_root=args.sweep_root,
    )
    output = stdout if stdout is not None else sys.stdout
    if args.format == "json":
        print(json.dumps(report, indent=2), file=output)
    else:
        print(format_text_report(report), file=output)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
