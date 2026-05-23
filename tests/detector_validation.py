from __future__ import annotations

import argparse
import json
import py_compile
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from detector_report import build_detector_report
from scenario_dsl import (
    assert_batch_expectations,
    assert_live_expectations,
    assert_no_unexpected_drift,
    validate_scenario_case,
)
from scenario_matrix import (
    build_matrix,
    find_catalog_gaps,
    find_unknown_kinds,
    format_catalog_failures,
    load_cases,
)
from scenario_sweeps import (
    load_sweep_variants,
    policy_path_for_sweep_root,
    run_sweep_variants,
    validate_sweep_coverage,
)
from synthetic_hygiene import find_hygiene_findings, iter_checked_files

DEFAULT_SCENARIO_ROOT = Path("tests/scenarios")
DEFAULT_SWEEP_ROOT = Path("tests/sweeps")
COMPILE_TARGETS = (
    Path("src/lgu/audit.py"),
    Path("src/lgu/watch.py"),
    Path("src/lgu/detector_catalog.py"),
    Path("src/lgu/provider_ranges.py"),
)
CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class ValidationStep:
    name: str
    status: str
    details: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        return self.status in {"passed", "skipped"}

    def to_jsonable(self) -> dict[str, object]:
        return {
            "name": self.name,
            "status": self.status,
            "details": list(self.details),
        }

    def format(self) -> str:
        prefix = self.status.upper()
        if not self.details:
            return f"{prefix} {self.name}"
        return f"{prefix} {self.name}: {'; '.join(self.details)}"


def run_validation(
    *,
    scenario_root: Path = DEFAULT_SCENARIO_ROOT,
    sweep_root: Path = DEFAULT_SWEEP_ROOT,
    pytest_workers: str = "auto",
    run_ruff: bool = True,
    run_pytest: bool = True,
    command_runner: CommandRunner = subprocess.run,
) -> list[ValidationStep]:
    steps = [
        compile_step(),
        scenario_catalog_step(scenario_root),
        scenario_execution_step(scenario_root),
        sweep_step(sweep_root),
        synthetic_hygiene_step(),
        confidence_report_step(scenario_root, sweep_root),
    ]
    steps.append(
        command_step(
            name="ruff",
            command=("uv", "run", "ruff", "check", "."),
            command_runner=command_runner,
            enabled=run_ruff,
        )
    )
    steps.append(
        command_step(
            name="pytest",
            command=("uv", "run", "pytest", "-n", pytest_workers, "-q"),
            command_runner=command_runner,
            enabled=run_pytest,
        )
    )
    return steps


def compile_step() -> ValidationStep:
    try:
        for target in COMPILE_TARGETS:
            py_compile.compile(str(target), doraise=True)
    except Exception as exc:  # pragma: no cover - failure path is environment-specific.
        return ValidationStep("compile", "failed", (str(exc),))
    return ValidationStep(
        "compile",
        "passed",
        (f"{len(COMPILE_TARGETS)} Python entrypoints compiled",),
    )


def scenario_catalog_step(scenario_root: Path) -> ValidationStep:
    try:
        rows = build_matrix(load_cases(scenario_root))
        unknown = find_unknown_kinds(rows)
        gaps = find_catalog_gaps(rows)
    except Exception as exc:
        return ValidationStep("scenario catalog", "failed", (str(exc),))

    if unknown or gaps:
        return ValidationStep(
            "scenario catalog",
            "failed",
            tuple(format_catalog_failures(unknown, gaps).splitlines()),
        )
    return ValidationStep(
        "scenario catalog",
        "passed",
        (f"{len(rows)} detector kinds covered by scenario expectations",),
    )


def scenario_execution_step(scenario_root: Path) -> ValidationStep:
    try:
        cases = load_cases(scenario_root)
        for case in cases:
            validate_scenario_case(case)
            assert_batch_expectations(case)
            assert_live_expectations(case)
            assert_no_unexpected_drift(case)
    except Exception as exc:
        return ValidationStep("scenario execution", "failed", (str(exc),))
    return ValidationStep(
        "scenario execution",
        "passed",
        (f"{len(cases)} scenarios passed schema, expectation, and drift checks",),
    )


def sweep_step(sweep_root: Path) -> ValidationStep:
    try:
        variants = load_sweep_variants(sweep_root)
        if not variants:
            return ValidationStep(
                "threshold sweeps",
                "failed",
                (f"{sweep_root}: no sweep variants found",),
            )
        coverage_errors = validate_sweep_coverage(
            variants,
            policy_path=policy_path_for_sweep_root(sweep_root),
        )
        if coverage_errors:
            return ValidationStep(
                "threshold sweeps",
                "failed",
                tuple(coverage_errors),
            )
        results = run_sweep_variants(variants)
    except Exception as exc:
        return ValidationStep("threshold sweeps", "failed", (str(exc),))
    return ValidationStep(
        "threshold sweeps",
        "passed",
        (f"{len(results)} generated boundary variants passed",),
    )


def synthetic_hygiene_step() -> ValidationStep:
    findings = find_hygiene_findings()
    if findings:
        return ValidationStep(
            "synthetic hygiene",
            "failed",
            tuple(finding.format() for finding in findings),
        )
    return ValidationStep(
        "synthetic hygiene",
        "passed",
        (f"{len(iter_checked_files())} docs/example/scenario files checked",),
    )


def confidence_report_step(scenario_root: Path, sweep_root: Path) -> ValidationStep:
    try:
        report = build_detector_report(
            scenario_root=scenario_root,
            sweep_root=sweep_root,
        )
    except Exception as exc:
        return ValidationStep("confidence report", "failed", (str(exc),))
    tasks = report["tasks"]
    if tasks:
        by_severity: dict[str, int] = {}
        for task in tasks:
            severity = str(task.get("severity", "unknown"))
            by_severity[severity] = by_severity.get(severity, 0) + 1
        return ValidationStep(
            "confidence report",
            "failed",
            (
                f"{len(tasks)} generated tasks must be resolved or explicitly deferred",
                f"severity counts: {dict(sorted(by_severity.items()))}",
                *tuple(str(task) for task in tasks[:8]),
            ),
        )
    return ValidationStep(
        "confidence report",
        "passed",
        (
            f"{report['summary']['catalog_detector_count']} detectors reported; "
            f"{report['summary']['task_count']} total generated tasks",
        ),
    )


def command_step(
    *,
    name: str,
    command: Sequence[str],
    command_runner: CommandRunner,
    enabled: bool,
) -> ValidationStep:
    if not enabled:
        return ValidationStep(name, "skipped", ("disabled by CLI flag",))

    result = command_runner(
        command,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return ValidationStep(name, "passed", (command_summary(command),))

    details = [command_summary(command), f"exit code {result.returncode}"]
    details.extend(compact_output(result.stdout))
    details.extend(compact_output(result.stderr))
    return ValidationStep(name, "failed", tuple(details))


def command_summary(command: Sequence[str]) -> str:
    return " ".join(command)


def compact_output(text: str, *, max_lines: int = 12) -> list[str]:
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) <= max_lines:
        return lines
    return [*lines[:4], "...", *lines[-(max_lines - 5) :]]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the full detector correctness validation gate."
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
        "--pytest-workers",
        default="auto",
        help='xdist worker count for pytest. Defaults to "auto".',
    )
    parser.add_argument(
        "--skip-ruff",
        action="store_true",
        help="Skip ruff linting.",
    )
    parser.add_argument(
        "--skip-pytest",
        action="store_true",
        help="Skip the full pytest suite.",
    )
    parser.add_argument(
        "--skip-runtime",
        action="store_true",
        help="Skip runtime subprocess gates, currently ruff and pytest.",
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
    steps = run_validation(
        scenario_root=args.scenario_root,
        sweep_root=args.sweep_root,
        pytest_workers=args.pytest_workers,
        run_ruff=not args.skip_ruff and not args.skip_runtime,
        run_pytest=not args.skip_pytest and not args.skip_runtime,
    )
    output = stdout if stdout is not None else sys.stdout
    if args.format == "json":
        print(
            json.dumps([step.to_jsonable() for step in steps], indent=2),
            file=output,
        )
    else:
        for step in steps:
            print(step.format(), file=output)
    return 0 if all(step.passed for step in steps) else 1


if __name__ == "__main__":
    raise SystemExit(main())
