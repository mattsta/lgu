from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from scenario_dsl import ScenarioCase, load_scenario_cases, validate_scenario_case

from lgu.detector_catalog import DETECTOR_KINDS, DETECTORS

DEFAULT_SCENARIO_ROOT = Path(__file__).parent / "scenarios"


@dataclass(frozen=True)
class ExpectationBucket:
    count: int
    scenario_ids: tuple[str, ...]


@dataclass(frozen=True)
class MatrixRow:
    kind: str
    batch_positive: ExpectationBucket
    batch_absent_negative: ExpectationBucket
    live_positive: ExpectationBucket


@dataclass(frozen=True)
class CoverageGap:
    kind: str
    missing: tuple[str, ...]


@dataclass
class _MutableBucket:
    count: int = 0
    scenario_ids: set[str] = field(default_factory=set)

    def add(self, scenario_id: str) -> None:
        self.count += 1
        self.scenario_ids.add(scenario_id)

    def freeze(self) -> ExpectationBucket:
        return ExpectationBucket(
            count=self.count,
            scenario_ids=tuple(sorted(self.scenario_ids)),
        )


@dataclass
class _MutableRow:
    batch_positive: _MutableBucket = field(default_factory=_MutableBucket)
    batch_absent_negative: _MutableBucket = field(default_factory=_MutableBucket)
    live_positive: _MutableBucket = field(default_factory=_MutableBucket)

    def freeze(self, kind: str) -> MatrixRow:
        return MatrixRow(
            kind=kind,
            batch_positive=self.batch_positive.freeze(),
            batch_absent_negative=self.batch_absent_negative.freeze(),
            live_positive=self.live_positive.freeze(),
        )


def load_cases(path: Path) -> list[ScenarioCase]:
    if path.is_dir():
        return load_scenario_cases(path)
    if path.is_file():
        resolved = path.resolve()
        return [
            case
            for case in load_scenario_cases(path.parent)
            if case.path.resolve() == resolved
        ]
    raise FileNotFoundError(path)


def build_matrix(cases: Iterable[ScenarioCase]) -> list[MatrixRow]:
    rows: dict[str, _MutableRow] = {}
    for case in cases:
        row_id = case.id
        for kind in _batch_positive_kinds(case):
            rows.setdefault(kind, _MutableRow()).batch_positive.add(row_id)
        for kind in _batch_absent_negative_kinds(case):
            rows.setdefault(kind, _MutableRow()).batch_absent_negative.add(row_id)
        for kind in _live_positive_kinds(case):
            rows.setdefault(kind, _MutableRow()).live_positive.add(row_id)
    return [rows[kind].freeze(kind) for kind in sorted(rows)]


def find_catalog_gaps(
    rows: Iterable[MatrixRow],
    *,
    require_live: bool = True,
    outcomes: tuple[str, ...] = ("heuristic", "proof", "optional-proof"),
) -> list[CoverageGap]:
    rows_by_kind = {row.kind: row for row in rows}
    gaps: list[CoverageGap] = []
    for spec in DETECTORS:
        if spec.outcome not in outcomes:
            continue
        row = rows_by_kind.get(spec.kind)
        missing = []
        if row is None or row.batch_positive.count == 0:
            missing.append("batch_positive")
        if row is None or row.batch_absent_negative.count == 0:
            missing.append("batch_absent_negative")
        if (
            require_live
            and spec.live_coverage_required
            and (row is None or row.live_positive.count == 0)
        ):
            missing.append("live_positive")
        if missing:
            gaps.append(CoverageGap(kind=spec.kind, missing=tuple(missing)))
    return gaps


def find_unknown_kinds(rows: Iterable[MatrixRow]) -> list[str]:
    return sorted(row.kind for row in rows if row.kind not in DETECTOR_KINDS)


def matrix_to_jsonable(rows: Iterable[MatrixRow]) -> list[dict[str, object]]:
    return [
        {
            "kind": row.kind,
            "batch_positive": _bucket_to_jsonable(row.batch_positive),
            "batch_absent_negative": _bucket_to_jsonable(row.batch_absent_negative),
            "live_positive": _bucket_to_jsonable(row.live_positive),
        }
        for row in rows
    ]


def format_matrix(rows: Iterable[MatrixRow]) -> str:
    materialized = list(rows)
    if not materialized:
        return "No detector/proof expectations found."

    table_rows = [
        (
            row.kind,
            _format_bucket(row.batch_positive),
            _format_bucket(row.batch_absent_negative),
            _format_bucket(row.live_positive),
        )
        for row in materialized
    ]
    headers = (
        "detector/proof kind",
        "batch positive",
        "batch absent/negative",
        "live positive",
    )
    widths = [
        max(len(str(value)) for value in column)
        for column in zip(headers, *table_rows, strict=True)
    ]
    lines = [_format_table_line(headers, widths)]
    lines.append(_format_table_line(tuple("-" * width for width in widths), widths))
    lines.extend(_format_table_line(row, widths) for row in table_rows)
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Report expected detector coverage in JSON scenarios."
    )
    parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        default=DEFAULT_SCENARIO_ROOT,
        help="Scenario JSON file or directory. Defaults to tests/scenarios.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format.",
    )
    parser.add_argument(
        "--check-catalog",
        action="store_true",
        help="Fail if catalog detectors lack positive, negative, or live scenario coverage.",
    )
    parser.add_argument(
        "--proofs-only",
        action="store_true",
        help="With --check-catalog, require coverage only for proof detectors.",
    )
    parser.add_argument(
        "--no-require-live",
        action="store_true",
        help="With --check-catalog, do not require live-positive coverage.",
    )
    return parser


def main(argv: Sequence[str] | None = None, stdout: TextIO | None = None) -> int:
    args = build_parser().parse_args(argv)
    cases = load_cases(args.path)
    try:
        for case in cases:
            validate_scenario_case(case)
    except Exception as exc:
        output = stdout if stdout is not None else sys.stdout
        print(f"Scenario validation failed: {exc}", file=output)
        return 1
    rows = build_matrix(cases)
    output = stdout if stdout is not None else sys.stdout
    if args.format == "json":
        print(json.dumps(matrix_to_jsonable(rows), indent=2), file=output)
    else:
        print(format_matrix(rows), file=output)

    if not args.check_catalog:
        return 0

    unknown = find_unknown_kinds(rows)
    outcomes = (
        ("proof",) if args.proofs_only else ("heuristic", "proof", "optional-proof")
    )
    gaps = find_catalog_gaps(
        rows,
        require_live=not args.no_require_live,
        outcomes=outcomes,
    )
    if unknown or gaps:
        print(format_catalog_failures(unknown, gaps), file=output)
        return 1
    print("Catalog coverage check passed.", file=output)
    return 0


def _batch_positive_kinds(case: ScenarioCase) -> Iterable[str]:
    batch = _mapping(case.data.get("expect", {}), f"{case.id}.expect").get("batch", {})
    batch_mapping = _mapping(batch, f"{case.id}.expect.batch")
    yield from _actor_kind_mapping(
        batch_mapping.get("proofs", {}), f"{case.id}.expect.batch.proofs"
    )
    yield from _actor_kind_mapping(
        batch_mapping.get("reasons", {}), f"{case.id}.expect.batch.reasons"
    )


def _batch_absent_negative_kinds(case: ScenarioCase) -> Iterable[str]:
    batch = _mapping(case.data.get("expect", {}), f"{case.id}.expect").get("batch", {})
    batch_mapping = _mapping(batch, f"{case.id}.expect.batch")
    yield from _actor_kind_mapping(
        batch_mapping.get("absent_proofs", {}),
        f"{case.id}.expect.batch.absent_proofs",
    )
    yield from _actor_kind_mapping(
        batch_mapping.get("absent_reasons", {}),
        f"{case.id}.expect.batch.absent_reasons",
    )


def _live_positive_kinds(case: ScenarioCase) -> Iterable[str]:
    live = _mapping(case.data.get("expect", {}), f"{case.id}.expect").get("live", {})
    emissions = _mapping(live, f"{case.id}.expect.live").get("emissions", ())
    if not isinstance(emissions, list | tuple):
        raise TypeError(f"{case.id}.expect.live.emissions must be a list")
    for index, emission in enumerate(emissions):
        context = f"{case.id}.expect.live.emissions[{index}]"
        reasons = _mapping(emission, context).get("reasons", ())
        yield from _reason_sequence(reasons, f"{context}.reasons")


def _actor_kind_mapping(raw: Any, context: str) -> Iterable[str]:
    for actor, kinds in _mapping(raw, context).items():
        yield from _reason_sequence(kinds, f"{context}.{actor}")


def _mapping(value: Any, context: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise TypeError(f"{context} must be an object")
    return value


def _string_sequence(value: Any, context: str) -> Iterable[str]:
    if not isinstance(value, list | tuple):
        raise TypeError(f"{context} must be a list")
    for item in value:
        if not isinstance(item, str):
            raise TypeError(f"{context} entries must be strings")
        yield item


def _reason_sequence(value: Any, context: str) -> Iterable[str]:
    for item in _string_sequence(value, context):
        yield item.split("=", 1)[0]


def _bucket_to_jsonable(bucket: ExpectationBucket) -> dict[str, object]:
    return {
        "count": bucket.count,
        "scenario_ids": list(bucket.scenario_ids),
    }


def _format_bucket(bucket: ExpectationBucket) -> str:
    if bucket.count == 0:
        return "0"
    return f"{bucket.count}: {', '.join(bucket.scenario_ids)}"


def _format_table_line(values: tuple[str, ...], widths: list[int]) -> str:
    return " | ".join(value.ljust(width) for value, width in zip(values, widths))


def format_catalog_failures(unknown: Iterable[str], gaps: Iterable[CoverageGap]) -> str:
    lines = ["Catalog coverage check failed."]
    unknown = list(unknown)
    gaps = list(gaps)
    if unknown:
        lines.append(f"Unknown detector kinds: {', '.join(unknown)}")
    if gaps:
        lines.append("Coverage gaps:")
        for gap in gaps:
            lines.append(f"- {gap.kind}: {', '.join(gap.missing)}")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
