from __future__ import annotations

import argparse
import copy
import json
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

from scenario_dsl import (
    ScenarioCase,
    assert_batch_expectations,
    assert_live_expectations,
    assert_no_unexpected_drift,
    validate_scenario_case,
)

from lgu.detector_catalog import DETECTORS

DEFAULT_SWEEP_ROOT = Path(__file__).parent / "sweeps"
DEFAULT_SWEEP_POLICY = DEFAULT_SWEEP_ROOT / "coverage_policy.json"
BOUNDARY_KINDS = {"below", "at", "above"}
DETECTOR_BY_KIND = {spec.kind: spec for spec in DETECTORS}


@dataclass(frozen=True)
class SweepCoverage:
    kind: str
    args: tuple[str, ...]
    boundary: str


@dataclass(frozen=True)
class SweepPolicyRequirement:
    kind: str
    args: tuple[str, ...]
    boundaries: tuple[str, ...]


@dataclass(frozen=True)
class SweepPolicyDeferred:
    kind: str
    args: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class SweepPolicy:
    required: tuple[SweepPolicyRequirement, ...]
    deferred: tuple[SweepPolicyDeferred, ...]


@dataclass(frozen=True)
class SweepVariant:
    path: Path
    sweep_name: str
    variant_name: str
    case: ScenarioCase
    coverage: tuple[SweepCoverage, ...]

    @property
    def id(self) -> str:
        return f"{self.path.stem}::{self.sweep_name}::{self.variant_name}"


def load_sweep_variants(root: Path) -> list[SweepVariant]:
    paths = sorted(root.rglob("*.json")) if root.is_dir() else [root]
    variants = []
    for path in paths:
        if path.name == DEFAULT_SWEEP_POLICY.name:
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        for sweep in sweeps_from_data(data, path):
            variants.extend(expand_sweep(path, sweep))
    return variants


def policy_path_for_sweep_root(root: Path) -> Path | None:
    if root.is_file():
        return None
    return root / DEFAULT_SWEEP_POLICY.name


def sweeps_from_data(data: Any, path: Path) -> Iterable[dict[str, Any]]:
    if isinstance(data, dict) and isinstance(data.get("sweeps"), list):
        for sweep in data["sweeps"]:
            yield require_mapping(sweep, f"{path}.sweeps[]")
        return
    if isinstance(data, list):
        for sweep in data:
            yield require_mapping(sweep, f"{path}[]")
        return
    yield require_mapping(data, str(path))


def expand_sweep(path: Path, sweep: dict[str, Any]) -> list[SweepVariant]:
    sweep_name = str(sweep["name"])
    base = require_mapping(sweep.get("base"), f"{path}:{sweep_name}.base")
    raw_variants = sweep.get("variants")
    if not isinstance(raw_variants, list) or not raw_variants:
        raise ValueError(f"{path}:{sweep_name}: expected non-empty variants list")

    variants = []
    for raw_variant in raw_variants:
        variant = require_mapping(raw_variant, f"{path}:{sweep_name}.variants[]")
        variant_name = str(variant["name"])
        case_data = copy.deepcopy(base)
        case_data["name"] = f"{sweep_name}__{variant_name}"
        deep_merge(case_data, require_mapping(variant.get("merge", {}), "merge"))
        for dotted_path, value in require_mapping(
            variant.get("set", {}), "set"
        ).items():
            set_path(case_data, str(dotted_path), value)
        case = ScenarioCase(path=path, data=case_data)
        variants.append(
            SweepVariant(
                path=path,
                sweep_name=sweep_name,
                variant_name=variant_name,
                case=case,
                coverage=parse_coverage(path, sweep_name, variant),
            )
        )
    return variants


def run_sweep_variant(variant: SweepVariant) -> None:
    validate_scenario_case(variant.case)
    assert_batch_expectations(variant.case)
    assert_live_expectations(variant.case)
    assert_no_unexpected_drift(variant.case)


def run_sweep_variants(variants: Iterable[SweepVariant]) -> list[dict[str, str]]:
    results = []
    for variant in variants:
        run_sweep_variant(variant)
        results.append(
            {
                "id": variant.id,
                "case": variant.case.id,
                "status": "passed",
            }
        )
    return results


def load_sweep_policy(
    path: Path = DEFAULT_SWEEP_POLICY,
) -> tuple[SweepPolicyRequirement, ...]:
    return load_sweep_policy_config(path).required


def load_sweep_policy_config(path: Path = DEFAULT_SWEEP_POLICY) -> SweepPolicy:
    if not path.exists():
        return SweepPolicy(required=(), deferred=())
    data = json.loads(path.read_text(encoding="utf-8"))
    raw_requirements = data.get("required", ())
    if not isinstance(raw_requirements, list):
        raise TypeError(f"{path}: required must be a list")
    requirements = []
    for index, raw in enumerate(raw_requirements):
        item = require_mapping(raw, f"{path}.required[{index}]")
        args = require_string_list(
            item.get("args", ()), f"{path}.required[{index}].args"
        )
        boundaries = require_string_list(
            item.get("boundaries", ()), f"{path}.required[{index}].boundaries"
        )
        requirements.append(
            SweepPolicyRequirement(
                kind=str(item["kind"]),
                args=tuple(args),
                boundaries=tuple(boundaries),
            )
        )
    raw_deferred = data.get("deferred", ())
    if not isinstance(raw_deferred, list):
        raise TypeError(f"{path}: deferred must be a list")
    deferred = []
    for index, raw in enumerate(raw_deferred):
        item = require_mapping(raw, f"{path}.deferred[{index}]")
        args = require_string_list(
            item.get("args", ()), f"{path}.deferred[{index}].args"
        )
        deferred.append(
            SweepPolicyDeferred(
                kind=str(item["kind"]),
                args=tuple(args),
                reason=str(item.get("reason", "deferred by sweep policy")),
            )
        )
    return SweepPolicy(required=tuple(requirements), deferred=tuple(deferred))


def load_deferred_thresholds(
    path: Path = DEFAULT_SWEEP_POLICY,
) -> dict[tuple[str, str], str]:
    policy = load_sweep_policy_config(path)
    deferred = {}
    for item in policy.deferred:
        for arg in item.args:
            deferred[(item.kind, arg)] = item.reason
    return deferred


def validate_sweep_coverage(
    variants: Iterable[SweepVariant],
    *,
    policy_path: Path | None = DEFAULT_SWEEP_POLICY,
) -> list[str]:
    errors = []
    materialized = list(variants)
    if not materialized:
        return ["no sweep variants found"]
    by_arg = sweep_coverage_index(materialized)
    for variant in materialized:
        if not variant.coverage:
            errors.append(f"{variant.id}: missing covers metadata")
            continue
        for coverage in variant.coverage:
            spec = DETECTOR_BY_KIND.get(coverage.kind)
            if spec is None:
                errors.append(f"{variant.id}: unknown detector kind {coverage.kind}")
                continue
            unknown_args = set(coverage.args) - set(spec.threshold_args)
            if unknown_args:
                errors.append(
                    f"{variant.id}: unknown threshold args for {coverage.kind}: "
                    f"{sorted(unknown_args)}"
                )
            if coverage.boundary not in BOUNDARY_KINDS:
                errors.append(f"{variant.id}: unknown boundary {coverage.boundary!r}")
        errors.extend(validate_sweep_expectation_semantics(variant))

    for (kind, arg), boundaries in sorted(by_arg.items()):
        if "at" not in boundaries or not ({"below", "above"} & boundaries):
            errors.append(
                f"{kind}.{arg}: expected at plus below/above boundary coverage"
            )
    if policy_path is not None:
        policy = load_sweep_policy_config(policy_path)
        errors.extend(validate_sweep_policy_references(policy))
        errors.extend(validate_sweep_policy(by_arg, policy.required))
    return errors


def sweep_coverage_index(
    variants: Iterable[SweepVariant],
) -> dict[tuple[str, str], set[str]]:
    by_arg: dict[tuple[str, str], set[str]] = {}
    for variant in variants:
        for coverage in variant.coverage:
            for arg in coverage.args:
                by_arg.setdefault((coverage.kind, arg), set()).add(coverage.boundary)
    return by_arg


def validate_sweep_policy(
    by_arg: dict[tuple[str, str], set[str]],
    requirements: Iterable[SweepPolicyRequirement],
) -> list[str]:
    errors = []
    for requirement in requirements:
        for arg in requirement.args:
            actual = by_arg.get((requirement.kind, arg), set())
            missing = set(requirement.boundaries) - actual
            if missing:
                errors.append(
                    f"{requirement.kind}.{arg}: missing required sweep boundaries "
                    f"{sorted(missing)}"
                )
    return errors


def validate_sweep_policy_references(policy: SweepPolicy) -> list[str]:
    errors = []
    classified: dict[tuple[str, str], str] = {}
    for section, items in (
        ("required", policy.required),
        ("deferred", policy.deferred),
    ):
        for item in items:
            spec = DETECTOR_BY_KIND.get(item.kind)
            if spec is None:
                errors.append(f"{section}: unknown detector kind {item.kind}")
                continue
            if not item.args:
                errors.append(f"{section}: {item.kind} must declare at least one arg")
            if isinstance(item, SweepPolicyRequirement):
                invalid_boundaries = sorted(set(item.boundaries) - BOUNDARY_KINDS)
                if invalid_boundaries:
                    errors.append(
                        f"required: {item.kind} unknown boundaries {invalid_boundaries}"
                    )
                if not item.boundaries:
                    errors.append(
                        f"required: {item.kind} must declare at least one boundary"
                    )
            if isinstance(item, SweepPolicyDeferred) and not item.reason.strip():
                errors.append(f"deferred: {item.kind} must explain deferral")

            for arg in item.args:
                if arg not in spec.threshold_args:
                    errors.append(f"{section}: unknown threshold arg {item.kind}.{arg}")
                    continue
                key = (item.kind, arg)
                previous = classified.get(key)
                if previous is not None:
                    errors.append(
                        f"{item.kind}.{arg}: classified more than once "
                        f"({previous}, {section})"
                    )
                classified[key] = section

    for spec in DETECTORS:
        for arg in spec.threshold_args:
            if (spec.kind, arg) not in classified:
                errors.append(f"{spec.kind}.{arg}: missing sweep policy classification")
    return errors


def validate_sweep_expectation_semantics(variant: SweepVariant) -> list[str]:
    errors = []
    checked = {
        (coverage.kind, coverage.boundary)
        for coverage in variant.coverage
        if coverage.boundary in BOUNDARY_KINDS
    }
    for kind, boundary in sorted(checked):
        if boundary == "at":
            if not case_has_positive_kind(variant.case.data, kind):
                errors.append(
                    f"{variant.id}: at boundary for {kind} must assert a "
                    "positive proof, reason, or live emission"
                )
            continue
        if not case_has_absent_kind(variant.case.data, kind):
            errors.append(
                f"{variant.id}: {boundary} boundary for {kind} must assert "
                "an absent proof or reason"
            )
    return errors


def case_has_positive_kind(data: dict[str, Any], kind: str) -> bool:
    expect = require_mapping(data.get("expect", {}), "expect")
    batch = require_mapping(expect.get("batch", {}), "expect.batch")
    if mapping_has_kind(batch.get("proofs", {}), kind) or mapping_has_kind(
        batch.get("reasons", {}), kind
    ):
        return True
    live = require_mapping(expect.get("live", {}), "expect.live")
    emissions = live.get("emissions", ())
    if not isinstance(emissions, list):
        return False
    return any(
        kind in reason_kinds(require_mapping(emission, "emission").get("reasons", ()))
        for emission in emissions
    )


def case_has_absent_kind(data: dict[str, Any], kind: str) -> bool:
    expect = require_mapping(data.get("expect", {}), "expect")
    batch = require_mapping(expect.get("batch", {}), "expect.batch")
    if mapping_has_kind(batch.get("absent_proofs", {}), kind) or mapping_has_kind(
        batch.get("absent_reasons", {}), kind
    ):
        return True
    live = require_mapping(expect.get("live", {}), "expect.live")
    return mapping_has_kind(live.get("absent_reasons", {}), kind)


def mapping_has_kind(raw: Any, kind: str) -> bool:
    if not isinstance(raw, dict):
        return False
    return any(kind in reason_kinds(values) for values in raw.values())


def reason_kinds(raw: Any) -> set[str]:
    if not isinstance(raw, list | tuple):
        return set()
    return {str(value).split("=", 1)[0] for value in raw}


def catalog_threshold_coverage(
    variants: Iterable[SweepVariant],
) -> list[dict[str, object]]:
    by_arg = sweep_coverage_index(variants)
    rows = []
    for spec in DETECTORS:
        threshold_rows = []
        for arg in spec.threshold_args:
            threshold_rows.append(
                {
                    "arg": arg,
                    "boundaries": sorted(by_arg.get((spec.kind, arg), set())),
                }
            )
        rows.append(
            {
                "kind": spec.kind,
                "outcome": spec.outcome,
                "scope": spec.scope,
                "thresholds": threshold_rows,
            }
        )
    return rows


def parse_coverage(
    path: Path, sweep_name: str, variant: dict[str, Any]
) -> tuple[SweepCoverage, ...]:
    raw = variant.get("covers", ())
    if not isinstance(raw, list):
        raise TypeError(f"{path}:{sweep_name}.{variant['name']}.covers must be a list")
    parsed = []
    for index, item in enumerate(raw):
        coverage = require_mapping(
            item, f"{path}:{sweep_name}.{variant['name']}.covers[{index}]"
        )
        args = coverage.get("args", ())
        args = require_string_list(
            args,
            f"{path}:{sweep_name}.{variant['name']}.covers[{index}].args",
        )
        parsed.append(
            SweepCoverage(
                kind=str(coverage["kind"]),
                args=tuple(args),
                boundary=str(coverage["boundary"]),
            )
        )
    return tuple(parsed)


def deep_merge(target: dict[str, Any], patch: dict[str, Any]) -> None:
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            deep_merge(target[key], value)
        else:
            target[key] = copy.deepcopy(value)


def set_path(target: Any, dotted_path: str, value: Any) -> None:
    parts = dotted_path.split(".")
    current = target
    for part in parts[:-1]:
        current = path_child(current, part)
    assign_path_child(current, parts[-1], value)


def path_child(current: Any, part: str) -> Any:
    if isinstance(current, list):
        return current[int(part)]
    if not isinstance(current, dict):
        raise TypeError(f"cannot descend into {type(current).__name__}")
    if part not in current:
        raise KeyError(f"cannot descend into missing key {part!r}")
    return current[part]


def assign_path_child(current: Any, part: str, value: Any) -> None:
    if isinstance(current, list):
        current[int(part)] = copy.deepcopy(value)
        return
    if not isinstance(current, dict):
        raise TypeError(f"cannot assign into {type(current).__name__}")
    current[part] = copy.deepcopy(value)


def require_mapping(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TypeError(f"{context} must be an object")
    return value


def require_string_list(value: Any, context: str) -> list[str]:
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise TypeError(f"{context} must be a string or list of strings")
    return value


def format_text(results: list[dict[str, str]]) -> str:
    if not results:
        return "No sweep variants found."
    return "\n".join(f"{result['id']}: {result['status']}" for result in results)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run generated detector threshold sweep variants."
    )
    parser.add_argument(
        "path",
        nargs="?",
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
    parser.add_argument(
        "--check",
        action="store_true",
        help="Run expectations and fail on any sweep mismatch.",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=None,
        help="Sweep coverage policy JSON. Defaults to coverage_policy.json beside a sweep directory.",
    )
    return parser


def main(argv: Sequence[str] | None = None, stdout: TextIO | None = None) -> int:
    args = build_parser().parse_args(argv)
    variants = load_sweep_variants(args.path)
    output = stdout if stdout is not None else sys.stdout
    if args.check:
        policy_path = args.policy or policy_path_for_sweep_root(args.path)
        coverage_errors = validate_sweep_coverage(variants, policy_path=policy_path)
        if coverage_errors:
            print("\n".join(coverage_errors), file=output)
            return 1
        results = run_sweep_variants(variants)
    else:
        results = [
            {
                "id": variant.id,
                "case": variant.case.id,
                "status": "loaded",
            }
            for variant in variants
        ]
    if args.format == "json":
        print(json.dumps(results, indent=2), file=output)
    else:
        print(format_text(results), file=output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
