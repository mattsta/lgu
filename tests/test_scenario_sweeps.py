from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from scenario_dsl import ScenarioCase
from scenario_sweeps import (
    SweepCoverage,
    SweepPolicy,
    SweepPolicyDeferred,
    SweepPolicyRequirement,
    SweepVariant,
    catalog_threshold_coverage,
    deep_merge,
    load_deferred_thresholds,
    load_sweep_policy_config,
    load_sweep_variants,
    main,
    run_sweep_variant,
    set_path,
    sweep_coverage_index,
    validate_sweep_coverage,
    validate_sweep_policy,
    validate_sweep_policy_references,
)

SWEEP_ROOT = Path(__file__).parent / "sweeps"
SWEEP_VARIANTS = load_sweep_variants(SWEEP_ROOT)


@pytest.mark.parametrize(
    "variant",
    [pytest.param(variant, id=variant.id) for variant in SWEEP_VARIANTS],
)
def test_sweep_variant_expectations(variant) -> None:
    run_sweep_variant(variant)


def test_set_path_updates_nested_lists_and_dicts() -> None:
    data = {"events": [{"repeat": 8}], "expect": {"batch": {}}}

    set_path(data, "events.0.repeat", 7)
    set_path(data, "expect.batch.clean", ["source"])

    assert data == {
        "events": [{"repeat": 7}],
        "expect": {"batch": {"clean": ["source"]}},
    }


def test_set_path_rejects_missing_intermediate_key() -> None:
    data = {"expect": {"batch": {}}}

    with pytest.raises(KeyError, match="missing key"):
        set_path(data, "expect.btach.clean", ["source"])


def test_sweep_variants_have_catalog_backed_coverage_metadata() -> None:
    assert validate_sweep_coverage(SWEEP_VARIANTS) == []


def test_sweep_policy_deferred_thresholds_are_machine_readable() -> None:
    deferred = load_deferred_thresholds()

    assert deferred[("known-ua-or-referer", "known_bot_ua_patterns")].startswith(
        "regex configuration"
    )
    assert deferred[("provider-hosted-activity", "provider_watch")].startswith(
        "provider data source"
    )


def test_sweep_policy_classifies_every_catalog_threshold_arg() -> None:
    assert validate_sweep_policy_references(load_sweep_policy_config()) == []


def test_sweep_policy_rejects_unclassified_unknown_or_duplicate_args() -> None:
    policy = SweepPolicy(
        required=(
            SweepPolicyRequirement(
                kind="repeated-pair",
                args=("pair_repeat_count", "not_a_real_arg"),
                boundaries=("at", "sometimes"),
            ),
        ),
        deferred=(
            SweepPolicyDeferred(
                kind="repeated-pair",
                args=("pair_repeat_count",),
                reason="",
            ),
            SweepPolicyDeferred(
                kind="unknown-detector",
                args=("threshold",),
                reason="synthetic",
            ),
        ),
    )

    errors = validate_sweep_policy_references(policy)

    assert "required: unknown threshold arg repeated-pair.not_a_real_arg" in errors
    assert "required: repeated-pair unknown boundaries ['sometimes']" in errors
    assert "deferred: repeated-pair must explain deferral" in errors
    assert (
        "repeated-pair.pair_repeat_count: classified more than once "
        "(required, deferred)"
    ) in errors
    assert "deferred: unknown detector kind unknown-detector" in errors
    assert "burst.window_seconds: missing sweep policy classification" in errors


def test_sweep_coverage_requires_at_boundary_positive_expectation() -> None:
    variant = synthetic_variant(
        boundary="at",
        expect={
            "batch": {
                "clean": ["source"],
                "absent_reasons": {"source": ["burst"]},
            }
        },
    )

    errors = validate_sweep_coverage([variant], policy_path=None)

    assert any(
        "at boundary for burst must assert a positive proof, reason, or live emission"
        in error
        for error in errors
    )


def test_sweep_coverage_requires_clean_boundary_absent_expectation() -> None:
    variant = synthetic_variant(
        boundary="below",
        expect={
            "batch": {
                "clean": ["source"],
            },
            "live": {
                "no_emissions": ["source"],
            },
        },
    )

    errors = validate_sweep_coverage([variant], policy_path=None)

    assert any(
        "below boundary for burst must assert an absent proof or reason" in error
        for error in errors
    )


def test_sweep_policy_reports_missing_required_boundary() -> None:
    errors = validate_sweep_policy(
        sweep_coverage_index(SWEEP_VARIANTS),
        (
            SweepPolicyRequirement(
                kind="repeated-pair",
                args=("pair_repeat_count",),
                boundaries=("below", "at", "above"),
            ),
        ),
    )

    assert errors == [
        "repeated-pair.pair_repeat_count: missing required sweep boundaries ['above']"
    ]


def test_catalog_threshold_coverage_reports_uncovered_catalog_args() -> None:
    rows = {row["kind"]: row for row in catalog_threshold_coverage(SWEEP_VARIANTS)}

    repeated_pair = {
        threshold["arg"]: threshold["boundaries"]
        for threshold in rows["repeated-pair"]["thresholds"]
    }
    assert repeated_pair["pair_repeat_count"] == ["at", "below"]
    assert repeated_pair["pair_gap_seconds"] == ["above", "at"]


def test_deep_merge_replaces_values_and_merges_nested_objects() -> None:
    data = {"expect": {"batch": {"bots": ["source"], "proofs": {"source": ["x"]}}}}

    deep_merge(data, {"expect": {"batch": {"bots": [], "clean": ["source"]}}})

    assert data == {
        "expect": {
            "batch": {
                "bots": [],
                "proofs": {"source": ["x"]},
                "clean": ["source"],
            }
        }
    }


def test_cli_check_reports_loaded_sweep_results() -> None:
    stdout = io.StringIO()

    assert main([str(SWEEP_ROOT), "--format", "json", "--check"], stdout=stdout) == 0

    results = json.loads(stdout.getvalue())
    assert len(results) == len(SWEEP_VARIANTS)
    assert {result["status"] for result in results} == {"passed"}


def synthetic_variant(*, boundary: str, expect: dict) -> SweepVariant:
    return SweepVariant(
        path=Path("synthetic_sweep.json"),
        sweep_name="synthetic",
        variant_name=boundary,
        case=ScenarioCase(
            path=Path("synthetic_sweep.json"),
            data={
                "name": f"synthetic_{boundary}",
                "actors": {"source": {"ip": "doc:1:10", "ua": "chrome_120"}},
                "events": [
                    {
                        "actor": "source",
                        "at": 0,
                        "path": "/synthetic/sweep-semantic",
                    }
                ],
                "expect": expect,
            },
        ),
        coverage=(
            SweepCoverage(kind="burst", args=("burst_count",), boundary=boundary),
        ),
    )
