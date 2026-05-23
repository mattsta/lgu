from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from synthetic_access import (
    JUNK_REFERRER,
    REFERRER,
    audit_args,
    doc_ip,
    proof_kinds,
    row,
    rows_for_paths,
    synthetic_paths,
)

from lgu.audit import (
    ForcedProof,
    IPStats,
    build_ip_stats,
    build_runtime,
    detect_subnet_sweep,
    evaluate_ip_decision,
    has_payload_marker_mutation,
    payload_campaign_key,
    payload_family,
    subnet_host_key,
    subnet_key,
)


def test_evaluate_ip_decision_strong_proof_forces_ban() -> None:
    args = audit_args(ban_score=999.0)
    evaluation = evaluate_ip_decision(
        IPStats(ip=doc_ip(90)),
        [ForcedProof(kind="serial-sweep", detail="synthetic serial proof")],
        args,
    )

    assert evaluation.action == "ban"
    assert evaluation.heuristic.reasons == ("serial-sweep",)


def test_evaluate_ip_decision_rotating_ua_is_suspect_until_score_threshold() -> None:
    args = audit_args(ban_score=999.0)
    evaluation = evaluate_ip_decision(
        IPStats(ip=doc_ip(91)),
        [ForcedProof(kind="rotating-ua", detail="synthetic rotating proof")],
        args,
    )

    assert evaluation.action == "suspect"
    assert evaluation.heuristic.reasons == ("rotating-ua",)


def test_evaluate_ip_decision_dedupes_proof_reason_kinds() -> None:
    args = audit_args()
    evaluation = evaluate_ip_decision(
        IPStats(ip=doc_ip(92)),
        [
            ForcedProof(kind="serial-sweep", detail="first"),
            ForcedProof(kind="serial-sweep", detail="second"),
        ],
        args,
    )

    assert evaluation.heuristic.reasons.count("serial-sweep") == 1


def test_payload_family_classifies_marker_mutation_injection_and_referer_junk() -> None:
    marker_patterns = ("render=full",)

    assert (
        payload_family("/synthetic/payload?render=full", "-", marker_patterns)
        == "payload-marker-walker"
    )
    assert (
        payload_family("/synthetic/payload?render=full&x=1", "-", marker_patterns)
        == "param-mutation"
    )
    assert (
        payload_family("/synthetic/payload?abcd=1234%20and%201=1", "-", ())
        == "injection-probe"
    )
    assert payload_family("/synthetic/payload", JUNK_REFERRER, ()) == "referer-fuzzer"
    assert (
        payload_family(
            "/synthetic/payload?abcd=1234%20and%201=1",
            JUNK_REFERRER,
            marker_patterns,
        )
        == "injection-probe+ref-junk"
    )
    assert has_payload_marker_mutation(
        "/synthetic/payload?render=full&x=1", marker_patterns
    )
    assert (
        payload_campaign_key(
            "/synthetic-payload?render=full", REFERRER, marker_patterns
        )
        == "payload-marker-walker:slug"
    )


@settings(max_examples=40, deadline=None)
@given(
    base_gap=st.floats(min_value=3000.0, max_value=7200.0, allow_nan=False),
    jitter=st.floats(min_value=0.0, max_value=5.0, allow_nan=False),
)
def test_cadenced_repeat_accepts_generated_gap_spread_within_tolerance(
    base_gap: float, jitter: float
) -> None:
    ip = doc_ip(93)
    rows = [
        row(0.0, ip, "/synthetic/generated-cadence"),
        row(base_gap, ip, "/synthetic/generated-cadence"),
        row(base_gap * 2 + jitter, ip, "/synthetic/generated-cadence"),
    ]

    assert "cadenced-repeat" in proof_kinds(
        rows, audit_args(cadence_hour_repeat_count=99)
    )


@settings(max_examples=40, deadline=None)
@given(
    base_gap=st.floats(min_value=3000.0, max_value=7200.0, allow_nan=False),
    excess=st.floats(min_value=5.01, max_value=120.0, allow_nan=False),
)
def test_cadenced_repeat_rejects_generated_gap_spread_above_tolerance(
    base_gap: float, excess: float
) -> None:
    ip = doc_ip(94)
    rows = [
        row(0.0, ip, "/synthetic/generated-cadence-negative"),
        row(base_gap, ip, "/synthetic/generated-cadence-negative"),
        row(base_gap * 2 + excess, ip, "/synthetic/generated-cadence-negative"),
    ]

    assert "cadenced-repeat" not in proof_kinds(
        rows, audit_args(cadence_hour_repeat_count=99)
    )


@settings(max_examples=30, deadline=None)
@given(
    count=st.integers(min_value=12, max_value=30),
    step=st.floats(min_value=0.01, max_value=0.15, allow_nan=False),
)
def test_burst_property_flags_dense_unique_generated_paths(
    count: int, step: float
) -> None:
    args = audit_args()
    ip = doc_ip(95)
    stats_rows = rows_for_paths(
        synthetic_paths("generated-burst", count), ip=ip, step=step
    )

    stats = build_ip_stats(stats_rows, args, build_runtime(args))[ip]

    assert stats.is_bot(args) is True


def test_subnet_key_groups_ipv4_and_ipv6_by_configured_prefix() -> None:
    assert subnet_key(doc_ip(130, net=2), 22, 48) == "198.51.100.0/22"
    assert subnet_key(doc_ip(130, net=2), 25, 48) == "198.51.100.128/25"
    assert subnet_key("2001:db8:aa:1::5", 22, 48) == "2001:db8:aa::/48"
    assert subnet_key("not-an-ip", 22, 48) == "not-an-ip"


def test_subnet_host_key_collapses_ipv6_privacy_addresses_to_one_host() -> None:
    assert subnet_host_key("2001:db8:aa:1::5") == subnet_host_key("2001:db8:aa:1::9")
    assert subnet_host_key("2001:db8:aa:1::5") != subnet_host_key("2001:db8:aa:2::5")
    assert subnet_host_key(doc_ip(5)) == doc_ip(5)


def test_subnet_sweep_ignores_single_ipv6_reader_rotating_privacy_addresses() -> None:
    args = audit_args()
    rows = [
        row(index * 60.0, f"2001:db8:aa:1::{index + 1:x}", f"/synthetic/v6-{index}")
        for index in range(8)
    ]

    assert detect_subnet_sweep(rows, args).forced_proofs_by_ip == {}


def test_subnet_sweep_flags_ipv6_pool_spread_across_distinct_64s() -> None:
    args = audit_args()
    rows = [
        row(index * 60.0, f"2001:db8:aa:{index + 1:x}::1", f"/synthetic/v6-{index}")
        for index in range(6)
    ]

    proofs = detect_subnet_sweep(rows, args).forced_proofs_by_ip

    assert set(proofs) == {request.ip for request in rows}
    assert "subnet=2001:db8:aa::/48" in proofs[rows[-1].ip][-1].detail


def test_build_runtime_rejects_out_of_range_subnet_prefix() -> None:
    with pytest.raises(ValueError, match="--subnet-sweep-ipv4-prefix"):
        build_runtime(audit_args(subnet_sweep_ipv4_prefix=33))
