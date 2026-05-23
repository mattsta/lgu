from __future__ import annotations

from synthetic_access import (
    CHROME_WIN_134_UA,
    CHROME_WIN_135_UA,
    FIREFOX_122_UA,
    REFERRER,
    SHARED_UA,
    audit_args,
    doc_ip,
    row,
    watch_args,
)

from lgu.audit import (
    DetectorConfig,
    analyze_payload_campaigns,
    build_runtime,
    detect_coordinated_target_fanout,
    detect_coordinated_ua_ips,
)
from lgu.watch import LiveContext, gc_global_windows, process_row


def make_context(args) -> LiveContext:
    return LiveContext(runtime=build_runtime(args))


def test_coordinated_ua_includes_exact_window_cutoff() -> None:
    args = audit_args(
        coord_window_seconds=10.0,
        coord_count=3,
        coord_unique_paths=3,
        coord_unique_ips=3,
    )
    rows = [
        row(0.0, doc_ip(1), "/synthetic/coord-a", SHARED_UA),
        row(5.0, doc_ip(2), "/synthetic/coord-b", SHARED_UA),
        row(10.0, doc_ip(3), "/synthetic/coord-c", SHARED_UA),
    ]

    analysis = detect_coordinated_ua_ips(rows, args)

    assert set(analysis.forced_proofs_by_ip) == {
        doc_ip(1),
        doc_ip(2),
        doc_ip(3),
    }


def test_coordinated_ua_rejects_one_ip_dominance_and_low_diversity() -> None:
    args = audit_args(
        coord_window_seconds=10.0,
        coord_count=5,
        coord_unique_paths=3,
        coord_unique_ips=3,
        coord_max_ip_share=0.6,
    )
    one_ip_dominant_rows = [
        row(0.0, doc_ip(1), "/synthetic/coord-a", SHARED_UA),
        row(1.0, doc_ip(1), "/synthetic/coord-b", SHARED_UA),
        row(2.0, doc_ip(1), "/synthetic/coord-c", SHARED_UA),
        row(3.0, doc_ip(1), "/synthetic/coord-d", SHARED_UA),
        row(4.0, doc_ip(2), "/synthetic/coord-e", SHARED_UA),
        row(5.0, doc_ip(3), "/synthetic/coord-f", SHARED_UA),
    ]
    low_path_diversity_rows = [
        row(float(index), doc_ip(index + 1), "/synthetic/coord-single", SHARED_UA)
        for index in range(5)
    ]

    assert not detect_coordinated_ua_ips(one_ip_dominant_rows, args).forced_proofs_by_ip
    assert not detect_coordinated_ua_ips(
        low_path_diversity_rows, args
    ).forced_proofs_by_ip


def test_target_fanout_collapses_query_variants_but_keeps_families_separate() -> None:
    args = audit_args(
        target_fanout_count=3,
        target_fanout_unique_ips=3,
        target_fanout_window_seconds=30.0,
    )
    chrome_rows = [
        row(
            ts=float(index),
            ip=doc_ip(index + 10),
            path=f"/synthetic/fanout-target?variant={index}",
            ua=CHROME_WIN_134_UA if index == 0 else CHROME_WIN_135_UA,
            referer=REFERRER,
        )
        for index in range(3)
    ]
    mixed_family_rows = [
        chrome_rows[0],
        row(
            ts=1.0,
            ip=doc_ip(20),
            path="/synthetic/fanout-target?variant=firefox",
            ua=FIREFOX_122_UA,
            referer=REFERRER,
        ),
        chrome_rows[1],
    ]

    positive = detect_coordinated_target_fanout(chrome_rows, args)
    separated = detect_coordinated_target_fanout(mixed_family_rows, args)

    assert set(positive.forced_proofs_by_ip) == {
        doc_ip(10),
        doc_ip(11),
        doc_ip(12),
    }
    assert not separated.forced_proofs_by_ip


def test_target_fanout_rejects_low_referer_dominance() -> None:
    args = audit_args(
        target_fanout_count=3,
        target_fanout_unique_ips=3,
        target_fanout_window_seconds=30.0,
        target_fanout_dominant_referer_ratio=0.8,
    )
    rows = [
        row(0.0, doc_ip(21), "/synthetic/fanout-low-ref", CHROME_WIN_135_UA, REFERRER),
        row(1.0, doc_ip(22), "/synthetic/fanout-low-ref", CHROME_WIN_135_UA, "-"),
        row(2.0, doc_ip(23), "/synthetic/fanout-low-ref", CHROME_WIN_135_UA, "-"),
    ]

    assert not detect_coordinated_target_fanout(rows, args).forced_proofs_by_ip


def test_same_ua_target_fanout_catches_tight_distributed_burst() -> None:
    args = audit_args(target_fanout_count=100)
    rows = [
        row(0.0, doc_ip(24), "/synthetic/exact-ua-target", SHARED_UA),
        row(1.0, doc_ip(25), "/synthetic/exact-ua-target", SHARED_UA),
        row(2.0, doc_ip(26), "/synthetic/exact-ua-target", SHARED_UA),
    ]

    analysis = detect_coordinated_target_fanout(rows, args)

    assert set(analysis.forced_proofs_by_ip) == {
        doc_ip(24),
        doc_ip(25),
        doc_ip(26),
    }
    detail = analysis.forced_proofs_by_ip[doc_ip(24)][0].detail
    assert "mode=same-ua-target-fanout" in detail


def test_same_ua_target_fanout_respects_tight_window() -> None:
    args = audit_args(target_fanout_count=100)
    rows = [
        row(0.0, doc_ip(27), "/synthetic/exact-ua-slow-target", SHARED_UA),
        row(1.0, doc_ip(28), "/synthetic/exact-ua-slow-target", SHARED_UA),
        row(6.1, doc_ip(29), "/synthetic/exact-ua-slow-target", SHARED_UA),
    ]

    assert not detect_coordinated_target_fanout(rows, args).forced_proofs_by_ip


def test_payload_campaign_ignores_non_candidates_and_summarizes_best_window() -> None:
    args = audit_args(
        detector_config=DetectorConfig(payload_marker_patterns=("render=full",)),
        payload_campaign_count=3,
        payload_campaign_unique_ips=3,
        payload_campaign_unique_paths=3,
        payload_campaign_window_seconds=30.0,
    )
    runtime = build_runtime(args)
    rows = [
        row(0.0, doc_ip(30), "/synthetic/no-marker-a"),
        row(1.0, doc_ip(31), "/synthetic/payload-a?render=full"),
        row(2.0, doc_ip(32), "/synthetic/payload-b?render=full"),
        row(3.0, doc_ip(33), "/synthetic/payload-c?render=full"),
        row(4.0, doc_ip(34), "/synthetic/payload-d?render=full"),
    ]

    analysis = analyze_payload_campaigns(rows, args, runtime)

    assert set(analysis.forced_proofs_by_ip) == {
        doc_ip(31),
        doc_ip(32),
        doc_ip(33),
        doc_ip(34),
    }
    assert analysis.summaries[0].request_count == 4
    assert analysis.summaries[0].unique_paths == 4


def test_live_coordinated_ua_bans_on_threshold_row() -> None:
    args = watch_args(
        coord_window_seconds=10.0,
        coord_count=3,
        coord_unique_paths=3,
        coord_unique_ips=3,
    )
    context = make_context(args)

    assert (
        process_row(
            row(0.0, doc_ip(40), "/synthetic/live-coord-a", SHARED_UA), context, args
        )
        is None
    )
    assert (
        process_row(
            row(1.0, doc_ip(41), "/synthetic/live-coord-b", SHARED_UA), context, args
        )
        is None
    )
    decision = process_row(
        row(2.0, doc_ip(42), "/synthetic/live-coord-c", SHARED_UA), context, args
    )

    assert decision is not None
    assert decision.action == "ban"
    assert "coordinated-ua" in decision.reasons


def test_live_target_fanout_bans_on_threshold_row() -> None:
    args = watch_args(
        target_fanout_count=3,
        target_fanout_unique_ips=3,
        target_fanout_window_seconds=30.0,
    )
    context = make_context(args)

    for index in range(2):
        decision = process_row(
            row(
                ts=float(index),
                ip=doc_ip(50 + index),
                path="/synthetic/live-fanout-target",
                ua=CHROME_WIN_135_UA,
                referer=REFERRER,
            ),
            context,
            args,
        )
        assert decision is None
    decision = process_row(
        row(
            ts=2.0,
            ip=doc_ip(52),
            path="/synthetic/live-fanout-target",
            ua=CHROME_WIN_135_UA,
            referer=REFERRER,
        ),
        context,
        args,
    )

    assert decision is not None
    assert decision.action == "ban"
    assert "coordinated-target-fanout" in decision.reasons


def test_live_same_ua_target_fanout_bans_on_tight_distributed_burst() -> None:
    args = watch_args(target_fanout_count=100)
    context = make_context(args)

    for index in range(2):
        decision = process_row(
            row(
                ts=float(index),
                ip=doc_ip(53 + index),
                path="/synthetic/live-exact-ua-target",
                ua=SHARED_UA,
            ),
            context,
            args,
        )
        assert decision is None
    decision = process_row(
        row(
            ts=2.0,
            ip=doc_ip(55),
            path="/synthetic/live-exact-ua-target",
            ua=SHARED_UA,
        ),
        context,
        args,
    )

    assert decision is not None
    assert decision.action == "ban"
    assert "coordinated-target-fanout" in decision.reasons
    assert "mode=same-ua-target-fanout" in decision.proof_detail


def test_live_payload_campaign_bans_on_threshold_row() -> None:
    args = watch_args(
        detector_config=DetectorConfig(payload_marker_patterns=("render=full",)),
        payload_campaign_count=3,
        payload_campaign_unique_ips=3,
        payload_campaign_unique_paths=3,
        payload_campaign_window_seconds=30.0,
    )
    context = make_context(args)

    for index in range(2):
        decision = process_row(
            row(
                ts=float(index),
                ip=doc_ip(60 + index),
                path=f"/synthetic/live-payload-{index}?render=full",
            ),
            context,
            args,
        )
        assert decision is None
    decision = process_row(
        row(2.0, doc_ip(62), "/synthetic/live-payload-2?render=full"),
        context,
        args,
    )

    assert decision is not None
    assert decision.action == "ban"
    assert "payload-campaign" in decision.reasons


def test_live_cooldown_suppresses_and_then_allows_same_action_reemit() -> None:
    args = watch_args(
        detector_config=DetectorConfig(known_bot_ua_patterns=("SyntheticFetcher/",)),
        cooldown_seconds=10.0,
    )
    context = make_context(args)

    first = process_row(
        row(0.0, doc_ip(70), "/synthetic/known-bot-a", "SyntheticFetcher/2.0.0"),
        context,
        args,
    )
    suppressed = process_row(
        row(1.0, doc_ip(70), "/synthetic/known-bot-b", "SyntheticFetcher/2.0.0"),
        context,
        args,
    )
    reemitted = process_row(
        row(11.0, doc_ip(70), "/synthetic/known-bot-c", "SyntheticFetcher/2.0.0"),
        context,
        args,
    )

    assert first is not None
    assert first.action == "ban"
    assert suppressed is None
    assert reemitted is not None
    assert reemitted.action == "ban"


def test_gc_global_windows_prunes_all_detector_maps() -> None:
    args = watch_args(
        coord_window_seconds=10.0,
        target_fanout_window_seconds=10.0,
        payload_campaign_window_seconds=10.0,
        detector_config=DetectorConfig(payload_marker_patterns=("render=full",)),
    )
    context = make_context(args)

    process_row(
        row(0.0, doc_ip(80), "/synthetic/global-a?render=full", SHARED_UA),
        context,
        args,
    )
    assert context.coordinated_windows
    assert context.target_fanout_windows
    assert context.target_same_ua_fanout_windows
    assert context.payload_windows

    gc_global_windows(context, 20.0, args)

    assert not context.coordinated_windows
    assert not context.target_fanout_windows
    assert not context.target_same_ua_fanout_windows
    assert not context.payload_windows
