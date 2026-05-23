from __future__ import annotations

from synthetic_access import (
    ALT_REFERRER,
    CHROME_120_UA,
    CHROME_133_UA,
    CHROME_WIN_134_UA,
    CHROME_WIN_135_UA,
    FIREFOX_122_UA,
    FIREFOX_150_UA,
    REFERRER,
    SAFARI_17_UA,
    audit_args,
    doc_ip,
    proof_kinds,
    row,
    rows_for_paths,
    synthetic_paths,
)

from lgu.audit import (
    DetectorConfig,
    build_ip_stats,
    build_runtime,
)


def assert_proof(rows, proof_kind: str, args=None) -> None:
    assert proof_kind in proof_kinds(rows, args)


def assert_no_proof(rows, proof_kind: str, args=None) -> None:
    assert proof_kind not in proof_kinds(rows, args)


def test_per_ip_detector_threshold_defaults_are_intentional() -> None:
    args = audit_args()

    assert args.burst_count == 12
    assert args.unique_paths == 8
    assert args.head_burst == 6
    assert args.sweep_count == 10
    assert args.pair_repeat_count == 8
    assert args.multi_fetch_count == 4
    assert args.exposure_probe_window_seconds == 10.0
    assert args.exposure_probe_asset_count == 2
    assert args.exposure_probe_count == 2
    assert args.cadence_repeat_count == 3
    assert args.cadence_hour_repeat_count == 2
    assert args.cadence_hour_gap_seconds == 3600.0
    assert args.cadence_hour_gap_tolerance_seconds == 120.0
    assert args.rotate_ua_count == 6
    assert args.poll_repeat_count == 6
    assert args.serial_count == 12
    assert args.payload_show_analysis_count == 12
    assert args.same_second_ua_swap_count == 1
    assert args.ua_switch_count == 2


def test_burst_requires_request_count_and_path_diversity() -> None:
    args = audit_args()
    ip = doc_ip(60)
    burst_rows = rows_for_paths(
        synthetic_paths("burst", 12), ip=ip, start=0.0, step=0.1
    )
    repeated_path_rows = rows_for_paths(
        ["/synthetic/repeated-burst-target"] * 12, ip=ip, start=0.0, step=0.1
    )

    burst_stats = build_ip_stats(burst_rows, args, build_runtime(args))[ip]
    repeated_stats = build_ip_stats(repeated_path_rows, args, build_runtime(args))[ip]

    assert burst_stats.is_bot(args) is True
    assert repeated_stats.is_bot(args) is False


def test_head_burst_requires_head_density_and_path_diversity() -> None:
    args = audit_args()
    ip = doc_ip(61)
    head_rows = rows_for_paths(
        synthetic_paths("head", 6), ip=ip, start=0.0, step=0.1, method="HEAD"
    )
    same_target_head_rows = rows_for_paths(
        ["/synthetic/head-target"] * 6,
        ip=ip,
        start=0.0,
        step=0.1,
        method="HEAD",
    )

    head_stats = build_ip_stats(head_rows, args, build_runtime(args))[ip]
    same_target_stats = build_ip_stats(
        same_target_head_rows, args, build_runtime(args)
    )[ip]

    assert head_stats.is_bot(args) is True
    assert same_target_stats.is_bot(args) is False


def test_paced_sweep_requires_dominant_referer() -> None:
    args = audit_args()
    ip = doc_ip(62)
    paths = synthetic_paths("sweep-window", 8) + [
        "/synthetic/sweep-window-00",
        "/synthetic/sweep-window-01",
    ]
    dominant_rows = rows_for_paths(paths, ip=ip, start=0.0, step=4.0, referer=REFERRER)
    split_referer_rows = [
        row(
            ts=index * 4.0,
            ip=ip,
            path=path,
            referer=REFERRER if index < 6 else ALT_REFERRER,
        )
        for index, path in enumerate(paths)
    ]

    dominant_stats = build_ip_stats(dominant_rows, args, build_runtime(args))[ip]
    split_stats = build_ip_stats(split_referer_rows, args, build_runtime(args))[ip]

    assert dominant_stats.is_bot(args) is True
    assert split_stats.is_bot(args) is False


def test_fast_streak_requires_path_changes_and_unique_total() -> None:
    args = audit_args()
    ip = doc_ip(63)
    paths = synthetic_paths("streak", 20)
    streak_rows = rows_for_paths(paths, ip=ip, start=0.0, step=0.5)
    same_path_rows = rows_for_paths(
        ["/synthetic/streak-single-target"] * 20, ip=ip, start=0.0, step=0.5
    )

    streak_stats = build_ip_stats(streak_rows, args, build_runtime(args))[ip]
    same_path_stats = build_ip_stats(same_path_rows, args, build_runtime(args))[ip]

    assert streak_stats.is_bot(args) is True
    assert same_path_stats.is_bot(args) is False


def test_repeated_pair_fires_at_default_threshold_and_not_below() -> None:
    args = audit_args()
    ip = doc_ip(64)

    def repeated_pair_rows(pair_count: int):
        rows = []
        for index in range(pair_count):
            start = index * 40.0
            rows.append(row(start, ip, "/synthetic/pair-alpha"))
            rows.append(row(start + 1.0, ip, "/synthetic/pair-beta"))
        return rows

    assert_proof(repeated_pair_rows(8), "repeated-pair", args)
    assert_no_proof(repeated_pair_rows(7), "repeated-pair", args)


def test_redundant_revisit_requires_referer_dominance() -> None:
    args = audit_args()
    ip = doc_ip(65)
    paths = synthetic_paths("revisit", 5)
    dominant_rows = [
        row(ts=index * 40.0, ip=ip, path=path, referer=REFERRER)
        for index, path in enumerate(paths * 3)
    ]
    split_rows = [
        row(
            ts=index * 40.0,
            ip=ip,
            path=path,
            referer=REFERRER if index < 8 else ALT_REFERRER,
        )
        for index, path in enumerate(paths * 3)
    ]

    assert_proof(dominant_rows, "redundant-revisit", args)
    assert_no_proof(split_rows, "redundant-revisit", args)


def test_rotating_ua_requires_family_diversity() -> None:
    args = audit_args()
    ip = doc_ip(66)
    diverse_uas = [
        CHROME_120_UA,
        CHROME_133_UA,
        FIREFOX_122_UA,
        FIREFOX_150_UA,
        SAFARI_17_UA,
        "Mozilla/5.0 YaSearchBrowser/24.1",
    ]
    chrome_version_uas = [
        f"Mozilla/5.0 Chrome/{version}.0 Safari/537.36" for version in range(120, 126)
    ]
    diverse_rows = [
        row(ts=index * 3.0, ip=ip, path=f"/synthetic/ua-{index}", ua=ua)
        for index, ua in enumerate(diverse_uas)
    ]
    chrome_rows = [
        row(ts=index * 3.0, ip=ip, path=f"/synthetic/chrome-{index}", ua=ua)
        for index, ua in enumerate(chrome_version_uas)
    ]

    assert_proof(diverse_rows, "rotating-ua", args)
    assert_no_proof(chrome_rows, "rotating-ua", args)


def test_periodic_poller_requires_exact_gap_mode() -> None:
    args = audit_args()
    ip = doc_ip(67)
    path = "/synthetic/poll-target"
    exact_rows = [row(ts=index * 3600.0, ip=ip, path=path) for index in range(6)]
    jittered_offsets = [0.0, 3600.0, 7200.0, 10806.0, 14406.0, 18006.0]
    jittered_rows = [row(ts=ts, ip=ip, path=path) for ts in jittered_offsets]

    assert_proof(exact_rows, "periodic-poller", args)
    assert_no_proof(jittered_rows, "periodic-poller", args)


def test_serial_sweep_default_thresholds() -> None:
    args = audit_args()
    ip = doc_ip(68)
    sweep_rows = rows_for_paths(
        synthetic_paths("serial", 12), ip=ip, start=0.0, step=1.0
    )
    too_fast_rows = rows_for_paths(
        synthetic_paths("serial-fast", 12), ip=ip, start=0.0, step=0.79
    )
    low_diversity_rows = rows_for_paths(
        [f"/synthetic/serial-low-{index % 9}" for index in range(12)],
        ip=ip,
        start=0.0,
        step=1.0,
    )

    assert_proof(sweep_rows, "serial-sweep", args)
    assert_no_proof(too_fast_rows, "serial-sweep", args)
    assert_no_proof(low_diversity_rows, "serial-sweep", args)


def test_payload_fuzzer_requires_configured_marker() -> None:
    marker = "synthetic_marker="
    configured_args = audit_args(
        detector_config=DetectorConfig(payload_marker_patterns=(marker,))
    )
    default_args = audit_args()
    ip = doc_ip(69)
    rows = [
        row(
            ts=float(index),
            ip=ip,
            path=(
                f"/synthetic/payload-target?synthetic_marker={index}"
                "&probe=union%20all%20select"
            ),
        )
        for index in range(12)
    ]

    assert_proof(rows, "payload-fuzzer", configured_args)
    assert_no_proof(rows, "payload-fuzzer", default_args)


def test_asset_primed_probe_requires_page_assets_and_exposure_paths() -> None:
    args = audit_args()
    ip = doc_ip(72)
    page = "/synthetic/asset-primed-page"
    referer = f"https://reader.example.test{page}"
    positive_rows = [
        row(0.0, ip=ip, path=page, referer="-"),
        row(0.1, ip=ip, path="/synthetic/js?v=alpha", referer=referer),
        row(0.2, ip=ip, path="/synthetic/style?v=alpha", referer=referer),
        row(0.3, ip=ip, path="/synthetic/.git/HEAD", referer=referer),
        row(0.4, ip=ip, path="/synthetic/.git/config", referer=referer),
    ]
    no_asset_rows = [
        row(0.0, ip=ip, path=page, referer="-"),
        row(0.3, ip=ip, path="/synthetic/.git/HEAD", referer=referer),
        row(0.4, ip=ip, path="/synthetic/.git/config", referer=referer),
    ]

    assert_proof(positive_rows, "asset-primed-probe", args)
    assert_no_proof(no_asset_rows, "asset-primed-probe", args)


def test_same_second_ua_swap_requires_marker_twins_and_different_uas() -> None:
    args = audit_args(
        detector_config=DetectorConfig(payload_marker_patterns=("synthetic_marker=",))
    )
    ip = doc_ip(70)
    positive_rows = [
        row(
            ts=100.2,
            ip=ip,
            path="/synthetic/marker-twin?synthetic_marker=alpha",
            ua=CHROME_120_UA,
        ),
        row(
            ts=100.8,
            ip=ip,
            path="/synthetic/marker-twin?synthetic_marker=beta",
            ua=FIREFOX_122_UA,
        ),
    ]
    same_ua_rows = [
        row(
            ts=100.2,
            ip=ip,
            path="/synthetic/marker-twin?synthetic_marker=alpha",
            ua=CHROME_120_UA,
        ),
        row(
            ts=100.8,
            ip=ip,
            path="/synthetic/marker-twin?synthetic_marker=beta",
            ua=CHROME_120_UA,
        ),
    ]
    different_second_rows = [
        row(
            ts=100.2,
            ip=ip,
            path="/synthetic/marker-twin?synthetic_marker=alpha",
            ua=CHROME_120_UA,
        ),
        row(
            ts=101.2,
            ip=ip,
            path="/synthetic/marker-twin?synthetic_marker=beta",
            ua=FIREFOX_122_UA,
        ),
    ]

    assert_proof(positive_rows, "same-second-ua-swap", args)
    assert_no_proof(same_ua_rows, "same-second-ua-swap", args)
    assert_no_proof(different_second_rows, "same-second-ua-swap", args)


def test_rapid_ua_switch_direct_batch() -> None:
    args = audit_args()
    ip = doc_ip(71)
    rapid_rows = [
        row(ts=0.0, ip=ip, path="/synthetic/ua-switch-a", ua=CHROME_120_UA),
        row(ts=0.5, ip=ip, path="/synthetic/ua-switch-b", ua=FIREFOX_122_UA),
    ]
    chrome_family_rows = [
        row(ts=0.0, ip=ip, path="/synthetic/ua-switch-a", ua=CHROME_WIN_134_UA),
        row(ts=0.5, ip=ip, path="/synthetic/ua-switch-b", ua=CHROME_WIN_135_UA),
    ]

    assert_proof(rapid_rows, "rapid-ua-switch", args)
    assert_no_proof(chrome_family_rows, "rapid-ua-switch", args)
