from __future__ import annotations

from pathlib import Path

from synthetic_access import (
    CHROME_120_UA,
    CHROME_MAC_135_UA,
    CHROME_WIN_134_UA,
    CHROME_WIN_135_UA,
    REFERRER,
    access_line,
    audit_args,
    doc_ip,
    row,
)

from lgu.audit import (
    DetectorConfig,
    analyze_payload_campaigns,
    build_ip_stats,
    build_runtime,
    collect_rows_and_stats,
    detect_behavioral_bots,
    detect_coordinated_target_fanout,
    detect_coordinated_ua_ips,
    summarize_ua_base,
    ua_family,
)

FANOUT_PATH = "/synthetic/fanout-content-target"
KNOWN_BOT_PATH = "/synthetic/known-bot-target"
CADENCED_PATH = "/synthetic/cadenced-content-target"
MULTIFETCH_PATH_A = "/synthetic/multifetch-content-alpha"
MULTIFETCH_PATH_B = "/synthetic/multifetch-content-beta"


def write_log(path: Path, lines: list[str]) -> None:
    path.write_text("".join(lines), encoding="utf-8")


def test_collect_rows_equivalent_across_jobs(tmp_path: Path) -> None:
    log_path = tmp_path / "access.log"
    write_log(
        log_path,
        [
            access_line(
                ip=doc_ip(1),
                ts="08/Apr/2026:02:30:52 +0000",
                path="/synthetic/posts/a",
            ),
            access_line(
                ip=doc_ip(1),
                ts="08/Apr/2026:02:30:53 +0000",
                path="/synthetic/posts/b",
            ),
            access_line(
                ip=doc_ip(2),
                ts="08/Apr/2026:02:30:54 +0000",
                path="/synthetic/posts/c",
            ),
        ],
    )

    args1 = audit_args(path_include=["/synthetic/posts/"], jobs=1)
    runtime1 = build_runtime(args1)
    result1 = collect_rows_and_stats(log_path, args1, runtime1)

    args4 = audit_args(path_include=["/synthetic/posts/"], jobs=4)
    runtime4 = build_runtime(args4)
    result4 = collect_rows_and_stats(log_path, args4, runtime4)

    assert result1.parsed_lines == result4.parsed_lines
    assert result1.matched_lines == result4.matched_lines
    assert [(row.ip, row.path) for row in result1.rows] == [
        (row.ip, row.path) for row in result4.rows
    ]


def test_collect_rows_assigns_input_indices_by_processed_input_order(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "access.log"
    write_log(
        log_path,
        [
            access_line(
                ip=doc_ip(3),
                ts="08/Apr/2026:02:30:52 +0000",
                path="/synthetic/skip",
            ),
            access_line(
                ip=doc_ip(3),
                ts="08/Apr/2026:02:30:53 +0000",
                path="/synthetic/posts/b",
            ),
            access_line(
                ip=doc_ip(4),
                ts="08/Apr/2026:02:30:54 +0000",
                path="/synthetic/posts/a",
            ),
            access_line(
                ip=doc_ip(5),
                ts="08/Apr/2026:02:30:55 +0000",
                path="/synthetic/skip",
            ),
            access_line(
                ip=doc_ip(6),
                ts="08/Apr/2026:02:30:56 +0000",
                path="/synthetic/posts/c",
            ),
        ],
    )

    args = audit_args(path_include=["/synthetic/posts/"], jobs=1)
    runtime = build_runtime(args)
    result = collect_rows_and_stats(log_path, args, runtime)

    assert [(row.path, row.input_index) for row in result.rows] == [
        ("/synthetic/posts/b", 1),
        ("/synthetic/posts/a", 2),
        ("/synthetic/posts/c", 3),
    ]


def test_summarize_ua_base_formats_legacy_ie_cleanly() -> None:
    assert (
        summarize_ua_base("Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)")
        == "IE 6 / WinXP"
    )


def test_coordinated_ua_detector_degrades_but_still_finds_ips() -> None:
    args = audit_args(
        coord_count=4,
        coord_unique_paths=4,
        coord_unique_ips=3,
        coord_max_rows=4,
    )
    rows = [
        row(
            float(i),
            doc_ip((i % 3) + 10),
            f"/synthetic/coordinated-{i}",
            "SharedUA/1.0",
        )
        for i in range(8)
    ]

    analysis = detect_coordinated_ua_ips(rows, args)

    assert analysis.degraded is True
    assert analysis.forced_proofs_by_ip


def test_payload_campaign_degrades_but_still_finds_ips() -> None:
    args = audit_args(
        detector_config=DetectorConfig(payload_marker_patterns=("render=full",)),
        payload_campaign_count=4,
        payload_campaign_unique_ips=3,
        payload_campaign_unique_paths=3,
        payload_campaign_max_rows=4,
    )
    runtime = build_runtime(args)
    rows = [
        row(
            float(i),
            doc_ip((i % 3) + 20, net=2),
            f"/synthetic/payload-target-{i}?render=full",
            CHROME_120_UA,
        )
        for i in range(8)
    ]

    analysis = analyze_payload_campaigns(rows, args, runtime)

    assert analysis.degraded is True
    assert analysis.forced_proofs_by_ip


def test_coordinated_target_fanout_groups_browser_family_versions() -> None:
    args = audit_args(target_fanout_unique_ips=5)
    rows = [
        row(
            float(ts),
            ip,
            FANOUT_PATH,
            ua,
        )
        for ts, ip, ua in [
            (
                0,
                doc_ip(30),
                CHROME_WIN_134_UA,
            ),
            (
                0,
                doc_ip(31),
                CHROME_WIN_135_UA,
            ),
            (
                0,
                doc_ip(32),
                CHROME_MAC_135_UA,
            ),
            (
                0,
                doc_ip(33),
                CHROME_WIN_134_UA,
            ),
            (
                245,
                doc_ip(34, net=2),
                CHROME_WIN_135_UA,
            ),
            (
                246,
                doc_ip(35, net=3),
                CHROME_WIN_135_UA,
            ),
        ]
    ]

    analysis = detect_coordinated_target_fanout(rows, args)

    assert set(analysis.forced_proofs_by_ip) == {
        doc_ip(30),
        doc_ip(31),
        doc_ip(32),
        doc_ip(33),
        doc_ip(34, net=2),
        doc_ip(35, net=3),
    }
    detail = analysis.forced_proofs_by_ip[doc_ip(30)][0].detail
    assert "family=Chrome|webkit" in detail
    assert f"path={FANOUT_PATH}" in detail


def test_coordinated_target_fanout_catches_five_ip_nine_minute_swarm() -> None:
    args = audit_args(target_fanout_unique_ips=5)
    rows = [
        row(
            float(ts),
            ip,
            FANOUT_PATH,
            ua,
        )
        for ts, ip, ua in [
            (
                0,
                doc_ip(40),
                CHROME_WIN_135_UA,
            ),
            (
                0,
                doc_ip(41),
                CHROME_MAC_135_UA,
            ),
            (
                0,
                doc_ip(42),
                CHROME_WIN_134_UA,
            ),
            (
                536,
                doc_ip(43, net=2),
                CHROME_WIN_135_UA,
            ),
            (
                536,
                doc_ip(44, net=3),
                CHROME_WIN_135_UA,
            ),
        ]
    ]

    analysis = detect_coordinated_target_fanout(rows, args)

    assert set(analysis.forced_proofs_by_ip) == {
        doc_ip(40),
        doc_ip(41),
        doc_ip(42),
        doc_ip(43, net=2),
        doc_ip(44, net=3),
    }


def test_configured_fetcher_is_a_direct_known_bot_ua_signature() -> None:
    args = audit_args(
        detector_config=DetectorConfig(known_bot_ua_patterns=("SyntheticFetcher/",))
    )
    runtime = build_runtime(args)
    ip = doc_ip(50)
    rows = [
        row(
            0.0,
            ip,
            KNOWN_BOT_PATH,
            "SyntheticFetcher/2.0.0",
        )
    ]

    built = build_ip_stats(rows, args, runtime)

    assert built[ip].matched_known_bot is True
    assert (
        ua_family(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
        )
        == "Chrome|webkit"
    )


def test_configured_provider_is_a_direct_known_bot_ua_signature() -> None:
    args = audit_args(
        detector_config=DetectorConfig(known_bot_ua_patterns=("SyntheticProvider",))
    )
    runtime = build_runtime(args)
    ip = doc_ip(51)
    rows = [
        row(
            0.0,
            ip,
            KNOWN_BOT_PATH,
            "Mozilla/5.0 (compatible; SyntheticProviderBot)",
        )
    ]

    built = build_ip_stats(rows, args, runtime)

    assert built[ip].matched_known_bot is True


def test_cadenced_same_second_repeat_is_forced_proof() -> None:
    args = audit_args()
    runtime = build_runtime(args)
    ip = doc_ip(52, net=2)
    rows = [
        row(
            0.0,
            ip,
            CADENCED_PATH,
            "Mozilla/5.0 Chrome/133.0 Safari/537.36",
        ),
        row(
            3660.0,
            ip,
            CADENCED_PATH,
            "Mozilla/5.0 Chrome/133.0 Safari/537.36",
        ),
        row(
            7320.0,
            ip,
            CADENCED_PATH,
            "Mozilla/5.0 Chrome/133.0 Safari/537.36",
        ),
    ]

    proofs = detect_behavioral_bots({ip: rows}, args, runtime)

    assert [proof.kind for proof in proofs[ip]] == ["cadenced-repeat"]


def test_repeated_same_second_multifetch_cluster_is_forced_proof() -> None:
    args = audit_args()
    runtime = build_runtime(args)
    ip = doc_ip(53, net=3)
    rows = [
        row(
            0.0,
            ip,
            MULTIFETCH_PATH_A,
            "Mozilla/5.0 Firefox/150.0",
            referer=REFERRER,
        ),
        row(
            0.0,
            ip,
            MULTIFETCH_PATH_B,
            "Mozilla/5.0 Firefox/150.0",
            referer=REFERRER,
        ),
        row(
            25.0,
            ip,
            MULTIFETCH_PATH_A,
            "Mozilla/5.0 Firefox/150.0",
            referer=REFERRER,
        ),
        row(
            28.0,
            ip,
            MULTIFETCH_PATH_B,
            "Mozilla/5.0 Firefox/150.0",
            referer=REFERRER,
        ),
    ]

    proofs = detect_behavioral_bots({ip: rows}, args, runtime)

    assert [proof.kind for proof in proofs[ip]] == ["tight-multifetch"]
