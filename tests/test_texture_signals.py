from __future__ import annotations

import sys

import pytest
from synthetic_access import (
    CHROME_WIN_135_UA,
    FIREFOX_150_UA,
    REFERRER,
    access_line,
    audit_args,
    doc_ip,
    row,
    watch_args,
)

from lgu import audit
from lgu.audit import (
    VISIT_CONFIRMED,
    VISIT_SPLIT,
    VISIT_UNCONFIRMED,
    build_parser,
    build_runtime,
    build_texture_context,
    classify_visits,
    collect_rows_and_stats,
    detect_coordinated_ua_ips,
    detect_redirect_ip_hops,
    extract_fast_tokens,
    has_browser_evidence,
    is_machine_path,
    is_subresource_path,
    line_matches,
    parse_log_line,
    parse_protocol,
    parse_trusted_networks,
    resolve_client_ip,
    resolve_detector_config,
    summarize_ua_base,
    texture_proofs,
    unconfirmed_ips,
)
from lgu.detector_catalog import DETECTORS, TEXTURE_SIGNAL_KINDS
from lgu.watch import (
    LiveContext,
    LiveDecision,
    format_fail2ban,
    process_row,
    row_from_line,
)
from lgu.watch import build_parser as build_watch_parser

TS = "05/Nov/2026:10:00:00 +0000"
STALE_EDGE_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
)
STALE_FIREFOX_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0"
)
STALE_SAFARI_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.1 Safari/605.1.15"
)
CURRENT_SAFARI_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/26.6.1 Mobile/15E148 Safari/604.1"
)


def default_runtime():
    args = build_parser().parse_args([])
    args.detector_config = resolve_detector_config(args)
    return args, build_runtime(args)


def kinds(proofs) -> set[str]:
    return {proof.kind for proof in proofs}


def test_parse_log_line_keeps_protocol_size_and_forwarded() -> None:
    line = access_line(
        ip=doc_ip(1),
        ts=TS,
        path="/synthetic/a",
        protocol="HTTP/2.0",
        body_bytes=4096,
        forwarded=doc_ip(2),
    )

    parsed = parse_log_line(line)

    assert parsed is not None
    assert parsed.body_bytes == 4096
    assert parsed.forwarded == doc_ip(2)
    assert parse_protocol(parsed.request) == "HTTP/2.0"


@pytest.mark.parametrize(
    "line",
    [
        f'{doc_ip(1)} - - [{TS}] "GET /synthetic/a HTTP/1.1" 200 - "-" "ua"\n',
        f'{doc_ip(1)} - - [{TS}] "GET /synthetic/a HTTP/1.1" 200 "-" "ua"\n',
    ],
)
def test_parse_log_line_tolerates_missing_body_size(line: str) -> None:
    parsed = parse_log_line(line)

    assert parsed is not None
    assert parsed.status == "200"
    assert parsed.body_bytes == -1


def test_parse_protocol_handles_requests_without_a_version() -> None:
    assert parse_protocol("GET /synthetic/a") == "-"
    assert parse_protocol("garbage") == "-"


@pytest.mark.parametrize(
    ("pattern", "path"),
    [
        (r"(?i)\.(mp3|mp4|webm|ogg)", "/synthetic/a.mp3?v=1"),
        (r"site-?_?map", "/synthetic/sitemap.rss"),
        (r"(?i)FAVICON", "/synthetic/favicon.ico"),
        (r"/(blog|posts)/", "/posts/a"),
        (r"a.c", "/synthetic/abc"),
    ],
)
def test_fast_tokens_never_reject_a_matching_line(pattern: str, path: str) -> None:
    tokens = extract_fast_tokens([pattern])
    raw = access_line(ip=doc_ip(1), ts=TS, path=path).encode()

    assert line_matches(path, [audit.re.compile(pattern)], [])
    assert not tokens or any(token in raw for token in tokens)


def test_fast_tokens_prefilter_plain_literals() -> None:
    assert extract_fast_tokens(["/synthetic/posts"]) == [b"/synthetic/posts"]
    assert extract_fast_tokens([r"\.mp3", "/feed"]) == [b".mp3", b"/feed"]


def test_fast_tokens_disable_for_whole_set_when_any_pattern_is_a_regex() -> None:
    assert extract_fast_tokens(["/synthetic/posts", "(a|b)"]) == []


def test_path_include_alternation_keeps_short_extensions(tmp_path) -> None:
    log = tmp_path / "access.log"
    log.write_text(
        access_line(ip=doc_ip(1), ts=TS, path="/synthetic/a.mp3")
        + access_line(ip=doc_ip(2), ts=TS, path="/synthetic/b.html"),
        encoding="utf-8",
    )
    args = audit_args(path_include=[r"\.(mp3|webm)"])

    analysis = collect_rows_and_stats(log, args, build_runtime(args))

    assert [item.path for item in analysis.rows] == ["/synthetic/a.mp3"]


def test_summarize_ua_names_edge_and_opera() -> None:
    assert summarize_ua_base(STALE_EDGE_UA) == "Edge 120 / Win10"
    assert summarize_ua_base(CHROME_WIN_135_UA + " OPR/120.0.0.0").startswith(
        "Opera 120"
    )


def test_resolve_client_ip_requires_a_trusted_peer() -> None:
    edge = doc_ip(1)
    client = doc_ip(2, net=2)
    networks = parse_trusted_networks([f"{doc_ip(0)}/24"])

    assert resolve_client_ip(edge, client, networks) == client
    assert resolve_client_ip(client, doc_ip(9, net=3), networks) == client
    assert resolve_client_ip(edge, client, ()) == edge


def test_resolve_client_ip_walks_past_spoofed_left_entries() -> None:
    edge = doc_ip(1)
    spoofed = doc_ip(7, net=3)
    client = doc_ip(2, net=2)
    networks = parse_trusted_networks([f"{doc_ip(0)}/24"])

    assert (
        resolve_client_ip(edge, f"{spoofed}, {client}, {doc_ip(3)}", networks) == client
    )


@pytest.mark.parametrize("forwarded", ["-", "", "10.0.0.8", "unknown"])
def test_resolve_client_ip_keeps_peer_without_a_public_hop(forwarded: str) -> None:
    networks = parse_trusted_networks([f"{doc_ip(0)}/24"])

    assert resolve_client_ip(doc_ip(1), forwarded, networks) == doc_ip(1)


def test_invalid_trusted_proxy_is_rejected() -> None:
    with pytest.raises(ValueError, match="trusted-proxy"):
        parse_trusted_networks(["not-a-network"])


def test_trusted_proxy_applies_to_batch_and_live(tmp_path) -> None:
    client = doc_ip(2, net=2)
    line = access_line(ip=doc_ip(1), ts=TS, path="/synthetic/a", forwarded=client)
    log = tmp_path / "access.log"
    log.write_text(line, encoding="utf-8")
    trusted = [f"{doc_ip(0)}/24"]

    args = audit_args(trusted_proxy=trusted)
    batch = collect_rows_and_stats(log, args, build_runtime(args))
    live_args = watch_args(trusted_proxy=trusted)
    live = row_from_line(line, LiveContext(runtime=build_runtime(live_args)))

    assert batch.rows[0].ip == client
    assert live is not None
    assert live.ip == client


@pytest.mark.parametrize(
    "path",
    [
        "/js?v=abc",
        "/style?v=abc",
        "/favicon.ico",
        "/p.mp3?v=1",
        "/apple-touch-icon.png",
    ],
)
def test_subresource_paths_cover_extensionless_site_assets(path: str) -> None:
    assert is_subresource_path(path)


@pytest.mark.parametrize("path", ["/", "/robots.txt", "/sitemap.xml", "/page.html"])
def test_documents_are_not_subresources(path: str) -> None:
    assert not is_subresource_path(path)


def test_browser_evidence_rejects_scripted_favicon_and_self_referencing_assets() -> (
    None
):
    ua = CHROME_WIN_135_UA

    assert has_browser_evidence(row(1, path="/favicon.ico", ua=ua, protocol="HTTP/2.0"))
    assert has_browser_evidence(
        row(1, path="/favicon.ico", ua=ua, protocol="HTTP/1.1", referer=REFERRER)
    )
    assert not has_browser_evidence(
        row(1, path="/favicon.ico", ua=ua, protocol="HTTP/1.1")
    )
    assert not has_browser_evidence(
        row(
            1,
            path="/style?v=1",
            ua=ua,
            protocol="HTTP/2.0",
            referer="https://referrer.example.test/style?v=1",
        )
    )
    assert not has_browser_evidence(
        row(1, path="/favicon.ico", ua="SyntheticFetcher/2.0", protocol="HTTP/2.0")
    )


@pytest.mark.parametrize(
    "path",
    [
        "/robots.txt",
        "/llms.txt",
        "/llms-full.txt",
        "/ads.txt",
        "/sitemap.xml",
        "/sitemap_index.xml",
        "/sitemap-1.xml",
        "/sitemap.xml.gz",
        "/sitemap/index.xml",
        "/sitemap/",
        "/sitemap",
        "/site-map",
        "/post-sitemap.xml",
        "/media/sitemap.xml",
        "/.rss",
        "/feed",
        "/rss.xml",
        "/atom.xml",
    ],
)
def test_default_config_treats_discovery_paths_as_machine_only(path: str) -> None:
    _, runtime = default_runtime()

    assert is_machine_path(path, runtime)


@pytest.mark.parametrize(
    "path", ["/", "/favicon.ico", "/research.html", "/posts/feedback", "/map"]
)
def test_default_config_leaves_ordinary_paths_alone(path: str) -> None:
    _, runtime = default_runtime()

    assert not is_machine_path(path, runtime)


@pytest.mark.parametrize(
    "ua",
    [
        STALE_SAFARI_UA,
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/140.0.0.0 Safari/537.36 SyntheticScanner/1.2 (+https://example.test/)",
        "Mozilla/5.0 (Android 14; Mobile; rv:123.0) Gecko/123.0 Firefox/123",
    ],
)
def test_default_config_suspect_ua_matches_observed_shapes(ua: str) -> None:
    _, runtime = default_runtime()

    assert runtime.suspect_ua_pattern.search(ua)


@pytest.mark.parametrize(
    "ua",
    [
        CURRENT_SAFARI_UA,
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) Gecko/20100101 "
        "Firefox/147.0",
        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/156.0.0.0 Mobile Safari/537.36",
    ],
)
def test_default_config_suspect_ua_spares_current_browsers(ua: str) -> None:
    _, runtime = default_runtime()

    assert runtime.suspect_ua_pattern.search(ua) is None


def test_stale_ua_with_rendered_page_stays_visible() -> None:
    args, runtime = default_runtime()
    rows = [
        row(0, path="/synthetic/a", ua=STALE_SAFARI_UA, protocol="HTTP/2.0"),
        row(
            1,
            path="/js?v=1",
            ua=STALE_SAFARI_UA,
            referer=REFERRER,
            protocol="HTTP/2.0",
        ),
    ]

    assert texture_proofs(rows, args, runtime, build_texture_context(rows)) == []


def test_exposure_probe_is_not_overruled_by_browser_evidence() -> None:
    args, runtime = default_runtime()
    rows = [
        row(0, path="/favicon.ico", ua=CHROME_WIN_135_UA, protocol="HTTP/2.0"),
        row(1, path="/.git/config", ua=CHROME_WIN_135_UA, status="404"),
    ]

    assert kinds(texture_proofs(rows, args, runtime, build_texture_context(rows))) == {
        "exposure-probe"
    }


def test_protocol_mismatch_stays_off_behind_a_downgrading_proxy() -> None:
    args, runtime = default_runtime()
    rows = [row(0, ua=CHROME_WIN_135_UA, protocol="HTTP/1.1")]

    assert texture_proofs(rows, args, runtime, build_texture_context(rows)) == []


def test_uncompressed_baseline_resists_a_bulk_majority() -> None:
    texture = build_texture_context(
        [row(0, status="200", body_bytes=1000, path="/synthetic/a")] * 2
        + [row(0, status="200", body_bytes=1800, path="/synthetic/a")] * 6
    )

    assert texture.typical_body("/synthetic/a", 5) == 1000


def test_texture_body_profile_is_bounded(monkeypatch) -> None:
    monkeypatch.setattr(audit, "BODY_PROFILE_MAX_PATHS", 2)
    rows = [
        row(0, status="200", body_bytes=10, path=f"/synthetic/{index}")
        for index in range(5)
    ]

    assert len(build_texture_context(rows).body_sizes) == 2


def test_redirect_hop_spares_a_visit_that_a_browser_rendered() -> None:
    args = audit_args()
    entry = doc_ip(1)
    visitor = doc_ip(2)
    rows = [
        row(0, ip=entry, status="301", ua=CHROME_WIN_135_UA),
        row(1, ip=visitor, ua=CHROME_WIN_135_UA),
        row(
            2,
            ip=visitor,
            path="/favicon.ico",
            ua=CHROME_WIN_135_UA,
            protocol="HTTP/2.0",
        ),
    ]

    proofs = detect_redirect_ip_hops(rows, args).forced_proofs_by_ip

    assert proofs == {}


def test_redirect_hop_requires_the_same_user_agent() -> None:
    args = audit_args()
    rows = [
        row(0, ip=doc_ip(1), status="301", ua=CHROME_WIN_135_UA),
        row(1, ip=doc_ip(2), ua=FIREFOX_150_UA),
    ]

    assert detect_redirect_ip_hops(rows, args).forced_proofs_by_ip == {}


def test_classify_visits_pairs_a_prefetched_page_with_its_visitor() -> None:
    args = audit_args()
    proxy = doc_ip(1)
    visitor = doc_ip(2)
    bystander = doc_ip(3)
    rows = [
        row(
            0,
            ip=proxy,
            path="/",
            ua=CHROME_WIN_135_UA,
            referer="https://search.example.test/",
            protocol="HTTP/2.0",
        ),
        row(
            4,
            ip=visitor,
            path="/favicon.ico",
            ua=CHROME_WIN_135_UA,
            protocol="HTTP/2.0",
            referer=REFERRER,
        ),
        row(500, ip=bystander, ua=CHROME_WIN_135_UA, protocol="HTTP/2.0"),
    ]

    visits = classify_visits(rows, args)

    assert visits[(proxy, CHROME_WIN_135_UA)] == VISIT_SPLIT
    assert visits[(visitor, CHROME_WIN_135_UA)] == VISIT_CONFIRMED
    assert visits[(bystander, CHROME_WIN_135_UA)] == VISIT_UNCONFIRMED
    assert unconfirmed_ips(visits) == {bystander}


def test_classify_visits_never_pairs_evidence_from_before_the_page() -> None:
    args = audit_args()
    rows = [
        row(
            0,
            ip=doc_ip(2),
            path="/favicon.ico",
            ua=CHROME_WIN_135_UA,
            protocol="HTTP/2.0",
        ),
        row(4, ip=doc_ip(1), ua=CHROME_WIN_135_UA, protocol="HTTP/2.0"),
    ]

    assert classify_visits(rows, args)[(doc_ip(1), CHROME_WIN_135_UA)] == (
        VISIT_UNCONFIRMED
    )


def test_unconfirmed_ips_keeps_an_address_with_any_confirmed_client() -> None:
    ip = doc_ip(1)

    assert (
        unconfirmed_ips({(ip, "a"): VISIT_CONFIRMED, (ip, "b"): VISIT_UNCONFIRMED})
        == set()
    )


def test_texture_signals_never_ban() -> None:
    specs = {spec.kind: spec for spec in DETECTORS}

    assert set(specs) >= TEXTURE_SIGNAL_KINDS
    assert not any(specs[kind].strong_proof for kind in TEXTURE_SIGNAL_KINDS)


def test_walker_row_reaches_suspect_but_not_ban_live() -> None:
    args = build_watch_parser().parse_args(["--emit-suspects"])
    args.detector_config = resolve_detector_config(args)
    context = LiveContext(runtime=build_runtime(args))

    decision = process_row(
        row(
            1000,
            ip=doc_ip(9),
            path="/robots.txt",
            ua=STALE_EDGE_UA,
            referer=REFERRER,
            status="404",
            protocol="HTTP/1.1",
        ),
        context,
        args,
    )

    assert decision is not None
    assert decision.action == "suspect"
    assert "machine-path" in decision.reasons


def test_live_redirect_windows_are_collected() -> None:
    args = watch_args(emit_suspects=True)
    context = LiveContext(runtime=build_runtime(args))

    process_row(row(1000, ip=doc_ip(1), status="301"), context, args)
    assert context.redirect_windows
    process_row(row(2000, ip=doc_ip(2), path="/synthetic/other"), context, args)

    assert all(
        window[0].ts >= 2000 - args.redirect_hop_window_seconds
        for window in context.redirect_windows.values()
    )


@pytest.mark.parametrize(
    ("action", "expected"), [("suspect", "suspect"), ("ban", "drop")]
)
def test_fail2ban_output_only_labels_real_bans(action: str, expected: str) -> None:
    decision = LiveDecision(
        action=action,
        ip=doc_ip(1),
        ts=1000.0,
        raw_ts=TS,
        score=1.0,
        reasons=("machine-path",),
        proof_detail="-",
        path="/robots.txt",
        ua=CHROME_WIN_135_UA,
        referer="-",
    )

    assert f"action={expected} " in format_fail2ban(decision, "drop")


def write_walker_log(tmp_path):
    def stamp(hour: int) -> str:
        return f"05/Nov/2026:{hour:02d}:00:00 +0000"

    lines = [
        access_line(
            ip=doc_ip(10 + index),
            ts=stamp(index),
            path="/synthetic/page",
            ua=CURRENT_SAFARI_UA,
            protocol="HTTP/2.0",
            referer="https://referrer.example.test/articles/synthetic",
        )
        + access_line(
            ip=doc_ip(10 + index),
            ts=stamp(index),
            path="/favicon.ico",
            ua=CURRENT_SAFARI_UA,
            protocol="HTTP/2.0",
            status="404",
        )
        for index in range(12)
    ]
    lines.append(
        access_line(
            ip=doc_ip(70),
            ts=stamp(13),
            path="/sitemap.xml",
            ua=STALE_EDGE_UA,
            referer=REFERRER,
            status="404",
        )
    )
    lines.append(
        access_line(
            ip=doc_ip(71),
            ts=stamp(15),
            path="/synthetic/lone",
            ua=CURRENT_SAFARI_UA,
            protocol="HTTP/2.0",
        )
    )
    log = tmp_path / "access.log"
    log.write_text("".join(lines), encoding="utf-8")
    return log


def run_main(monkeypatch, capsys, log, *flags: str) -> str:
    monkeypatch.setattr(
        sys,
        "argv",
        ["log-audit", str(log), "--no-reverse-dns", "--no-whois", *flags],
    )

    assert audit.main() == 0
    return capsys.readouterr().out


def test_recent_view_hides_walker_and_labels_visits(
    tmp_path, monkeypatch, capsys
) -> None:
    output = run_main(monkeypatch, capsys, write_walker_log(tmp_path))

    assert "/sitemap.xml" not in output
    assert "visit=confirmed" in output
    assert "visit=unconfirmed" in output


def test_bots_only_view_explains_why_a_client_was_hidden(
    tmp_path, monkeypatch, capsys
) -> None:
    output = run_main(monkeypatch, capsys, write_walker_log(tmp_path), "--bots-only")

    assert "Edge 120 / Win10" in output
    assert "why machine-path" in output


def test_confirmed_only_drops_unconfirmed_clients(
    tmp_path, monkeypatch, capsys
) -> None:
    output = run_main(
        monkeypatch, capsys, write_walker_log(tmp_path), "--confirmed-only"
    )

    assert "/synthetic/lone" not in output
    assert "/synthetic/page" in output


def test_summary_reports_visitor_breakdown(tmp_path, monkeypatch, capsys) -> None:
    output = run_main(monkeypatch, capsys, write_walker_log(tmp_path), "--summary")

    assert "visitor_breakdown:" in output
    assert "confirmed_visitors=12\trequests=24" in output
    assert "unconfirmed_visitors=1\trequests=1" in output
    assert "machine-path=1" in output


MALFORMED_URLS = (
    "http://[192.0.2.1]/",
    "http://[broken",
    "//[192.0.2.1]/synthetic",
)


@pytest.mark.parametrize("referer", MALFORMED_URLS)
def test_malformed_referer_cannot_stop_batch_analysis(
    tmp_path, monkeypatch, capsys, referer: str
) -> None:
    log = tmp_path / "access.log"
    log.write_text(
        "".join(
            access_line(
                ip=doc_ip(5),
                ts=f"05/Nov/2026:10:00:{second:02d} +0000",
                path=f"/synthetic/page-{second}?marker=1",
                referer=referer,
            )
            for second in range(4)
        ),
        encoding="utf-8",
    )

    assert "parsed_lines=4" in run_main(monkeypatch, capsys, log, "--summary")


@pytest.mark.parametrize("referer", MALFORMED_URLS)
def test_malformed_referer_cannot_stop_live_analysis(referer: str) -> None:
    args = watch_args()
    context = LiveContext(runtime=build_runtime(args))

    for offset in range(4):
        process_row(
            row(1000 + offset, path=f"/synthetic/page-{offset}", referer=referer),
            context,
            args,
        )

    assert len(context.ip_states[doc_ip(1)].rows) == 4


def test_malformed_request_path_cannot_stop_payload_analysis() -> None:
    assert (
        audit.has_payload_marker_mutation(
            "//[192.0.2.1]/synthetic?marker=1", ("marker=",)
        )
        is False
    )


def test_compact_referer_still_shows_malformed_values() -> None:
    assert "192.0.2.1" in audit.compact_referer("http://[192.0.2.1]/", 48)


def test_show_path_keeps_browser_evidence_for_filtered_output(
    tmp_path, monkeypatch, capsys
) -> None:
    output = run_main(
        monkeypatch,
        capsys,
        write_walker_log(tmp_path),
        "--show-path",
        "^/synthetic/page",
    )

    assert "visit=confirmed" in output
    assert "/favicon.ico" not in output
    assert "/synthetic/lone" not in output


def test_show_path_differs_from_prefiltering_the_input(
    tmp_path, monkeypatch, capsys
) -> None:
    log = tmp_path / "access.log"
    log.write_text(
        access_line(
            ip=doc_ip(5),
            ts=TS,
            path="/synthetic/page",
            ua=STALE_SAFARI_UA,
            protocol="HTTP/2.0",
        )
        + access_line(
            ip=doc_ip(5),
            ts=TS,
            path="/favicon.ico",
            ua=STALE_SAFARI_UA,
            protocol="HTTP/2.0",
            referer=REFERRER,
        ),
        encoding="utf-8",
    )

    scoped = run_main(monkeypatch, capsys, log, "--show-path", "^/synthetic/page")
    prefiltered = run_main(
        monkeypatch, capsys, log, "--path-include", "^/synthetic/page"
    )

    assert "/synthetic/page" in scoped
    assert "visit=confirmed" in scoped
    assert "no matching rows" in prefiltered


def test_show_path_applies_recent_limit_to_shown_rows(
    tmp_path, monkeypatch, capsys
) -> None:
    output = run_main(
        monkeypatch,
        capsys,
        write_walker_log(tmp_path),
        "--show-path",
        "^/synthetic/lone",
        "--recent-limit",
        "1",
    )

    assert "/synthetic/lone" in output


def test_show_path_filters_raw_lines_and_bots_only(
    tmp_path, monkeypatch, capsys
) -> None:
    log = write_walker_log(tmp_path)

    raw = run_main(
        monkeypatch,
        capsys,
        log,
        "--raw-filtered-lines",
        "--show-path",
        "^/synthetic/page",
    )
    hidden = run_main(
        monkeypatch, capsys, log, "--bots-only", "--show-path", "^/sitemap"
    )

    assert raw.count("/synthetic/page") == 12
    assert "/favicon.ico" not in raw
    assert "/sitemap.xml" in hidden
    assert "why machine-path" in hidden


def test_show_path_scopes_summary_to_matching_clients(
    tmp_path, monkeypatch, capsys
) -> None:
    output = run_main(
        monkeypatch,
        capsys,
        write_walker_log(tmp_path),
        "--summary",
        "--show-path",
        "^/synthetic/lone",
    )

    assert "parsed_lines=26" in output
    assert "clean_requests=1" in output
    assert "unconfirmed_visitors=1\trequests=1" in output
    assert "confirmed_visitors=0" in output


def test_prefiltered_input_turns_visit_labels_off_and_says_why(
    tmp_path, monkeypatch, capsys
) -> None:
    log = tmp_path / "access.log"
    log.write_text(
        access_line(
            ip=doc_ip(5),
            ts=TS,
            path="/synthetic/page",
            ua=CURRENT_SAFARI_UA,
            protocol="HTTP/2.0",
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys, "argv", ["log-audit", str(log), "--no-reverse-dns", "--no-whois"]
    )

    assert audit.main() == 0
    captured = capsys.readouterr()

    assert "visit=" not in captured.out
    assert "--show-path" in captured.err


def test_invalid_show_path_is_a_usage_error(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["log-audit", "--show-path", "(unclosed"])

    with pytest.raises(SystemExit) as raised:
        audit.main()

    assert raised.value.code == 2
    assert "unterminated" in capsys.readouterr().err


def test_show_path_is_batch_only() -> None:
    assert "Only report requests" not in build_watch_parser().format_help()


def shared_page_rows(ua: str = CHROME_WIN_135_UA) -> list:
    return [
        row(
            1000 + index,
            ip=doc_ip(100 + index),
            path=f"/synthetic/asset-{index}.js",
            ua=ua,
            referer=REFERRER,
            protocol="HTTP/2.0",
        )
        for index in range(30)
    ]


def test_coordinated_ua_ignores_assets_of_identical_browsers() -> None:
    args = audit_args(
        coord_count=5, coord_unique_paths=5, coord_unique_ips=5, coord_max_ip_share=1.0
    )

    assert detect_coordinated_ua_ips(shared_page_rows(), args).forced_proofs_by_ip == {}


def test_coordinated_ua_still_catches_document_sweeps() -> None:
    args = audit_args(
        coord_count=5, coord_unique_paths=5, coord_unique_ips=5, coord_max_ip_share=1.0
    )
    rows = [
        row(1000 + index, ip=doc_ip(100 + index), path=f"/synthetic/page-{index}")
        for index in range(30)
    ]

    assert detect_coordinated_ua_ips(rows, args).forced_proofs_by_ip


def test_live_coordinated_ua_ignores_assets_of_identical_browsers() -> None:
    args = watch_args(
        coord_count=5, coord_unique_paths=5, coord_unique_ips=5, coord_max_ip_share=1.0
    )
    context = LiveContext(runtime=build_runtime(args))

    decisions = [process_row(item, context, args) for item in shared_page_rows()]

    assert decisions == [None] * len(decisions)
    assert context.coordinated_windows == {}


def test_label_note_fires_when_only_hidden_clients_have_evidence(
    tmp_path, monkeypatch, capsys
) -> None:
    log = tmp_path / "access.log"
    log.write_text(
        access_line(
            ip=doc_ip(5),
            ts=TS,
            path="/synthetic/page",
            ua=CURRENT_SAFARI_UA,
            protocol="HTTP/2.0",
        )
        + access_line(
            ip=doc_ip(6),
            ts=TS,
            path="/synthetic/app.css",
            ua=CHROME_WIN_135_UA,
            protocol="HTTP/2.0",
        )
        + access_line(
            ip=doc_ip(6),
            ts="05/Nov/2026:10:00:05 +0000",
            path="/.git/config",
            ua=CHROME_WIN_135_UA,
            status="404",
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys, "argv", ["log-audit", str(log), "--no-reverse-dns", "--no-whois"]
    )

    assert audit.main() == 0
    captured = capsys.readouterr()

    assert "/synthetic/page" in captured.out
    assert "visit=" not in captured.out
    assert "--show-path" in captured.err


def asset_row(ts: float, ip: str, ua: str = CHROME_WIN_135_UA, referer=REFERRER):
    return row(
        ts, ip=ip, path="/favicon.ico", ua=ua, referer=referer, protocol="HTTP/2.0"
    )


def page_row(ts: float, ip: str, ua: str = CHROME_WIN_135_UA, status: str = "200"):
    return row(ts, ip=ip, path="/", ua=ua, status=status, protocol="HTTP/2.0")


def test_rotating_privacy_user_is_one_verified_visit() -> None:
    args = audit_args()
    redirected, landed, rendered = doc_ip(1), doc_ip(2), doc_ip(3)
    rows = [
        page_row(0, redirected, status="301"),
        page_row(2, landed),
        asset_row(4, rendered),
    ]

    visits = classify_visits(rows, args)

    assert visits[(landed, CHROME_WIN_135_UA)] == VISIT_SPLIT
    assert detect_redirect_ip_hops(rows, args, visits).forced_proofs_by_ip == {}


def test_proxy_scrapers_that_never_render_still_hop() -> None:
    args = audit_args()
    rows = [page_row(0, doc_ip(1), status="301"), page_row(2, doc_ip(2))]

    assert set(detect_redirect_ip_hops(rows, args).forced_proofs_by_ip) == {
        doc_ip(1),
        doc_ip(2),
    }


def test_one_asset_cannot_vouch_for_a_scraper_pool() -> None:
    args = audit_args()
    pool = [doc_ip(10 + index) for index in range(5)]
    rows = [page_row(index, ip) for index, ip in enumerate(pool)]
    rows.append(asset_row(6, doc_ip(1)))

    visits = classify_visits(rows, args)

    assert [visits[(ip, CHROME_WIN_135_UA)] for ip in pool].count(VISIT_SPLIT) == 1


def test_hidden_client_cannot_vouch_for_a_page() -> None:
    args = audit_args()
    rows = [page_row(0, doc_ip(1)), asset_row(2, doc_ip(2))]

    visits = classify_visits(rows, args, hidden_ips={doc_ip(2)})

    assert visits[(doc_ip(1), CHROME_WIN_135_UA)] == VISIT_UNCONFIRMED


def test_asset_must_name_the_page_as_its_referer() -> None:
    args = audit_args()
    rows = [
        page_row(0, doc_ip(1)),
        asset_row(2, doc_ip(2), referer="https://referrer.example.test/other"),
    ]

    assert classify_visits(rows, args)[(doc_ip(1), CHROME_WIN_135_UA)] == (
        VISIT_UNCONFIRMED
    )


def test_visitor_with_its_own_page_does_not_vouch_for_a_stranger() -> None:
    args = audit_args()
    rows = [
        page_row(0, doc_ip(1)),
        page_row(1, doc_ip(2)),
        asset_row(2, doc_ip(2)),
    ]

    assert classify_visits(rows, args)[(doc_ip(1), CHROME_WIN_135_UA)] == (
        VISIT_UNCONFIRMED
    )


def versioned_chrome(major: int) -> str:
    return (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        f"(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
    )


def rendered_by(major: int, count: int, start: int = 20) -> list:
    return [
        asset_row(index, doc_ip(start + index), ua=versioned_chrome(major))
        for index in range(count)
    ]


def test_staleness_follows_versions_seen_rendering() -> None:
    args = audit_args()
    runtime = build_runtime(args)
    old = versioned_chrome(120)
    target = [row(100, ip=doc_ip(9), ua=old, protocol="HTTP/2.0")]

    fresh = build_texture_context(rendered_by(125, 3) + target)
    moved_on = build_texture_context(rendered_by(138, 3) + target)

    assert "stale-browser" not in kinds(texture_proofs(target, args, runtime, fresh))
    assert "stale-browser" in kinds(texture_proofs(target, args, runtime, moved_on))


def test_spoofed_future_version_cannot_age_out_real_browsers() -> None:
    args = audit_args()
    runtime = build_runtime(args)
    target = [row(100, ip=doc_ip(9), ua=versioned_chrome(150), protocol="HTTP/2.0")]
    texture = build_texture_context(
        rendered_by(150, 3) + rendered_by(999, 2, start=40) + target
    )

    assert "stale-browser" not in kinds(texture_proofs(target, args, runtime, texture))


def test_stale_browser_with_rendered_page_stays_visible() -> None:
    args = audit_args()
    runtime = build_runtime(args)
    old = versioned_chrome(100)
    rows = [row(0, ua=old, protocol="HTTP/2.0"), asset_row(1, doc_ip(1), ua=old)]
    texture = build_texture_context(rendered_by(150, 3) + rows)

    assert texture_proofs(rows, args, runtime, texture) == []


def test_browser_version_identifies_families() -> None:
    assert audit.browser_version(versioned_chrome(120)) == ("chromium", 120)
    assert audit.browser_version(STALE_FIREFOX_UA) == ("firefox", 126)
    assert audit.browser_version(CURRENT_SAFARI_UA) is None
    assert audit.browser_version("SyntheticFetcher/2.0 Chrome/1") is None


def test_browser_version_clients_are_bounded(monkeypatch) -> None:
    monkeypatch.setattr(audit, "BROWSER_VERSION_CLIENT_CAP", 2)

    texture = build_texture_context(rendered_by(150, 5))

    assert len(texture.browser_clients[("chromium", 150)]) == 2


@pytest.mark.parametrize(
    "path", ["/research.html", "/a/page.htm", "/index.php", "/PAGE.HTML?x=1"]
)
def test_documents_are_pages_not_assets(path: str) -> None:
    assert audit.target_profile(path) == "document"
    assert audit.is_content_page_path(path)
    assert not audit.is_page_dependency_path(path)


def test_low_context_fanout_now_covers_html_pages() -> None:
    args = audit_args()
    rows = [
        row(1000 + index, ip=doc_ip(30 + index), path="/synthetic/a.html")
        for index in range(args.low_context_fanout_count)
    ]

    assert audit.detect_low_context_fanout(rows, args).forced_proofs_by_ip


NO_PROTOCOL_GATE = ("--protocol-min-modern-rows", "100000")


def test_sole_signal_counts_only_single_reason_clients(
    tmp_path, monkeypatch, capsys
) -> None:
    output = run_main(
        monkeypatch, capsys, write_walker_log(tmp_path), "--summary", *NO_PROTOCOL_GATE
    )

    assert "sole_signal_ips=machine-path=1" in output


def test_sole_signal_shows_exactly_those_clients(tmp_path, monkeypatch, capsys) -> None:
    output = run_main(
        monkeypatch,
        capsys,
        write_walker_log(tmp_path),
        "--sole-signal",
        "machine-path",
        *NO_PROTOCOL_GATE,
    )

    assert "/sitemap.xml" in output
    assert "/synthetic/page" not in output


def test_sole_signal_skips_clients_with_other_reasons() -> None:
    args = audit_args()
    stats = {
        doc_ip(1): audit.IPStats(ip=doc_ip(1)),
        doc_ip(2): audit.IPStats(ip=doc_ip(2)),
    }
    proofs = {
        doc_ip(1): [audit.ForcedProof(kind="machine-path", detail="-")],
        doc_ip(2): [
            audit.ForcedProof(kind="machine-path", detail="-"),
            audit.ForcedProof(kind="burst", detail="-"),
        ],
    }

    assert audit.sole_signal_ips(stats, proofs, args) == {doc_ip(1): "machine-path"}


@pytest.mark.parametrize("flag", ["--path-include", "--path-exclude"])
def test_invalid_path_filter_is_a_usage_error(monkeypatch, capsys, flag: str) -> None:
    monkeypatch.setattr(sys, "argv", ["log-audit", flag, "(unclosed"])

    with pytest.raises(SystemExit) as raised:
        audit.main()

    assert raised.value.code == 2
    assert "unterminated" in capsys.readouterr().err
