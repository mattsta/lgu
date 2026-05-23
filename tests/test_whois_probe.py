"""Offline validation of the whois pacing probe and the resolver it audits.

A scripted RDAP registry (`ScriptedRegistry`) stands in for the network at the
`HttpExchange` layer, so these tests exercise the same `classify_exchange` path
production uses. One test runs a real local HTTP server to pin how
`fetch_exchange` captures status, headers, and bodies off the wire.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address, ip_network
from pathlib import Path

import pytest
from synthetic_access import doc_ip

from lgu.whois_lookup import (
    DEFER_BUDGET,
    DEFER_REFUSED,
    FETCH_ERROR,
    FETCH_FORBIDDEN,
    FETCH_NOT_FOUND,
    FETCH_OK,
    FETCH_REFUSED,
    HttpExchange,
    RdapBootstrap,
    RegistryState,
    WhoisRecord,
    classify_exchange,
    fetch_exchange,
    read_cache_file,
    write_cache_file,
)
from lgu.whois_probe import (
    EvidenceLog,
    RecordingFetch,
    exchange_record,
    explain_cache,
    format_rdap_error,
    inspect_entities,
    main,
    render_ask,
    render_entities,
    render_verify,
    run_ask,
    run_burst,
    run_replay,
    run_verify_cache,
    sample_addresses,
    summarize,
    verify_targets,
)

ARIN = "https://rdap.arin.net/registry/"
RIPE = "https://rdap.db.ripe.net/"
BOOTSTRAP = RdapBootstrap(
    [(ip_network("192.0.2.0/24"), ARIN), (ip_network("198.51.100.0/24"), RIPE)]
)


def always(_ip: str) -> bool:
    return True


class Clock:
    def __init__(self, now: float = 2_000_000.0) -> None:
        self.now = now

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class ScriptedRegistry:
    """RDAP server double answering at the HttpExchange layer.

    `limit=(window, n)` refuses with 429 once n requests landed in the window,
    optionally sending `retry_after`. Each /ip/ answer is a /28 around the IP.
    """

    def __init__(
        self,
        clock: Clock,
        *,
        limit: tuple[float, int] | None = None,
        retry_after: str | None = None,
        extra_headers: tuple[tuple[str, str], ...] = (),
        latency: float = 0.05,
        redirect_to: str | None = None,
    ) -> None:
        self.clock = clock
        self.limit = limit
        self.retry_after = retry_after
        self.extra_headers = extra_headers
        self.latency = latency
        self.redirect_to = redirect_to
        self.hits: list[float] = []

    def __call__(self, url: str, timeout: float) -> HttpExchange:
        started = self.clock.now
        self.clock.now += self.latency
        if "/ip/" not in url:  # IANA bootstrap document
            services = (
                [[["192.0.2.0/24"], [ARIN]], [["198.51.100.0/24"], [RIPE]]]
                if url.endswith("ipv4.json")
                else [[["2001:db8::/32"], [ARIN]]]
            )
            return HttpExchange(
                url=url,
                started=started,
                elapsed=self.latency,
                status=200,
                final_url=url,
                body=json.dumps({"services": services}).encode(),
            )
        ip = url.rsplit("/ip/", 1)[1]
        final = self.redirect_to + "ip/" + ip if self.redirect_to else url
        if self.limit is not None:
            window, allowed = self.limit
            recent = [t for t in self.hits if t > self.clock.now - window]
            if len(recent) >= allowed:
                headers = self.extra_headers
                if self.retry_after is not None:
                    headers += (("Retry-After", self.retry_after),)
                return HttpExchange(
                    url=url,
                    started=started,
                    elapsed=self.latency,
                    status=429,
                    final_url=final,
                    headers=headers,
                    body=b'{"title":"Too Many Requests"}',
                    error="HTTP 429 Too Many Requests",
                )
        self.hits.append(self.clock.now)
        base = int(ip_address(ip)) & ~0xF
        payload = {
            "objectClassName": "ip network",
            "startAddress": str(ip_address(base)),
            "endAddress": str(ip_address(base + 15)),
            "name": "SYNTHETIC-NET",
            "entities": [],
        }
        return HttpExchange(
            url=url,
            started=started,
            elapsed=self.latency,
            status=200,
            final_url=final,
            headers=(("Content-Type", "application/rdap+json"), *self.extra_headers),
            body=json.dumps(payload).encode(),
        )


def recording(exchange_fn, tmp_path: Path | None = None) -> RecordingFetch:
    log = EvidenceLog(tmp_path / "evidence.jsonl" if tmp_path else None)
    return RecordingFetch(exchange_fn, log, "test-run", "replay")


def arin_ips(count: int) -> list[str]:
    # One per /28 so every lookup is a distinct network.
    return [doc_ip(16 * i + 1) for i in range(count)]


# --- classification parity -------------------------------------------------


def _exchange(status: int | None, body: bytes = b"{}", **kw) -> HttpExchange:
    return HttpExchange(
        url="https://rdap.arin.net/registry/ip/192.0.2.1",
        started=0.0,
        elapsed=0.0,
        status=status,
        body=body,
        **kw,
    )


@pytest.mark.parametrize(
    ("exchange", "status", "retry_after"),
    [
        (_exchange(200, b'{"a": 1}'), FETCH_OK, None),
        (_exchange(200, b"[1]"), FETCH_ERROR, None),
        (_exchange(200, b"not json"), FETCH_ERROR, None),
        (_exchange(200, b"{}", truncated=True), FETCH_ERROR, None),
        (_exchange(404), FETCH_NOT_FOUND, None),
        (_exchange(429), FETCH_REFUSED, None),
        (_exchange(429, headers=(("retry-after", "7"),)), FETCH_REFUSED, 7.0),
        (_exchange(403, headers=(("Retry-After", "30"),)), FETCH_REFUSED, 30.0),
        (_exchange(403), FETCH_FORBIDDEN, None),
        (_exchange(503, headers=(("Retry-After", "9"),)), FETCH_REFUSED, 9.0),
        (_exchange(503), FETCH_ERROR, None),
        (_exchange(500), FETCH_ERROR, None),
        (_exchange(301), FETCH_ERROR, None),
        (_exchange(None, error="TimeoutError: timed out"), FETCH_ERROR, None),
    ],
)
def test_classify_exchange(exchange, status, retry_after) -> None:
    result = classify_exchange(exchange)
    assert result.status == status
    assert result.retry_after == retry_after


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path.endswith("/limited"):
            body = b'{"errorCode":429}'
            self.send_response(429)
            self.send_header("Retry-After", "12")
            self.send_header("X-RateLimit-Remaining", "0")
        else:
            body = b'{"startAddress":"192.0.2.0","endAddress":"192.0.2.255"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/rdap+json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def local_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def test_fetch_exchange_captures_wire_evidence(local_server: str) -> None:
    ok = fetch_exchange(local_server + "/ip/192.0.2.1", 2.0)
    assert ok.status == 200 and ok.header("content-type") == "application/rdap+json"
    assert classify_exchange(ok).status == FETCH_OK

    limited = fetch_exchange(local_server + "/limited", 2.0)
    assert limited.status == 429
    assert limited.header("x-ratelimit-remaining") == "0"
    assert limited.body == b'{"errorCode":429}'
    result = classify_exchange(limited)
    assert result.status == FETCH_REFUSED and result.retry_after == 12.0

    fetch = recording(fetch_exchange)
    fetch(local_server + "/limited", 2.0)
    record = fetch.records[0]
    assert record["http_status"] == 429
    assert record["rate_headers"] == {
        "retry-after": "12",
        "x-ratelimit-remaining": "0",
    }
    assert record["body"] == '{"errorCode":429}'
    assert record["rdap_error"] == {"errorCode": 429}


# --- the resolver must not invent limits -------------------------------------


def test_unlimited_registry_resolves_everything_within_budget(tmp_path: Path) -> None:
    clock = Clock()
    registry = ScriptedRegistry(clock)
    fetch = recording(registry, tmp_path)

    report = run_replay(
        ips=arin_ips(15),
        fetch=fetch,
        cache_path=None,
        bootstrap_path=None,
        time_fn=clock.time,
        sleep_fn=clock.sleep,
        queryable_fn=always,
    )

    assert report.lookups_made == 15
    assert report.resolved == 15
    assert report.deferred_by_kind == {}
    assert report.findings == []


def test_budget_deferrals_are_policy_not_findings(tmp_path: Path) -> None:
    clock = Clock()
    fetch = recording(ScriptedRegistry(clock))

    report = run_replay(
        ips=arin_ips(12),
        fetch=fetch,
        cache_path=None,
        bootstrap_path=None,
        max_lookups=10,
        time_fn=clock.time,
        sleep_fn=clock.sleep,
        queryable_fn=always,
    )

    assert report.lookups_made == 10
    assert dict(report.deferred_by_kind["(this client)"]) == {DEFER_BUDGET: 2}
    assert report.unjustified == []


def test_spacing_above_inline_cap_is_slept_not_deferred() -> None:
    # Regression: self-imposed spacing above the inline-wait cap used to defer
    # every lookup after the first, per registry, per run.
    clock = Clock()
    fetch = recording(ScriptedRegistry(clock))

    report = run_replay(
        ips=arin_ips(6),
        fetch=fetch,
        cache_path=None,
        bootstrap_path=None,
        interval=90.0,
        time_fn=clock.time,
        sleep_fn=clock.sleep,
        queryable_fn=always,
    )

    assert report.lookups_made == 6 and report.resolved == 6
    assert report.deferred_by_kind == {}
    assert report.findings == []


def test_burst_limiter_is_absorbed_by_short_backoff() -> None:
    # A registry allowing 1 request per second refuses every other request at
    # 0.5s spacing. Regression: one bare 429 used to pause the registry 300s
    # and defer the rest of the run. Now each refusal costs a 2s pause.
    clock = Clock()
    fetch = recording(ScriptedRegistry(clock, limit=(1.0, 1)))

    report = run_replay(
        ips=arin_ips(8),
        fetch=fetch,
        cache_path=None,
        bootstrap_path=None,
        time_fn=clock.time,
        sleep_fn=clock.sleep,
        queryable_fn=always,
    )

    assert report.resolved == 8
    assert report.deferred_by_kind == {}
    refusals = report.evidence["ARIN"].refusals
    assert refusals and all(r["http_status"] == 429 for r in refusals)
    assert all(r["retry_after"] is None for r in refusals)
    assert refusals[0]["requests_prev_60s"] == 1
    # start-to-start: 0.5s spacing after completion plus 0.05s latency
    assert refusals[0]["gap_since_previous_s"] == pytest.approx(0.55)
    assert report.unjustified == []


def test_persistent_throttle_defers_with_backing_evidence() -> None:
    clock = Clock()
    fetch = recording(ScriptedRegistry(clock, limit=(3600.0, 2)))

    report = run_replay(
        ips=arin_ips(5),
        fetch=fetch,
        cache_path=None,
        bootstrap_path=None,
        time_fn=clock.time,
        sleep_fn=clock.sleep,
        queryable_fn=always,
    )

    assert report.resolved == 2
    kinds = report.deferred_by_kind["ARIN"]
    assert kinds[DEFER_REFUSED] >= 1 and sum(kinds.values()) == 3
    assert any(f.severity == "refused" for f in report.findings)
    assert report.unjustified == []
    assert "returned HTTP 429 (no Retry-After" in (report.status_note or "")


def test_redirected_refusals_are_backed_by_the_answering_registry() -> None:
    clock = Clock()
    registry = ScriptedRegistry(clock, limit=(3600.0, 1), redirect_to=RIPE)
    fetch = recording(registry)

    report = run_replay(
        ips=arin_ips(3),
        fetch=fetch,
        cache_path=None,
        bootstrap_path=None,
        time_fn=clock.time,
        sleep_fn=clock.sleep,
        queryable_fn=always,
    )

    assert report.resolved == 1
    assert set(report.deferred_by_kind) == {"RIPE NCC"}
    assert report.unjustified == []
    assert any(
        f.severity == "info" and "answered by RIPE NCC" in f.message
        for f in report.findings
    )


def test_backoff_inherited_from_cache_is_reported_with_its_cause(
    tmp_path: Path,
) -> None:
    clock = Clock()
    cache = tmp_path / "whois-cache.json"
    write_cache_file(
        cache,
        {},
        {},
        {
            "ARIN": RegistryState(
                "ARIN",
                blocked_until=clock.now + 240.0,
                refusal_streak=1,
                streak_ts=clock.now,
                last_refusal={
                    "ts": clock.now,
                    "http_status": 429,
                    "retry_after": 240.0,
                    "backoff": 240.0,
                    "streak": 1,
                    "url": ARIN + "ip/" + doc_ip(1),
                },
            )
        },
        now=clock.now,
    )
    before = cache.read_bytes()
    fetch = recording(ScriptedRegistry(clock))

    report = run_replay(
        ips=arin_ips(3),
        fetch=fetch,
        cache_path=cache,
        bootstrap_path=None,
        time_fn=clock.time,
        sleep_fn=clock.sleep,
        queryable_fn=always,
    )

    assert report.lookups_made == 0
    assert report.inherited_backoff == {"ARIN": pytest.approx(240.0)}
    (finding,) = report.findings
    assert finding.severity == "inherited"
    assert "returned HTTP 429 (Retry-After 240s)" in finding.message
    assert cache.read_bytes() == before  # replay never writes the source cache


# --- burst --------------------------------------------------------------------


def test_sample_addresses_are_distinct_and_routed_to_the_registry() -> None:
    picked = sample_addresses(BOOTSTRAP, "ARIN", 20, always)
    assert len(picked) == len(set(picked)) == 20
    assert all(ip_address(ip) in ip_network("192.0.2.0/24") for ip in picked)
    assert sample_addresses(BOOTSTRAP, "LACNIC", 5, always) == []


def test_burst_finds_the_first_refusal() -> None:
    clock = Clock()
    registry = ScriptedRegistry(
        clock,
        limit=(60.0, 5),
        retry_after="20",
        extra_headers=(("X-RateLimit-Limit", "5"),),
    )
    fetch = recording(registry)

    report = run_burst(
        registry="ARIN",
        bootstrap=BOOTSTRAP,
        fetch=fetch,
        count=20,
        interval=0.5,
        time_fn=clock.time,
        sleep_fn=clock.sleep,
        queryable_fn=always,
    )

    assert report.sent == 6
    assert report.first_refusal_index == 6
    assert report.evidence.classified == {FETCH_OK: 5, FETCH_REFUSED: 1}
    assert report.evidence.rate_headers == {
        "x-ratelimit-limit": {"5"},
        "retry-after": {"20"},
    }
    assert report.per_minute == pytest.approx(5 * 60.0 / report.duration_s)


def test_burst_with_no_limit_runs_to_completion() -> None:
    clock = Clock()
    fetch = recording(ScriptedRegistry(clock))

    report = run_burst(
        registry="ARIN",
        bootstrap=BOOTSTRAP,
        fetch=fetch,
        count=10,
        interval=0.5,
        time_fn=clock.time,
        sleep_fn=clock.sleep,
        queryable_fn=always,
    )

    assert report.sent == 10 and report.first_refusal_index is None
    assert report.evidence.rate_headers == {}


# --- explain / summary ----------------------------------------------------------


def test_explain_reports_why_the_next_query_waits(tmp_path: Path) -> None:
    now = 3_000_000.0
    cache = tmp_path / "whois-cache.json"
    record = WhoisRecord(
        doc_ip(0), doc_ip(255), "Org", "NET", now, "ARIN", kind="ASSIGNED PA"
    )
    write_cache_file(
        cache,
        {record.key: record},
        {},
        {
            "ARIN": RegistryState("ARIN", requests=[now - 5], blocked_until=now + 90),
            "LACNIC": RegistryState("LACNIC", requests=[now - i for i in range(1, 10)]),
        },
        now=now,
    )

    data = explain_cache(cache, now=now)
    rows = {row["registry"]: row for row in data["registries"]}

    assert data["bootstrap"]["present"] is False
    assert rows["ARIN"]["cached_networks"] == 1
    assert rows["ARIN"]["blocked_for_s"] == 90.0
    assert rows["ARIN"]["next_query_kind"] == "backoff"
    assert rows["LACNIC"]["next_query_kind"] == "published-limit"
    assert rows["RIPE NCC"]["next_query_wait_s"] == 0.0


def test_evidence_log_round_trips_and_summarizes(tmp_path: Path) -> None:
    clock = Clock()
    fetch = recording(ScriptedRegistry(clock, limit=(1.0, 1)), tmp_path)
    run_burst(
        registry="ARIN",
        bootstrap=BOOTSTRAP,
        fetch=fetch,
        count=5,
        interval=0.5,
        stop_after_refusals=2,
        time_fn=clock.time,
        sleep_fn=clock.sleep,
        queryable_fn=always,
    )

    rows = EvidenceLog.read(tmp_path / "evidence.jsonl")
    assert len(rows) == len(fetch.records)
    data = summarize(rows)
    arin = data["registries"]["ARIN"]
    assert arin["classified"].get(FETCH_REFUSED) == 2
    assert all(r["requests_prev_60s"] >= 1 for r in arin["refusals"])


def test_cli_explain_and_summary_run_offline(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cache = tmp_path / "whois-cache.json"
    write_cache_file(cache, {}, {}, {}, now=1.0)
    assert main(["explain", "--cache", str(cache)]) == 0
    assert "MISSING" in capsys.readouterr().out

    evidence = tmp_path / "evidence.jsonl"
    assert main(["--json", "summary", "--evidence", str(evidence)]) == 0
    assert json.loads(capsys.readouterr().out)["records"] == 0


def test_rdap_error_is_found_behind_long_notices_and_body_kept_whole() -> None:
    # RIPE-shaped 429: terms-of-service notices first, error fields last.
    notices = [{"title": "Terms and Conditions", "description": ["x" * 5000]}]
    body = json.dumps(
        {
            "rdapConformance": ["rdap_level_0"],
            "notices": notices,
            "errorCode": 429,
            "title": "Too Many Requests",
            "description": ["synthetic reason line one", "synthetic line two"],
        }
    ).encode()
    exchange = _exchange(429, body)
    record = exchange_record(
        exchange, classify_exchange(exchange), run_id="r", mode="burst"
    )

    assert record["body"] == body.decode()
    assert record["rdap_error"] == {
        "errorCode": 429,
        "title": "Too Many Requests",
        "description": ["synthetic reason line one", "synthetic line two"],
    }
    assert format_rdap_error(record["rdap_error"]) == (
        "429: Too Many Requests: synthetic reason line one / synthetic line two"
    )


def _write_permanent_denial(cache: Path, now: float) -> None:
    write_cache_file(
        cache,
        {},
        {},
        {
            "RIPE NCC": RegistryState(
                "RIPE NCC",
                denied={
                    "ts": now,
                    "permanent": True,
                    "until": None,
                    "http_status": 429,
                    "message": "%ERROR:201: access denied for 2001:db8::87",
                    "url": RIPE + "ip/" + doc_ip(1, net=2),
                },
            )
        },
        now=now,
    )


def test_burst_refuses_a_registry_that_blocked_this_host(tmp_path: Path) -> None:
    cache = tmp_path / "whois-cache.json"
    _write_permanent_denial(cache, 1_000.0)

    def no_network(url: str, timeout: float) -> HttpExchange:
        raise AssertionError("must not query a blocked registry")

    with pytest.raises(SystemExit, match="blocked this host"):
        main(
            ["burst", "RIPE", "--cache", str(cache), "--evidence", "none"],
            exchange_fn=no_network,
        )


def test_explain_json_reports_permanent_block(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cache = tmp_path / "whois-cache.json"
    _write_permanent_denial(cache, 1_000.0)

    assert main(["--json", "explain", "--cache", str(cache)]) == 0

    def reject(constant: str) -> None:
        raise AssertionError(f"non-standard JSON constant {constant}")

    data = json.loads(capsys.readouterr().out, parse_constant=reject)
    ripe = next(r for r in data["registries"] if r["registry"] == "RIPE NCC")
    assert ripe["next_query_kind"] == "denied"
    assert ripe["next_query_wait_s"] is None
    assert ripe["denied"]["permanent"] is True

    assert main(["explain", "--cache", str(cache)]) == 0
    assert "NO QUERIES: blocked this host" in capsys.readouterr().out

    assert main(["clear-denial", "RIPE", "--cache", str(cache)]) == 0
    assert "cleared RIPE NCC block" in capsys.readouterr().out
    assert main(["clear-denial", "RIPE", "--cache", str(cache)]) == 1


def test_replay_reports_an_inherited_permanent_block_as_valid_json(
    tmp_path: Path,
) -> None:
    clock = Clock()
    cache = tmp_path / "whois-cache.json"
    _write_permanent_denial(cache, clock.now)
    fetch = recording(ScriptedRegistry(clock))

    report = run_replay(
        ips=[doc_ip(1, net=2)],
        fetch=fetch,
        cache_path=cache,
        bootstrap_path=None,
        time_fn=clock.time,
        sleep_fn=clock.sleep,
        queryable_fn=always,
    )

    assert report.lookups_made == 0
    (finding,) = report.findings
    assert finding.severity == "inherited" and "no end: permanent" in finding.message
    json.dumps(report.to_json(), allow_nan=False)


# --- placeholders ----------------------------------------------------------------


def _iana_block_exchange(url: str, timeout: float) -> HttpExchange:
    """A registry answering every /ip/ query with APNIC's whole-IPv4 stand-in."""
    if "/ip/" not in url:
        return ScriptedRegistry(Clock())(url, timeout)
    body = {
        "objectClassName": "ip network",
        "startAddress": "0.0.0.0",
        "endAddress": "255.255.255.255",
        "name": "IANA-BLOCK",
        "port43": "whois.apnic.net",
        "entities": [],
    }
    return HttpExchange(
        url=url,
        started=0.0,
        elapsed=0.0,
        status=200,
        final_url=url,
        body=json.dumps(body).encode(),
    )


def test_ask_queries_the_named_registry_and_rejects_placeholders() -> None:
    clock = Clock()
    fetch = recording(_iana_block_exchange)

    (row,) = run_ask(
        registry="RIPE NCC",
        ips=[doc_ip(1)],  # bootstrap routes this to ARIN; ask ignores that
        fetch=fetch,
        bootstrap=BOOTSTRAP,
        time_fn=clock.time,
        sleep_fn=clock.sleep,
    )

    assert fetch.records[0]["url"] == RIPE + "ip/" + doc_ip(1)
    assert row["record"]["start"] == "0.0.0.0"
    assert "IANA-BLOCK 0.0.0.0/0" in str(row["placeholder"])
    assert row["shown"] == "-"
    assert "REJECTED, not an owner" in render_ask([row])


def test_cli_ask_never_sends_private_addresses(tmp_path: Path) -> None:
    def no_network(url: str, timeout: float) -> HttpExchange:
        raise AssertionError("must not send")

    with pytest.raises(SystemExit, match="never sent"):
        main(
            ["ask", "ARIN", "10.0.0.1", "--evidence", "none", "--cache", "none"],
            exchange_fn=no_network,
        )


def test_explain_lists_records_lookups_no_longer_use(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cache = tmp_path / "whois-cache.json"
    poisoned = {
        "start": "0.0.0.0",
        "end": "255.255.255.255",
        "org": None,
        "net": "IANA-BLOCK",
        "registry": "APNIC",
        "ts": 1_000.0,
    }
    untyped = {
        "start": doc_ip(0),
        "end": doc_ip(255),
        "org": "Old Org",
        "net": "OLD",
        "registry": "ARIN",
        "ts": 1_000.0,
    }
    cache.write_text(
        json.dumps({"version": 1, "networks": {"x": poisoned, "y": untyped}}),
        encoding="utf-8",
    )

    data = explain_cache(cache, now=2_000.0)

    assert data["networks"] == 0
    placeholder, older = sorted(data["ignored"], key=lambda e: not e["placeholder"])
    assert placeholder["registry"] == "APNIC" and "0.0.0.0/0" in placeholder["reason"]
    assert not older["placeholder"] and "no registration type" in older["reason"]
    assert main(["explain", "--cache", str(cache)]) == 0
    out = capsys.readouterr().out
    assert "IGNORED 0.0.0.0-255.255.255.255 from APNIC" in out
    assert "IGNORED 1 cached records: no registration type" in out


def test_entities_marks_recorded_placeholder_answers(tmp_path: Path) -> None:
    fetch = recording(_iana_block_exchange)
    fetch(ARIN + "ip/" + doc_ip(1), 1.0)

    (row,) = inspect_entities(fetch.records)

    assert row["net"] == "IANA-BLOCK" and row["placeholder"]
    assert "REJECTED" in render_entities([row])


# --- verify-cache and evict ---------------------------------------------------------


def _stale_cache(path: Path, ts: float) -> WhoisRecord:
    """A cached assignment the scripted registry no longer agrees with."""
    stale = WhoisRecord(
        doc_ip(0), doc_ip(15), "Old Org", "OLD", ts, "ARIN", kind="ASSIGNED PA"
    )
    write_cache_file(path, {stale.key: stale}, {}, now=ts)
    return stale


def test_verify_cache_reports_divergence_and_writes_only_pacing(
    tmp_path: Path,
) -> None:
    clock = Clock()
    cache = tmp_path / "whois-cache.json"
    stale = _stale_cache(cache, clock.now)

    report = run_verify_cache(
        cache_path=cache,
        ips=[doc_ip(1)],
        fetch=recording(ScriptedRegistry(clock)),
        bootstrap=BOOTSTRAP,
        time_fn=clock.time,
        sleep_fn=clock.sleep,
        queryable_fn=always,
    )

    (row,) = report["rows"]
    assert row["verdict"] == "diverged"
    assert row["cached"]["org"] == "Old Org" and row["live"]["net"] == "SYNTHETIC-NET"
    assert "rerun with --fix" in render_verify(report)
    records, _misses, states, answers = read_cache_file(cache)
    assert list(records) == [stale.key] and answers == {}  # answers untouched
    assert len(states["ARIN"].requests) == 1  # the registry saw the query


def test_verify_cache_fix_replaces_diverged_answers(tmp_path: Path) -> None:
    clock = Clock()
    cache = tmp_path / "whois-cache.json"
    stale = _stale_cache(cache, clock.now)

    def verify() -> dict[str, object]:
        return run_verify_cache(
            cache_path=cache,
            ips=[doc_ip(1)],
            fetch=recording(ScriptedRegistry(clock)),
            bootstrap=BOOTSTRAP,
            fix=True,
            time_fn=clock.time,
            sleep_fn=clock.sleep,
            queryable_fn=always,
        )

    report = verify()

    assert report["evicted"]["networks"] == [stale.key]
    records, _misses, _states, answers = read_cache_file(cache)
    assert records == {} and answers[doc_ip(1)].net == "SYNTHETIC-NET"
    assert "fixed: evicted 1 ranges" in render_verify(report)
    clock.now += 10
    assert verify()["rows"][0]["verdict"] == "match"


def test_verify_targets_take_the_oldest_cached_answers_first(tmp_path: Path) -> None:
    cache = tmp_path / "whois-cache.json"
    newer = WhoisRecord(doc_ip(0), doc_ip(15), "A", None, 50.0, kind="ASSIGNED PA")
    older = WhoisRecord(doc_ip(64), doc_ip(127), "B", None, 10.0, kind="ALLOCATED PA")
    write_cache_file(
        cache, {newer.key: newer}, {}, now=60.0, answers={doc_ip(70): older}
    )

    assert verify_targets(cache, 5) == []  # documentation space is never sent
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("lgu.whois_probe.is_queryable", always)
        assert verify_targets(cache, 5) == [doc_ip(70), doc_ip(0)]
        assert verify_targets(cache, 1) == [doc_ip(70)]


def test_cli_evict_reports_what_it_removed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cache = tmp_path / "whois-cache.json"
    stale = _stale_cache(cache, 1_000.0)

    assert main(["evict", doc_ip(3), "--cache", str(cache)]) == 0
    out = capsys.readouterr().out
    assert (
        f"range {stale.key}" in out and "pacing state and recorded blocks kept" in out
    )
    assert main(["evict", doc_ip(3), "--cache", str(cache)]) == 1
    assert "nothing cached" in capsys.readouterr().out
    with pytest.raises(SystemExit, match="not an IP"):
        main(["evict", "nonsense", "--cache", str(cache)])
