from __future__ import annotations

import json
import socket
import time
from pathlib import Path

import pytest
from synthetic_access import CHROME_133_UA, audit_args, doc_ip, row

import lgu.reverse_dns as reverse_dns_module
from lgu.audit import build_reverse_dns_resolver, build_runtime, print_recent_view
from lgu.reverse_dns import (
    CACHE_ENV_VAR,
    CACHE_VERSION,
    NEGATIVE_TTL_CAP_SECONDS,
    PtrEntry,
    ReverseDNSResolver,
    arpa_to_ip,
    default_cache_path,
    ip_to_arpa,
    normalize_ip,
    parse_dig_output,
    read_cache_file,
    resolve_with_socket,
    write_cache_file,
)

DIG_OUTPUT = """;1.2.0.192.in-addr.arpa.\t\tIN\tPTR
1.2.0.192.in-addr.arpa.\t3600\tIN\tPTR\thost-one.example.test.
;2.2.0.192.in-addr.arpa.\t\tIN\tPTR
"""


def seed_cache(path: Path, entries: dict[str, str | None], ts: float) -> None:
    write_cache_file(
        path, {ip: PtrEntry(ptr=ptr, ts=ts) for ip, ptr in entries.items()}
    )


def test_arpa_conversion_round_trips_v4_and_v6() -> None:
    assert ip_to_arpa(doc_ip(7)) == "7.2.0.192.in-addr.arpa"
    assert arpa_to_ip("7.2.0.192.in-addr.arpa.") == doc_ip(7)
    v6 = "2001:db8::1"
    assert arpa_to_ip(ip_to_arpa(v6) or "") == v6


def test_ipv4_mapped_addresses_normalize_to_ipv4() -> None:
    assert normalize_ip(f"::ffff:{doc_ip(7)}") == doc_ip(7)
    assert normalize_ip(" 2001:DB8::1 ") == "2001:db8::1"
    assert normalize_ip("not-an-ip") == "not-an-ip"


def test_arpa_conversion_rejects_malformed_names() -> None:
    assert arpa_to_ip("example.test.") is None
    assert arpa_to_ip("2.0.192.in-addr.arpa.") is None
    assert arpa_to_ip("zz.ip6.arpa.") is None
    assert ip_to_arpa("not-an-ip") is None


def test_parse_dig_output_separates_answers_misses_and_failures() -> None:
    parsed = parse_dig_output(DIG_OUTPUT)
    # Answered with a PTR, answered with NXDOMAIN, and never answered at all.
    assert parsed[doc_ip(1)] == "host-one.example.test"
    assert parsed[doc_ip(2)] is None
    assert doc_ip(3) not in parsed


def test_cache_file_round_trips_and_merges(tmp_path: Path) -> None:
    cache = tmp_path / "ptr-cache.json"
    seed_cache(cache, {doc_ip(1): "host-one.example.test"}, ts=100.0)
    seed_cache(cache, {doc_ip(2): None}, ts=200.0)

    entries = read_cache_file(cache)
    assert entries[doc_ip(1)] == PtrEntry(ptr="host-one.example.test", ts=100.0)
    assert entries[doc_ip(2)] == PtrEntry(ptr=None, ts=200.0)

    payload = json.loads(cache.read_text(encoding="utf-8"))
    assert payload["version"] == CACHE_VERSION


def test_cache_file_keeps_newest_entry_per_ip(tmp_path: Path) -> None:
    cache = tmp_path / "ptr-cache.json"
    seed_cache(cache, {doc_ip(1): "old.example.test"}, ts=100.0)
    seed_cache(cache, {doc_ip(1): "new.example.test"}, ts=200.0)
    seed_cache(cache, {doc_ip(1): "stale.example.test"}, ts=50.0)
    assert read_cache_file(cache)[doc_ip(1)].ptr == "new.example.test"


def test_unreadable_cache_file_is_ignored(tmp_path: Path) -> None:
    cache = tmp_path / "ptr-cache.json"
    cache.write_text("{not json", encoding="utf-8")
    assert read_cache_file(cache) == {}

    cache.write_text(json.dumps({"version": 999, "entries": {}}), encoding="utf-8")
    assert read_cache_file(cache) == {}


def test_resolver_queries_each_ip_once_and_persists(tmp_path: Path) -> None:
    cache = tmp_path / "ptr-cache.json"
    queried: list[list[str]] = []

    def fake_resolve(ips: list[str]) -> dict[str, str | None]:
        queried.append(list(ips))
        return {ip: f"host-{ip}.example.test" for ip in ips}

    resolver = ReverseDNSResolver(
        cache_path=cache,
        resolve_fn=fake_resolve,
        time_fn=lambda: 1000.0,
    )
    resolver.resolve_many([doc_ip(1), doc_ip(2), doc_ip(1)])
    resolver.resolve_many([doc_ip(2)])
    resolver.save()

    assert queried == [[doc_ip(1), doc_ip(2)]]
    assert resolver.lookup(doc_ip(1)) == f"host-{doc_ip(1)}.example.test"

    reloaded = ReverseDNSResolver(
        cache_path=cache,
        resolve_fn=fake_resolve,
        time_fn=lambda: 1001.0,
    )
    reloaded.resolve_many([doc_ip(1), doc_ip(2)])
    assert queried == [[doc_ip(1), doc_ip(2)]]
    assert reloaded.lookup(doc_ip(2)) == f"host-{doc_ip(2)}.example.test"


def test_resolver_skips_persistence_without_cache_path() -> None:
    calls: list[list[str]] = []

    def fake_resolve(ips: list[str]) -> dict[str, str | None]:
        calls.append(list(ips))
        return dict.fromkeys(ips, "host.example.test")

    resolver = ReverseDNSResolver(cache_path=None, resolve_fn=fake_resolve)
    resolver.resolve_many([doc_ip(1)])
    resolver.save()
    assert resolver.lookup(doc_ip(1)) == "host.example.test"
    assert calls == [[doc_ip(1)]]


def test_unresolved_ips_are_not_cached(tmp_path: Path) -> None:
    cache = tmp_path / "ptr-cache.json"
    resolver = ReverseDNSResolver(
        cache_path=cache,
        resolve_fn=lambda ips: {},
        time_fn=lambda: 1000.0,
    )
    resolver.resolve_many([doc_ip(1)])
    resolver.save()
    assert resolver.lookup(doc_ip(1)) is None
    assert not cache.exists()


@pytest.mark.parametrize(
    ("ptr", "age", "expect_refresh"),
    [
        ("host.example.test", 10.0, False),
        ("host.example.test", 3600.0 * 24 * 30, True),
        (None, 60.0, False),
        (None, NEGATIVE_TTL_CAP_SECONDS + 60.0, True),
    ],
)
def test_entries_expire_by_ttl(
    tmp_path: Path, ptr: str | None, age: float, expect_refresh: bool
) -> None:
    cache = tmp_path / "ptr-cache.json"
    now = 1_000_000.0
    seed_cache(cache, {doc_ip(1): ptr}, ts=now - age)
    queried: list[list[str]] = []

    def fake_resolve(ips: list[str]) -> dict[str, str | None]:
        queried.append(list(ips))
        return dict.fromkeys(ips, "fresh.example.test")

    resolver = ReverseDNSResolver(
        cache_path=cache,
        resolve_fn=fake_resolve,
        time_fn=lambda: now,
    )
    resolver.resolve_many([doc_ip(1)])
    assert bool(queried) is expect_refresh
    assert resolver.lookup(doc_ip(1)) == (
        "fresh.example.test" if expect_refresh else ptr
    )


def test_default_cache_path_prefers_env_then_xdg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(CACHE_ENV_VAR, str(tmp_path / "explicit.json"))
    assert default_cache_path() == tmp_path / "explicit.json"

    monkeypatch.delenv(CACHE_ENV_VAR)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    assert default_cache_path() == tmp_path / "xdg" / "lgu" / "ptr-cache.json"


def test_build_reverse_dns_resolver_honors_flags(tmp_path: Path) -> None:
    assert build_reverse_dns_resolver(audit_args(reverse_dns=False)) is None

    disabled_cache = build_reverse_dns_resolver(
        audit_args(reverse_dns=True, ptr_cache="none")
    )
    assert disabled_cache is not None
    assert disabled_cache.cache_path is None

    explicit = build_reverse_dns_resolver(
        audit_args(reverse_dns=True, ptr_cache=str(tmp_path / "ptr.json"))
    )
    assert explicit is not None
    assert explicit.cache_path == tmp_path / "ptr.json"


def test_recent_view_prints_cached_ptr_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cache = tmp_path / "ptr-cache.json"
    seed_cache(
        cache,
        {doc_ip(1): "host-one.example.test", doc_ip(2): None},
        ts=time.time(),
    )
    args = audit_args(ptr_cache=str(cache))
    runtime = build_runtime(args)
    rows = [
        row(ts=2_000_000.0, ip=doc_ip(1), ua=CHROME_133_UA, path="/synthetic/one"),
        row(ts=2_000_001.0, ip=doc_ip(2), ua=CHROME_133_UA, path="/synthetic/two"),
    ]

    print_recent_view(rows, args, runtime, bot_ips=set())
    output = capsys.readouterr().out

    assert f"{doc_ip(1):<15}  " in output
    assert "  ptr host-one.example.test" in output
    assert "  ptr -" in output


def test_recent_view_omits_ptr_line_when_disabled(
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = audit_args(reverse_dns=False)
    runtime = build_runtime(args)
    rows = [row(ts=2_000_000.0, ip=doc_ip(1), ua=CHROME_133_UA)]

    print_recent_view(rows, args, runtime, bot_ips=set())
    assert " ptr " not in capsys.readouterr().out


# dig +noall +comments +question +answer: a header precedes each question.
DIG_STATUS_OUTPUT = """;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;1.2.0.192.in-addr.arpa.\t\tIN\tPTR

;; ANSWER SECTION:
1.2.0.192.in-addr.arpa.\t3600\tIN\tPTR\thost-one.example.test.

;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 2
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;2.2.0.192.in-addr.arpa.\t\tIN\tPTR

;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 3
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;3.2.0.192.in-addr.arpa.\t\tIN\tPTR

;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 4
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;4.2.0.192.in-addr.arpa.\t\tIN\tPTR

;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 5
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; QUESTION SECTION:
;5.2.0.192.in-addr.arpa.\t\tIN\tPTR
;; connection timed out; no servers could be reached
"""


def test_parse_dig_output_never_reports_a_failed_query_as_no_ptr() -> None:
    parsed = parse_dig_output(DIG_STATUS_OUTPUT)

    assert parsed[doc_ip(1)] == "host-one.example.test"
    assert parsed[doc_ip(2)] is None  # NXDOMAIN: settled, no PTR
    assert parsed[doc_ip(5)] is None  # NOERROR with no answer: settled
    assert doc_ip(3) not in parsed  # SERVFAIL: a failure, never cached
    assert doc_ip(4) not in parsed  # REFUSED: a failure, never cached


def test_dig_failures_are_not_cached_and_are_asked_again(tmp_path: Path) -> None:
    cache = tmp_path / "ptr.json"
    batches: list[list[str]] = []

    def resolve(ips: list[str]) -> dict[str, str | None]:
        batches.append(ips)
        return parse_dig_output(DIG_STATUS_OUTPUT)

    first = ReverseDNSResolver(cache_path=cache, resolve_fn=resolve)
    first.resolve_many([doc_ip(n) for n in range(1, 5)])
    assert first.save()

    second = ReverseDNSResolver(cache_path=cache, resolve_fn=resolve)
    second.resolve_many([doc_ip(n) for n in range(1, 5)])
    assert batches[1] == [doc_ip(3), doc_ip(4)]


@pytest.mark.parametrize(
    ("error", "cached"),
    [
        (socket.herror(1, "Unknown host"), True),  # HOST_NOT_FOUND: no PTR
        (socket.herror(4, "No address associated"), True),  # NO_DATA: no PTR
        (socket.herror(2, "Host name lookup failure"), False),  # TRY_AGAIN
        (socket.herror(3, "Unknown server error"), False),  # NO_RECOVERY
        (TimeoutError("timed out"), False),
        (socket.gaierror(-3, "Temporary failure in name resolution"), False),
    ],
)
def test_socket_failures_are_not_cached_as_no_ptr(
    monkeypatch: pytest.MonkeyPatch, error: OSError, cached: bool
) -> None:
    def fail(_ip: str) -> tuple[str, list[str], list[str]]:
        raise error

    monkeypatch.setattr(reverse_dns_module.socket, "gethostbyaddr", fail)

    resolved = resolve_with_socket([doc_ip(1)])

    assert (doc_ip(1) in resolved) is cached
    assert resolved.get(doc_ip(1)) is None
