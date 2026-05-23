from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from email.utils import format_datetime
from ipaddress import ip_network
from pathlib import Path

import pytest
from synthetic_access import CHROME_133_UA, audit_args, doc_ip, row

import lgu.audit as audit_module
from lgu.audit import (
    RequestRow,
    build_runtime,
    build_whois_resolver,
    print_recent_view,
)
from lgu.whois_lookup import (
    BOOTSTRAP_TTL_SECONDS,
    BOOTSTRAP_URLS,
    CACHE_ENV_VAR,
    CACHE_VERSION,
    DEFER_BACKOFF,
    DEFER_DENIED,
    DEFER_PUBLISHED_LIMIT,
    DEFER_REFUSED,
    FALLBACK_BASE_URL,
    FETCH_DENIED,
    FETCH_ERROR,
    FETCH_FORBIDDEN,
    FETCH_NOT_FOUND,
    FETCH_OK,
    FETCH_REFUSED,
    MAX_ATTEMPTS_PER_IP,
    MAX_BACKOFF_SECONDS,
    NEGATIVE_TTL_CAP_SECONDS,
    FetchResult,
    HttpExchange,
    RdapBootstrap,
    RegistryState,
    WhoisRecord,
    WhoisResolver,
    _HttpsOnlyRedirectHandler,
    classify_exchange,
    clean_label,
    clear_denial,
    default_cache_path,
    format_whois_line,
    is_queryable,
    load_bootstrap,
    meaningful_net_name,
    next_utc_midnight,
    parse_bootstrap,
    parse_rdap_network,
    parse_retry_after,
    read_cache_file,
    registrant_candidates,
    registry_for_port43,
    registry_for_url,
    write_cache_file,
)

FAST = "https://rdap.fast.example.test/"
SLOW = "https://rdap.slow.example.test/rdap/"
FAST_NAME = "rdap.fast.example.test"
SLOW_NAME = "rdap.slow.example.test"
# 192.0.2.0/25 is served by FAST, 192.0.2.128/25 by SLOW.
BOOTSTRAP = RdapBootstrap(
    [(ip_network("192.0.2.0/25"), FAST), (ip_network("192.0.2.128/25"), SLOW)]
)


def vcard_entity(handle: str, name: str, roles: list[str]) -> dict[str, object]:
    return {
        "handle": handle,
        "roles": roles,
        "vcardArray": [
            "vcard",
            [["version", {}, "text", "4.0"], ["fn", {}, "text", name]],
        ],
    }


def network_payload(
    start: str,
    end: str,
    *,
    name: str = "SYNTHETIC-NET",
    entities: list[dict[str, object]] | None = None,
    remarks: list[dict[str, object]] | None = None,
    port43: str | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "objectClassName": "ip network",
        "startAddress": start,
        "endAddress": end,
        "name": name,
        "entities": entities or [],
        "remarks": remarks or [],
    }
    if port43 is not None:
        payload["port43"] = port43
    return payload


def block_payload(octet_start: int, octet_end: int, org: str) -> dict[str, object]:
    return network_payload(
        doc_ip(octet_start),
        doc_ip(octet_end),
        entities=[vcard_entity("SYN-1", org, ["registrant"])],
    )


class Clock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now
        self.sleeps: list[float] = []

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(round(seconds, 6))
        self.now += seconds


class FakeRegistries:
    """Answers RDAP ip lookups with one synthetic block per 32 addresses."""

    def __init__(
        self,
        clock: Clock,
        results: dict[str, FetchResult | list[FetchResult]] | None = None,
    ) -> None:
        self.clock = clock
        self.results = results or {}
        self.urls: list[str] = []

    @property
    def calls(self) -> list[str]:
        return [url.rsplit("/ip/", 1)[1] for url in self.urls]

    def __call__(self, url: str, timeout: float) -> FetchResult:
        self.urls.append(url)
        self.clock.now += 0.1  # simulated network latency
        ip = url.rsplit("/ip/", 1)[1]
        scripted = self.results.get(ip)
        if isinstance(scripted, list):
            # A script of answers, consumed in order; normal answers after.
            if scripted:
                return scripted.pop(0)
        elif scripted is not None:
            return scripted
        last_octet = int(ip.rsplit(".", 1)[1])
        first = last_octet - last_octet % 32
        return FetchResult(
            FETCH_OK, block_payload(first, first + 31, f"Synthetic Org {first}")
        )


def make_resolver(
    clock: Clock, registries: FakeRegistries, **overrides: object
) -> WhoisResolver:
    options: dict[str, object] = {
        "fetch_fn": registries,
        "bootstrap": BOOTSTRAP,
        "interval": 0.0,
        "time_fn": clock.time,
        "sleep_fn": clock.sleep,
        "queryable_fn": lambda _ip: True,
        "published_limits": {},
    }
    options.update(overrides)
    return WhoisResolver(**options)  # type: ignore[arg-type]


@pytest.fixture
def clock() -> Clock:
    return Clock()


# --- parsing ------------------------------------------------------------------


def test_parse_prefers_registrant_org_over_network_name() -> None:
    payload = network_payload(
        doc_ip(0),
        doc_ip(255),
        name="SYNTHETIC-BLK",
        entities=[
            vcard_entity("SYN-ADMIN", "Synthetic Admin", ["administrative"]),
            vcard_entity("SYN-ORG", "Synthetic Hosting LLC", ["registrant"]),
        ],
    )

    record = parse_rdap_network(payload, doc_ip(9), ts=1.0)

    assert record == WhoisRecord(
        start=doc_ip(0),
        end=doc_ip(255),
        org="Synthetic Hosting LLC",
        net="SYNTHETIC-BLK",
        ts=1.0,
    )
    assert format_whois_line(record, doc_ip(9)) == (
        f"Synthetic Hosting LLC  {doc_ip(0)}/24  SYNTHETIC-BLK"
    )


def test_parse_prefers_ripe_org_object_over_maintainer_registrants() -> None:
    payload = network_payload(
        doc_ip(0),
        doc_ip(255),
        entities=[
            vcard_entity("SYN-NET-MNT", "SYN-NET-MNT", ["registrant"]),
            vcard_entity("ORG-SYN1-RIPE", "Synthetic Telecom SRL", ["registrant"]),
            vcard_entity("RIPE-NCC-HM-MNT", "RIPE-NCC-HM-MNT", ["registrant"]),
        ],
    )

    record = parse_rdap_network(payload, doc_ip(1), ts=1.0)

    assert record is not None
    assert record.org == "Synthetic Telecom SRL"


def test_parse_never_reports_a_maintainer_handle_as_the_org() -> None:
    payload = network_payload(
        doc_ip(0),
        doc_ip(255),
        name="SYN-EXIT-NET",
        entities=[vcard_entity("SYN1101-MNT", "SYN1101-MNT", ["registrant"])],
    )

    record = parse_rdap_network(payload, doc_ip(1), ts=1.0)

    assert record is not None and record.org is None
    assert format_whois_line(record, doc_ip(1)) == f"SYN-EXIT-NET  {doc_ip(0)}/24"


def test_parse_falls_back_to_remark_org_then_network_name() -> None:
    remark_only = network_payload(
        doc_ip(0),
        doc_ip(255),
        remarks=[{"description": ["Internet Service Provider", "OrgName: Lessee Co"]}],
    )
    bare = network_payload(doc_ip(0), doc_ip(255), name="BARE-NET")

    remark_record = parse_rdap_network(remark_only, doc_ip(1), ts=1.0)
    bare_record = parse_rdap_network(bare, doc_ip(1), ts=1.0)

    assert remark_record is not None and remark_record.org == "Lessee Co"
    assert bare_record is not None and bare_record.org is None
    assert format_whois_line(bare_record, doc_ip(1)) == f"BARE-NET  {doc_ip(0)}/24"


def test_parse_records_the_answering_registry_from_port43() -> None:
    payload = network_payload(
        doc_ip(0),
        doc_ip(255),
        entities=[vcard_entity("SYN-ORG", "Synthetic Carrier", ["registrant"])],
        port43="whois.registro.br",
    )

    record = parse_rdap_network(payload, doc_ip(1), ts=1.0, registry="LACNIC")
    queried_only = parse_rdap_network(
        network_payload(doc_ip(0), doc_ip(255)), doc_ip(1), ts=1.0, registry="LACNIC"
    )

    assert record is not None and record.registry == "NIC.br"
    assert queried_only is not None and queried_only.registry == "LACNIC"


@pytest.mark.parametrize(
    "payload",
    [
        network_payload(doc_ip(0), doc_ip(10)),  # does not contain the IP
        network_payload("2001:db8::", "2001:db8::ffff"),  # wrong family
        network_payload("not-an-ip", doc_ip(255)),
        {"startAddress": doc_ip(0)},
    ],
)
def test_parse_rejects_unusable_network_answers(payload: dict[str, object]) -> None:
    assert parse_rdap_network(payload, doc_ip(50), ts=1.0) is None


def test_clean_label_strips_terminal_control_sequences() -> None:
    label = clean_label("Evil\x1b[2J\x1b]0;pwned\x07 Org\r\n  Name" + "x" * 200)

    assert label is not None
    assert "\x1b" not in label and "\x07" not in label and "\r" not in label
    assert label.startswith("Evil [2J ]0;pwned Org Name")
    assert len(label) <= 80
    assert clean_label("   ") is None
    assert clean_label(42) is None


# --- display ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("net", "expected"),
    [
        ("SYN-HOSTING-BLK", True),
        ("144", False),
        (f"{doc_ip(0)} - {doc_ip(255)}", False),
        (f"{doc_ip(0)}/24", False),
        (doc_ip(0), False),
        (None, False),
    ],
)
def test_meaningful_net_name_hides_numbering_noise(
    net: str | None, expected: bool
) -> None:
    assert meaningful_net_name(net) is expected


def test_format_appends_the_registry_tag() -> None:
    record = WhoisRecord(
        doc_ip(0), doc_ip(255), "Synthetic Carrier", "144", 1.0, registry="NIC.br"
    )

    assert format_whois_line(record, doc_ip(7)) == (
        f"Synthetic Carrier  {doc_ip(0)}/24  [NIC.br]"
    )


def test_format_falls_back_to_the_registry_without_an_assignee() -> None:
    record = WhoisRecord(
        doc_ip(0), doc_ip(255), None, f"{doc_ip(0)} - {doc_ip(255)}", 1.0, "LACNIC"
    )

    assert format_whois_line(record, doc_ip(7)) == (
        f"LACNIC (no assignee listed)  {doc_ip(0)}/24"
    )


def test_registry_names_come_from_rdap_and_port43_hosts() -> None:
    assert registry_for_url("https://rdap.lacnic.net/rdap/") == "LACNIC"
    assert registry_for_url("https://rdap.db.ripe.net/") == "RIPE NCC"
    assert registry_for_url(FAST) == FAST_NAME
    assert registry_for_port43("whois.registro.br") == "NIC.br"
    assert registry_for_port43("WHOIS.ARIN.NET") == "ARIN"
    assert registry_for_port43(None) is None


# --- routing ------------------------------------------------------------------


def test_lookups_route_directly_to_the_bootstrap_registry(clock: Clock) -> None:
    registries = FakeRegistries(clock)
    resolver = make_resolver(clock, registries)

    resolver.resolve_many([doc_ip(5), doc_ip(200)])

    assert registries.urls == [f"{FAST}ip/{doc_ip(5)}", f"{SLOW}ip/{doc_ip(200)}"]


def test_unmapped_addresses_fall_back_to_the_arin_entry_point(clock: Clock) -> None:
    registries = FakeRegistries(clock)
    resolver = make_resolver(clock, registries, bootstrap=RdapBootstrap([]))

    resolver.resolve_many([doc_ip(5)])

    assert registries.urls == [f"{FALLBACK_BASE_URL}ip/{doc_ip(5)}"]


def test_bootstrap_prefers_the_most_specific_prefix() -> None:
    bootstrap = RdapBootstrap(
        [(ip_network("192.0.0.0/8"), FAST), (ip_network("192.0.2.0/24"), SLOW)]
    )

    assert bootstrap.base_url(doc_ip(1)) == SLOW
    assert bootstrap.base_url("192.0.3.1") == FAST
    assert bootstrap.base_url("2001:db8::1") is None


def test_parse_bootstrap_keeps_https_services_only() -> None:
    payload = {
        "services": [
            [["192.0.2.0/25"], ["http://plain.example.test/", FAST.rstrip("/")]],
            [["192.0.2.128/25", "bogus"], ["http://plain-only.example.test/"]],
        ]
    }

    assert parse_bootstrap(payload) == [(ip_network("192.0.2.0/25"), FAST)]
    assert parse_bootstrap({"services": "nope"}) == []


def test_bootstrap_is_cached_on_disk_and_refreshed_weekly(tmp_path: Path) -> None:
    path = tmp_path / "bootstrap.json"
    fetched: list[str] = []

    def fetch(url: str, timeout: float) -> FetchResult:
        fetched.append(url)
        prefix = "192.0.2.0/24" if url == BOOTSTRAP_URLS[4] else "2001:db8::/32"
        return FetchResult(FETCH_OK, {"services": [[[prefix], [FAST]]]})

    first = load_bootstrap(path, fetch, 1.0, now=1000.0)
    assert first is not None and first.base_url(doc_ip(1)) == FAST
    assert fetched == [BOOTSTRAP_URLS[4], BOOTSTRAP_URLS[6]]

    cached = load_bootstrap(path, fetch, 1.0, now=1000.0 + 3600)
    assert cached is not None and cached.base_url(doc_ip(1)) == FAST
    assert len(fetched) == 2

    load_bootstrap(path, fetch, 1.0, now=1000.0 + BOOTSTRAP_TTL_SECONDS + 1)
    assert len(fetched) == 4


def test_stale_bootstrap_is_used_when_refresh_fails(tmp_path: Path) -> None:
    path = tmp_path / "bootstrap.json"
    path.write_text(
        json.dumps({"ts": 0.0, "services": {"4": [["192.0.2.0/24", SLOW]]}}),
        encoding="utf-8",
    )

    def failing(url: str, timeout: float) -> FetchResult:
        return FetchResult(FETCH_ERROR)

    stale = load_bootstrap(path, failing, 1.0, now=BOOTSTRAP_TTL_SECONDS * 3)
    assert stale is not None and stale.base_url(doc_ip(1)) == SLOW
    assert load_bootstrap(None, failing, 1.0, now=0.0) is None


# --- caching ------------------------------------------------------------------


def test_non_global_addresses_are_never_queried(clock: Clock) -> None:
    assert not is_queryable(doc_ip(1))
    assert not is_queryable("10.0.0.1")
    assert not is_queryable("127.0.0.1")
    assert not is_queryable("::1")
    assert not is_queryable("garbage")

    registries = FakeRegistries(clock)
    resolver = WhoisResolver(
        fetch_fn=registries, bootstrap=BOOTSTRAP, sleep_fn=clock.sleep
    )
    resolver.resolve_many([doc_ip(1), "10.0.0.1", "::1"])

    assert registries.urls == []


def test_one_query_covers_every_ip_in_the_returned_block(clock: Clock) -> None:
    registries = FakeRegistries(clock)
    resolver = make_resolver(clock, registries)

    resolver.resolve_many([doc_ip(1), doc_ip(2), doc_ip(31), doc_ip(32)])

    assert registries.calls == [doc_ip(1), doc_ip(32)]
    first = resolver.lookup(doc_ip(31))
    second = resolver.lookup(doc_ip(32))
    assert first is not None and first.org == "Synthetic Org 0"
    assert second is not None and second.org == "Synthetic Org 32"


def test_lookup_prefers_the_most_specific_cached_block(clock: Clock) -> None:
    registries = FakeRegistries(
        clock,
        {
            doc_ip(1): FetchResult(FETCH_OK, block_payload(0, 127, "Parent ISP")),
            doc_ip(100): FetchResult(
                FETCH_OK, block_payload(96, 111, "Reassigned Customer")
            ),
        },
    )
    resolver = make_resolver(clock, registries)
    resolver.resolve_many([doc_ip(1)])
    resolver._ranges.clear()  # simulate learning the parent, then the child
    resolver.resolve_many([doc_ip(100), doc_ip(1)])

    child = resolver.lookup(doc_ip(105))
    parent = resolver.lookup(doc_ip(5))
    assert child is not None and child.org == "Reassigned Customer"
    assert parent is not None and parent.org == "Parent ISP"


def test_ipv4_mapped_addresses_share_the_ipv4_block_cache(clock: Clock) -> None:
    registries = FakeRegistries(clock)
    resolver = make_resolver(clock, registries)

    resolver.resolve_many([f"::ffff:{doc_ip(1)}", doc_ip(2), f"::FFFF:{doc_ip(3)}"])

    # One IPv4 query covers both mapped spellings and the plain address.
    assert registries.calls == [doc_ip(1)]
    record = resolver.lookup(f"::ffff:{doc_ip(3)}")
    assert record is not None and record.org == "Synthetic Org 0"
    assert resolver.describe(f"::ffff:{doc_ip(3)}").startswith("Synthetic Org 0")


def test_not_found_is_cached_briefly_then_retried(clock: Clock) -> None:
    registries = FakeRegistries(clock, {doc_ip(1): FetchResult(FETCH_NOT_FOUND)})
    resolver = make_resolver(clock, registries)

    resolver.resolve_many([doc_ip(1)])
    resolver.resolve_many([doc_ip(1)])
    assert registries.calls == [doc_ip(1)]
    assert resolver.describe(doc_ip(1)) == "-"

    clock.now += NEGATIVE_TTL_CAP_SECONDS + 1
    resolver.resolve_many([doc_ip(1)])
    assert registries.calls == [doc_ip(1), doc_ip(1)]


def test_expired_blocks_are_queried_again(clock: Clock) -> None:
    registries = FakeRegistries(clock)
    resolver = make_resolver(clock, registries, ttl=60.0)

    resolver.resolve_many([doc_ip(1)])
    clock.now += 61
    assert resolver.lookup(doc_ip(1)) is None
    resolver.resolve_many([doc_ip(1)])

    assert registries.calls == [doc_ip(1), doc_ip(1)]


def test_cache_persists_blocks_across_runs(tmp_path: Path, clock: Clock) -> None:
    cache = tmp_path / "nested" / "whois.json"
    first_registries = FakeRegistries(clock)
    first = make_resolver(clock, first_registries, cache_path=cache)
    first.resolve_many([doc_ip(1)])
    first.save()

    payload = json.loads(cache.read_text(encoding="utf-8"))
    assert payload["version"] == CACHE_VERSION
    assert list(payload["networks"]) == [f"{doc_ip(0)}-{doc_ip(31)}"]

    second_registries = FakeRegistries(clock)
    second = make_resolver(clock, second_registries, cache_path=cache)
    second.resolve_many([doc_ip(20)])

    assert second_registries.urls == []
    record = second.lookup(doc_ip(20))
    assert record is not None and record.org == "Synthetic Org 0"
    assert record.registry == FAST_NAME


def test_cache_writes_merge_with_concurrent_runs(tmp_path: Path) -> None:
    cache = tmp_path / "whois.json"
    older = WhoisRecord(doc_ip(0), doc_ip(63), "Old Name", None, ts=10.0)
    newer = WhoisRecord(doc_ip(0), doc_ip(63), "New Name", None, ts=20.0)
    other = WhoisRecord(doc_ip(64), doc_ip(127), "Other", None, ts=15.0)

    write_cache_file(
        cache,
        {newer.key: newer},
        {doc_ip(200): 5.0},
        {"R": RegistryState("R", requests=[100.0], blocked_until=500.0)},
        now=110.0,
    )
    write_cache_file(
        cache,
        {older.key: older, other.key: other},
        {},
        {"R": RegistryState("R", requests=[105.0], blocked_until=200.0)},
        now=110.0,
    )

    records, misses, registries = read_cache_file(cache)
    assert records[newer.key].org == "New Name"
    assert records[other.key].org == "Other"
    assert misses == {doc_ip(200): 5.0}
    assert registries["R"].requests == [100.0, 105.0]
    assert registries["R"].blocked_until == 500.0


def test_corrupt_or_foreign_cache_files_are_ignored(tmp_path: Path) -> None:
    cache = tmp_path / "whois.json"
    cache.write_text("{not json", encoding="utf-8")
    assert read_cache_file(cache) == ({}, {}, {})

    cache.write_text(json.dumps({"version": 999, "networks": {}}), encoding="utf-8")
    assert read_cache_file(cache) == ({}, {}, {})


def test_default_cache_path_honors_env_and_xdg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(CACHE_ENV_VAR, str(tmp_path / "explicit.json"))
    assert default_cache_path() == tmp_path / "explicit.json"

    monkeypatch.delenv(CACHE_ENV_VAR)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    assert default_cache_path() == tmp_path / "xdg" / "lgu" / "whois-cache.json"


# --- pacing -------------------------------------------------------------------


def test_spacing_applies_per_registry_not_globally(clock: Clock) -> None:
    registries = FakeRegistries(clock)
    resolver = make_resolver(clock, registries, interval=0.5)

    # fast, slow, fast: the second fast lookup waits on fast's own spacing,
    # and the slow lookup in between does not wait at all.
    resolver.resolve_many([doc_ip(1), doc_ip(129), doc_ip(33)])

    assert registries.calls == [doc_ip(1), doc_ip(129), doc_ip(33)]
    assert clock.sleeps == [0.4]


def test_published_minute_window_is_slept_not_deferred(clock: Clock) -> None:
    registries = FakeRegistries(clock)
    resolver = make_resolver(
        clock, registries, published_limits={SLOW_NAME: ((60.0, 2),)}
    )

    resolver.resolve_many([doc_ip(129), doc_ip(161), doc_ip(193), doc_ip(1)])

    # The third slow lookup waits out the minute window inside the run.
    assert registries.calls == [doc_ip(129), doc_ip(161), doc_ip(193), doc_ip(1)]
    assert max(clock.sleeps) == pytest.approx(59.9)
    assert resolver.pending == 0


def test_published_hour_window_defers_only_that_registry(clock: Clock) -> None:
    registries = FakeRegistries(clock)
    resolver = make_resolver(
        clock, registries, published_limits={SLOW_NAME: ((3600.0, 2),)}
    )

    resolver.resolve_many([doc_ip(129), doc_ip(161), doc_ip(193), doc_ip(1)])

    assert registries.calls == [doc_ip(129), doc_ip(161), doc_ip(1)]
    assert resolver.describe(doc_ip(193)).startswith(
        f"? deferred: {SLOW_NAME} published limit 3/1h; retry in ~"
    )
    assert resolver.deferred_kinds == {doc_ip(193): DEFER_PUBLISHED_LIMIT}
    assert resolver.lookup(doc_ip(1)) is not None


def test_published_window_is_shared_across_runs(tmp_path: Path, clock: Clock) -> None:
    cache = tmp_path / "whois.json"
    limits = {SLOW_NAME: ((3600.0, 2),)}
    first = make_resolver(
        clock, FakeRegistries(clock), cache_path=cache, published_limits=limits
    )
    first.resolve_many([doc_ip(129), doc_ip(161)])
    first.save()

    clock.now += 10
    second_registries = FakeRegistries(clock)
    second = make_resolver(
        clock, second_registries, cache_path=cache, published_limits=limits
    )
    second.resolve_many([doc_ip(193)])
    assert second_registries.urls == []
    assert second.pending == 1

    clock.now += 3600
    third_registries = FakeRegistries(clock)
    third = make_resolver(
        clock, third_registries, cache_path=cache, published_limits=limits
    )
    third.resolve_many([doc_ip(193)])
    assert third_registries.calls == [doc_ip(193)]


def test_spacing_is_always_slept_even_beyond_the_inline_cap(clock: Clock) -> None:
    registries = FakeRegistries(clock)
    resolver = make_resolver(clock, registries, interval=90.0)

    resolver.resolve_many([doc_ip(1), doc_ip(33), doc_ip(65)])

    assert registries.calls == [doc_ip(1), doc_ip(33), doc_ip(65)]
    assert clock.sleeps == [90.0, 90.0]
    assert resolver.pending == 0


def test_long_retry_after_pauses_only_the_throttling_registry(
    tmp_path: Path, clock: Clock
) -> None:
    cache = tmp_path / "whois.json"
    registries = FakeRegistries(
        clock,
        {doc_ip(129): FetchResult(FETCH_REFUSED, retry_after=120.0, http_status=429)},
    )
    resolver = make_resolver(clock, registries, cache_path=cache)

    resolver.resolve_many([doc_ip(129), doc_ip(161), doc_ip(1)])
    resolver.save()

    assert registries.calls == [doc_ip(129), doc_ip(1)]
    assert resolver.describe(doc_ip(129)) == (
        f"? deferred: {SLOW_NAME} returned HTTP 429 (Retry-After 120s); retry in ~120s"
    )
    assert resolver.describe(doc_ip(161)).startswith(
        f"? deferred: {SLOW_NAME} returned HTTP 429 (Retry-After 120s); retry in ~"
    )
    assert resolver.deferred_kinds == {
        doc_ip(129): DEFER_REFUSED,
        doc_ip(161): DEFER_BACKOFF,
    }

    clock.now += 30  # ~90s of the pause left: longer than the inline cap
    later = FakeRegistries(clock)
    make_resolver(clock, later, cache_path=cache).resolve_many([doc_ip(161)])
    assert later.urls == []

    clock.now += 91  # pause over
    after = FakeRegistries(clock)
    make_resolver(clock, after, cache_path=cache).resolve_many([doc_ip(161)])
    assert after.calls == [doc_ip(161)]


def test_short_retry_after_is_slept_and_the_same_ip_retried(clock: Clock) -> None:
    registries = FakeRegistries(
        clock, {doc_ip(129): [FetchResult(FETCH_REFUSED, retry_after=5.0)]}
    )
    resolver = make_resolver(clock, registries)

    resolver.resolve_many([doc_ip(129), doc_ip(161)])

    assert registries.calls == [doc_ip(129), doc_ip(129), doc_ip(161)]
    assert resolver.lookup(doc_ip(129)) is not None
    assert resolver.pending == 0


def test_refusal_without_retry_after_backs_off_doubling_then_recovers(
    clock: Clock,
) -> None:
    refused = FetchResult(FETCH_REFUSED, http_status=429)
    registries = FakeRegistries(clock, {doc_ip(129): [refused, refused, refused]})
    resolver = make_resolver(clock, registries)

    resolver.resolve_many([doc_ip(129), doc_ip(161)])

    assert registries.calls == [doc_ip(129)] * 4 + [doc_ip(161)]
    assert [s for s in clock.sleeps if s >= 1] == pytest.approx(
        [2.0, 4.0, 8.0], abs=0.2
    )
    assert resolver.pending == 0
    state = resolver.registry_states()[SLOW_NAME]
    assert state.refusal_streak == 0  # the success reset it


def test_persistent_refusal_escalates_then_defers_with_evidence(
    tmp_path: Path, clock: Clock
) -> None:
    cache = tmp_path / "whois.json"
    registries = FakeRegistries(
        clock, {doc_ip(129): FetchResult(FETCH_REFUSED, http_status=429)}
    )
    resolver = make_resolver(clock, registries, cache_path=cache)

    resolver.resolve_many([doc_ip(129), doc_ip(161)])
    resolver.save()

    assert registries.calls == [doc_ip(129)] * MAX_ATTEMPTS_PER_IP
    backoffs = [s for s in clock.sleeps if s >= 1]
    assert backoffs == pytest.approx([2.0, 4.0, 8.0], abs=0.2)
    expected = (
        f"{SLOW_NAME} returned HTTP 429 (no Retry-After; refusal 4 in a row, "
        "backing off 16s); retry in ~16s"
    )
    assert resolver.describe(doc_ip(129)) == (
        f"? deferred: {expected} (refused all {MAX_ATTEMPTS_PER_IP} attempts this run)"
    )
    assert resolver.deferred_kinds[doc_ip(161)] == DEFER_BACKOFF
    _records, _misses, saved = read_cache_file(cache)
    assert saved[SLOW_NAME].refusal_streak == 4
    assert saved[SLOW_NAME].last_refusal is not None
    assert saved[SLOW_NAME].last_refusal["http_status"] == 429
    assert saved[SLOW_NAME].last_refusal["backoff"] == 16.0

    # The next run continues the escalation instead of restarting at 2s.
    clock.now += 20
    again = FakeRegistries(
        clock, {doc_ip(161): FetchResult(FETCH_REFUSED, http_status=429)}
    )
    next_run = make_resolver(clock, again, cache_path=cache)
    next_run.resolve_many([doc_ip(161)])
    assert again.calls == [doc_ip(161)]
    assert "refusal 5 in a row, backing off 32s" in next_run.describe(doc_ip(161))


def test_stale_refusal_streak_restarts_at_the_short_pause(
    tmp_path: Path, clock: Clock
) -> None:
    cache = tmp_path / "whois.json"
    write_cache_file(
        cache,
        {},
        {},
        {SLOW_NAME: RegistryState(SLOW_NAME, refusal_streak=9, streak_ts=clock.now)},
        now=clock.now,
    )
    clock.now += 2 * 3600
    registries = FakeRegistries(
        clock, {doc_ip(129): [FetchResult(FETCH_REFUSED, http_status=429)]}
    )
    resolver = make_resolver(clock, registries, cache_path=cache)

    resolver.resolve_many([doc_ip(129)])

    assert [s for s in clock.sleeps if s >= 1] == pytest.approx([2.0], abs=0.2)
    assert resolver.lookup(doc_ip(129)) is not None


def test_forbidden_is_a_failure_not_a_rate_limit(clock: Clock) -> None:
    forbidden = FetchResult(FETCH_FORBIDDEN, http_status=403)
    registries = FakeRegistries(
        clock, {doc_ip(octet): forbidden for octet in (129, 161, 193, 225)}
    )
    resolver = make_resolver(clock, registries)

    resolver.resolve_many(
        [doc_ip(129), doc_ip(161), doc_ip(193), doc_ip(225), doc_ip(1)]
    )

    assert registries.calls == [doc_ip(129), doc_ip(161), doc_ip(193), doc_ip(1)]
    assert resolver.describe(doc_ip(129)) == (
        f"? {SLOW_NAME} denied access (HTTP 403, no Retry-After)"
    )
    assert "after 3 failures in a row" in resolver.describe(doc_ip(225))
    state = resolver.registry_states()[SLOW_NAME]
    assert state.blocked_until == 0.0 and state.refusal_streak == 0


def test_redirected_refusal_is_charged_to_the_registry_that_sent_it(
    clock: Clock,
) -> None:
    # FAST redirects 192.0.2.5 to SLOW, and SLOW throttles it for 120s. FAST
    # did nothing wrong and keeps resolving; SLOW's own queries wait.
    redirected = FetchResult(
        FETCH_REFUSED,
        retry_after=120.0,
        http_status=429,
        final_url=SLOW + "ip/" + doc_ip(5),
    )
    registries = FakeRegistries(clock, {doc_ip(5): redirected})
    resolver = make_resolver(clock, registries)

    resolver.resolve_many([doc_ip(5), doc_ip(33), doc_ip(129)])

    assert registries.calls == [doc_ip(5), doc_ip(33)]
    states = resolver.registry_states()
    assert states[FAST_NAME].blocked_until == 0.0
    assert states[SLOW_NAME].blocked_until > clock.now
    assert resolver.describe(doc_ip(5)).startswith(f"? deferred: {SLOW_NAME} ")
    assert resolver.deferred_kinds[doc_ip(129)] == DEFER_BACKOFF
    assert resolver.lookup(doc_ip(33)) is not None


def test_redirected_answers_label_and_pace_the_answering_registry(
    clock: Clock,
) -> None:
    answer = FetchResult(
        FETCH_OK,
        block_payload(0, 31, "Redirected Org"),
        http_status=200,
        final_url=SLOW + "ip/" + doc_ip(5),
    )
    registries = FakeRegistries(clock, {doc_ip(5): answer})
    resolver = make_resolver(clock, registries)

    resolver.resolve_many([doc_ip(5)])

    record = resolver.lookup(doc_ip(5))
    assert record is not None and record.registry == SLOW_NAME
    states = resolver.registry_states()
    assert len(states[FAST_NAME].requests) == len(states[SLOW_NAME].requests) == 1


def test_consecutive_failures_pause_only_that_registry_and_are_not_cached(
    tmp_path: Path, clock: Clock
) -> None:
    failing = {
        doc_ip(octet): FetchResult(FETCH_ERROR) for octet in (129, 161, 193, 225)
    }
    registries = FakeRegistries(clock, failing)
    cache = tmp_path / "whois.json"
    resolver = make_resolver(clock, registries, cache_path=cache)

    resolver.resolve_many(
        [doc_ip(129), doc_ip(161), doc_ip(193), doc_ip(225), doc_ip(1)]
    )
    resolver.save()

    assert registries.calls == [doc_ip(129), doc_ip(161), doc_ip(193), doc_ip(1)]
    assert resolver.describe(doc_ip(129)) == f"? {SLOW_NAME} lookup failed (no answer)"
    assert "paused for this run after 3 failures in a row" in resolver.describe(
        doc_ip(225)
    )
    records, misses, _ = read_cache_file(cache)
    assert list(records) == [f"{doc_ip(0)}-{doc_ip(31)}"]
    assert misses == {}


def test_run_budget_defers_with_a_visible_reason(clock: Clock) -> None:
    registries = FakeRegistries(clock)
    resolver = make_resolver(clock, registries, max_lookups=2)

    resolver.resolve_many([doc_ip(1), doc_ip(33), doc_ip(65), doc_ip(97)])

    assert registries.calls == [doc_ip(1), doc_ip(33)]
    assert resolver.pending == 2
    assert resolver.describe(doc_ip(65)) == ("? deferred: run budget of 2 lookups used")
    note = resolver.status_note()
    assert note is not None and "2 deferred" in note and "rerun" in note


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("120", 120.0),
        ("0", 1.0),
        ("999999", MAX_BACKOFF_SECONDS),
        ("soon", None),
        (None, None),
    ],
)
def test_parse_retry_after_seconds(header: str | None, expected: float | None) -> None:
    assert parse_retry_after(header) == expected


def test_parse_retry_after_http_date() -> None:
    when = datetime(2026, 1, 1, 0, 2, 0, tzinfo=UTC)
    now = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC).timestamp()

    assert parse_retry_after(format_datetime(when, usegmt=True), now=now) == 120.0


def test_redirects_to_plain_http_are_refused() -> None:
    handler = _HttpsOnlyRedirectHandler()
    request = urllib.request.Request("https://rdap.example.test/ip/192.0.2.1")

    with pytest.raises(urllib.error.HTTPError):
        handler.redirect_request(
            request, None, 301, "Moved", {}, "http://rdap.example.test/ip/192.0.2.1"
        )
    followed = handler.redirect_request(
        request, None, 301, "Moved", {}, "https://rdap.other.test/ip/192.0.2.1"
    )
    assert followed is not None


# --- CLI wiring ---------------------------------------------------------------


def test_build_whois_resolver_honors_flags(tmp_path: Path) -> None:
    assert build_whois_resolver(audit_args(whois=False)) is None

    uncached = build_whois_resolver(audit_args(whois=True, whois_cache="none"))
    assert uncached is not None and uncached.cache_path is None

    explicit = build_whois_resolver(
        audit_args(
            whois=True,
            whois_cache=str(tmp_path / "w.json"),
            whois_max_lookups=3,
            whois_interval=2.5,
        )
    )
    assert explicit is not None
    assert explicit.cache_path == tmp_path / "w.json"
    assert explicit.max_lookups == 3
    assert explicit.interval == 2.5


def test_recent_view_prints_org_line_under_ptr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cache = tmp_path / "whois.json"
    record = WhoisRecord(
        doc_ip(0),
        doc_ip(255),
        "Synthetic Hosting LLC",
        "SYN-BLK",
        ts=time.time(),
        registry="ARIN",
    )
    write_cache_file(cache, {record.key: record}, {})
    args = audit_args(
        whois=True, whois_cache=str(cache), ptr_cache="none", reverse_dns=False
    )
    runtime = build_runtime(args)
    rows = [
        row(ts=2_000_000.0, ip=doc_ip(1), ua=CHROME_133_UA, path="/synthetic/one"),
        row(ts=2_000_001.0, ip="198.51.100.7", ua=CHROME_133_UA, path="/two"),
    ]

    print_recent_view(rows, args, runtime, bot_ips=set())
    output = capsys.readouterr().out

    assert f"  org Synthetic Hosting LLC  {doc_ip(0)}/24  SYN-BLK  [ARIN]" in output
    assert "  org -" in output


def test_recent_view_omits_org_line_when_disabled(
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = audit_args(whois=False, reverse_dns=False)
    runtime = build_runtime(args)

    print_recent_view([row(ts=2_000_000.0, ip=doc_ip(1))], args, runtime, set())

    assert " org " not in capsys.readouterr().out


class _ClosedPipe:
    """stdout whose reader went away, as when piped into `head` or a pager."""

    def write(self, _text: str) -> int:
        raise BrokenPipeError(32, "Broken pipe")

    def flush(self) -> None:
        pass


def _recent_view_with_fake_registry(
    monkeypatch: pytest.MonkeyPatch, cache: Path, clock: Clock, **overrides: object
) -> tuple[FakeRegistries, object, list[RequestRow]]:
    registries = FakeRegistries(clock)
    monkeypatch.setattr(
        audit_module,
        "build_whois_resolver",
        lambda _args: make_resolver(clock, registries, cache_path=cache, **overrides),
    )
    args = audit_args(whois=True, ptr_cache="none", reverse_dns=False)
    rows = [
        row(ts=2_000_000.0 + n, ip=doc_ip(n * 40), ua=CHROME_133_UA, path=f"/p{n}")
        for n in range(3)
    ]
    return registries, args, rows


def test_recent_view_persists_lookups_even_when_stdout_closes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clock: Clock
) -> None:
    cache = tmp_path / "whois.json"
    registries, args, rows = _recent_view_with_fake_registry(monkeypatch, cache, clock)
    runtime = build_runtime(args)
    monkeypatch.setattr(sys, "stdout", _ClosedPipe())

    with pytest.raises(BrokenPipeError):
        print_recent_view(rows, args, runtime, bot_ips=set())

    assert len(registries.urls) == 3
    records, _misses, states = read_cache_file(cache)
    assert len(records) == 3
    assert sum(len(state.requests) for state in states.values()) == 3


def test_recent_view_persists_lookups_made_before_an_interrupt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clock: Clock
) -> None:
    cache = tmp_path / "whois.json"
    calls = {"n": 0}

    def sleep_then_interrupt(seconds: float) -> None:
        calls["n"] += 1
        if calls["n"] == 2:
            raise KeyboardInterrupt
        clock.sleep(seconds)

    _registries, args, rows = _recent_view_with_fake_registry(
        monkeypatch, cache, clock, interval=1.0, sleep_fn=sleep_then_interrupt
    )
    runtime = build_runtime(args)

    with pytest.raises(KeyboardInterrupt):
        print_recent_view(rows, args, runtime, bot_ips=set())

    records, _misses, _states = read_cache_file(cache)
    assert len(records) == 2


def test_recent_view_warns_when_the_cache_cannot_be_written(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    clock: Clock,
) -> None:
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("", encoding="utf-8")
    cache = blocker / "whois.json"
    _registries, args, rows = _recent_view_with_fake_registry(monkeypatch, cache, clock)

    print_recent_view(rows, args, build_runtime(args), bot_ips=set())

    assert f"whois: could not write cache {cache}" in capsys.readouterr().err


# --- registry blocks on this client (RIPE %ERROR:201) ---------------------------


def ripe_denial_body(permanent: bool = True) -> bytes:
    span = "permanently" if permanent else "temporarily"
    return json.dumps(
        {
            "rdapConformance": ["cidr0", "rdap_level_0"],
            "notices": [{"title": "Terms and Conditions", "description": ["y" * 3000]}],
            "errorCode": 429,
            "title": "Too Many Requests",
            "description": [
                "%ERROR:201: access denied for 2001:db8::87",
                "%",
                f"% Sorry, access from your host has been {span}",
                "% denied because of a repeated excessive querying.",
            ],
        }
    ).encode()


def denial_exchange(permanent: bool = True) -> HttpExchange:
    url = SLOW + "ip/" + doc_ip(129)
    return HttpExchange(
        url=url,
        started=0.0,
        elapsed=0.0,
        status=429,
        final_url=url,
        body=ripe_denial_body(permanent),
    )


def test_ripe_access_denied_is_classified_as_a_block_not_a_throttle() -> None:
    result = classify_exchange(denial_exchange())
    assert result.status == FETCH_DENIED
    assert result.http_status == 429
    assert result.message == (
        "%ERROR:201: access denied for 2001:db8::87 Sorry, access from your host "
        "has been permanently denied because of a repeated excessive querying."
    )


def test_permanent_block_stops_all_queries_now_and_in_later_runs(
    tmp_path: Path, clock: Clock
) -> None:
    cache = tmp_path / "whois.json"
    denied = classify_exchange(denial_exchange(permanent=True))
    registries = FakeRegistries(clock, {doc_ip(129): denied})
    resolver = make_resolver(clock, registries, cache_path=cache)

    resolver.resolve_many([doc_ip(129), doc_ip(161), doc_ip(1)])
    resolver.save()

    assert registries.calls == [doc_ip(129), doc_ip(1)]  # one request, no retries
    assert resolver.deferred_kinds == {
        doc_ip(129): DEFER_DENIED,
        doc_ip(161): DEFER_DENIED,
    }
    assert "blocked this host (HTTP 429, access denied) permanently" in (
        resolver.describe(doc_ip(161))
    )

    clock.now += 30 * 86400
    later = FakeRegistries(clock)
    make_resolver(clock, later, cache_path=cache).resolve_many([doc_ip(193)])
    assert later.urls == []

    cleared = clear_denial(cache, SLOW_NAME)
    assert cleared is not None and cleared["permanent"] is True
    after = FakeRegistries(clock)
    make_resolver(clock, after, cache_path=cache).resolve_many([doc_ip(193)])
    assert after.calls == [doc_ip(193)]


def test_temporary_block_holds_until_utc_midnight(tmp_path: Path) -> None:
    clock = Clock(now=1_700_000_000.0)  # 22:13 UTC
    cache = tmp_path / "whois.json"
    denied = classify_exchange(denial_exchange(permanent=False))
    registries = FakeRegistries(clock, {doc_ip(129): denied})
    resolver = make_resolver(clock, registries, cache_path=cache)

    resolver.resolve_many([doc_ip(129)])
    resolver.save()

    midnight = next_utc_midnight(clock.now)
    assert midnight == 1_700_006_400.0
    assert "until 2023-11-15 00:00 UTC" in resolver.describe(doc_ip(129))

    clock.now = midnight - 60
    before = FakeRegistries(clock)
    make_resolver(clock, before, cache_path=cache).resolve_many([doc_ip(161)])
    assert before.urls == []

    clock.now = midnight + 1
    after = FakeRegistries(clock)
    make_resolver(clock, after, cache_path=cache).resolve_many([doc_ip(161)])
    assert after.calls == [doc_ip(161)]


def test_redirect_to_a_blocking_registry_is_not_resent_next_run(
    tmp_path: Path, clock: Clock
) -> None:
    # FAST redirects 192.0.2.5 to SLOW, which has blocked this host. The next
    # run must not send that IP through FAST again while SLOW's block holds.
    cache = tmp_path / "whois.json"
    base = classify_exchange(denial_exchange())
    redirected = FetchResult(
        base.status,
        http_status=base.http_status,
        final_url=SLOW + "ip/" + doc_ip(5),
        message=base.message,
    )
    registries = FakeRegistries(clock, {doc_ip(5): redirected})
    resolver = make_resolver(clock, registries, cache_path=cache)
    resolver.resolve_many([doc_ip(5), doc_ip(33)])
    resolver.save()

    assert registries.calls == [doc_ip(5), doc_ip(33)]
    assert resolver.registry_states()[FAST_NAME].denied is None

    clock.now += 3600
    later = FakeRegistries(clock)
    next_run = make_resolver(clock, later, cache_path=cache)
    next_run.resolve_many([doc_ip(5), doc_ip(65)])
    assert later.calls == [doc_ip(65)]
    assert next_run.deferred_kinds == {doc_ip(5): DEFER_DENIED}


# --- registrant judgement (RIPE maintainer accounts) --------------------------------


def _registrant(handle: str, name: str, kind: str) -> dict[str, object]:
    entity = vcard_entity(handle, name, ["registrant"])
    entity["vcardArray"][1].append(["kind", {}, "text", kind])
    return entity


def test_ripe_maintainer_registrants_are_never_owners() -> None:
    # Shapes recorded from RIPE RDAP: maintainer accounts are listed as
    # registrants with kind "individual" and a name equal to their handle.
    payload = network_payload(
        doc_ip(0),
        doc_ip(255),
        name="SYN-LEASE",
        entities=[
            _registrant("SYN-MNT", "SYN-MNT", "individual"),
            _registrant("synaccount", "synaccount", "individual"),
            _registrant("ORG-SYN1-RIPE", "Synthetic Servers LLC", "org"),
        ],
    )
    record = parse_rdap_network(payload, doc_ip(1), 0.0)
    assert record is not None and record.org == "Synthetic Servers LLC"
    verdicts = [c["verdict"] for c in registrant_candidates(payload)]
    assert verdicts == [
        "account (maintainer), not an owner",
        "account (maintainer), not an owner",
        "organisation",
    ]


def test_maintainer_only_registrants_fall_back_to_the_network_name() -> None:
    payload = network_payload(
        doc_ip(0),
        doc_ip(255),
        name="SYN-ISP-NET",
        entities=[
            _registrant("SYNMNT-1", "SYNMNT-1", "individual"),
            _registrant("SYN-NIC", "SYN-NIC", "individual"),
        ],
    )
    record = parse_rdap_network(payload, doc_ip(1), 0.0)
    assert record is not None and record.org is None
    assert format_whois_line(record, doc_ip(1)) == f"SYN-ISP-NET  {doc_ip(0)}/24"


def test_named_registrant_without_org_kind_is_still_an_owner() -> None:
    # ARIN-style: registrant handle differs from its name.
    payload = network_payload(
        doc_ip(0),
        doc_ip(255),
        entities=[vcard_entity("SYNH", "Synthetic Hosting LLC", ["registrant"])],
    )
    record = parse_rdap_network(payload, doc_ip(1), 0.0)
    assert record is not None and record.org == "Synthetic Hosting LLC"
