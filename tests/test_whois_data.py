"""Local registry datasets: RPSL parsing, flattening, index build, download, and
resolver integration. Fixtures mirror the shapes seen in RIPE's published dumps
(header comments, unsorted objects, continuation lines, `#` end-of-line
comments, placeholder objects for non-managed space) using documentation
address ranges only.
"""

from __future__ import annotations

import gzip
import threading
import time
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_network
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from synthetic_access import CHROME_133_UA, audit_args, doc_ip, row

from lgu.audit import build_runtime, build_whois_resolver, print_recent_view
from lgu.whois_data import (
    DatasetSpec,
    LocalDataset,
    build_index,
    download_file,
    flatten,
    index_path,
    iter_rpsl,
    load_datasets,
    main,
    nesting_by_status,
    parse_range,
    structured,
    sync_dataset,
)
from lgu.whois_lookup import (
    FetchResult,
    RdapBootstrap,
    WhoisResolver,
    read_cache_file,
)

ORGANISATIONS = """\
#
# The contents of this file are subject to
# synthetic terms
#

organisation:   ORG-SYN1-TEST
org-name:       Synthetic Hosting LLC
org-type:       LIR
source:         TEST

organisation:   ORG-SYN2-TEST
org-name:       Nested Customer GmbH
source:         TEST
"""

INETNUM = """\
#
# synthetic dump header
#

inetnum:        192.0.2.64 - 192.0.2.127
netname:        CUSTOMER-NET # comment after the value
descr:          Nested customer
                second descr line
org:            ORG-SYN2-TEST
country:        DE
status:         ASSIGNED PA
source:         TEST

inetnum:        0.0.0.0 - 255.255.255.255
netname:        IANA-BLK
status:         ALLOCATED UNSPECIFIED
source:         TEST

inetnum:        192.0.2.0 - 192.0.2.255
netname:        SYN-HOSTING
org:            ORG-SYN1-TEST
country:        NL
status:         ALLOCATED PA
source:         TEST

inetnum:        192.0.2.80 - 192.0.2.95
netname:        GL-CL#3-INNERMOST
country:        DE
status:         ASSIGNED PA
source:         TEST

inetnum:        203.0.113.0 - 203.0.113.255
netname:        NON-RIPE-NCC-MANAGED-ADDRESS-BLOCK
status:         ALLOCATED UNSPECIFIED
source:         TEST

inetnum:        198.51.100.0/25
netname:        CIDR-WRITTEN
status:         ASSIGNED PA
source:         TEST

inetnum:        not an address
netname:        BROKEN
"""

INET6NUM = """\
inet6num:       ::/0
netname:        IANA-BLK
source:         TEST

inet6num:       2001:db8::/32
netname:        SYN-V6
org:            ORG-SYN1-TEST
status:         ALLOCATED-BY-RIR # This block was actually allocated by the IANA
source:         TEST

inet6num:       2001:db8:1::/48
netname:        SYN-V6-CUSTOMER
status:         ASSIGNED
source:         TEST
"""

SPEC = DatasetSpec(
    key="syn",
    registry="SYNTHETIC RIR",
    files=(
        ("organisation", "https://dumps.example.test/syn.db.organisation.gz"),
        ("inetnum", "https://dumps.example.test/syn.db.inetnum.gz"),
        ("inet6num", "https://dumps.example.test/syn.db.inet6num.gz"),
    ),
    placeholder_netnames=frozenset({"IANA-BLK", "NON-RIPE-NCC-MANAGED-ADDRESS-BLOCK"}),
)


def write_gz(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        handle.write(text)
    return path


def dump_files(root: Path) -> dict[str, Path]:
    return {
        "organisation": write_gz(root / "org.gz", ORGANISATIONS),
        "inetnum": write_gz(root / "inetnum.gz", INETNUM),
        "inet6num": write_gz(root / "inet6num.gz", INET6NUM),
    }


@pytest.fixture
def dataset(tmp_path: Path) -> LocalDataset:
    out = tmp_path / "index.sqlite"
    build_index(SPEC, dump_files(tmp_path / "raw"), out, published=1_000_000.0)
    built = LocalDataset(out)
    yield built
    built.close()


# --- parsing --------------------------------------------------------------------


def test_iter_rpsl_handles_comments_continuations_and_first_values() -> None:
    lines = [
        "% server comment\n",
        "inetnum: 192.0.2.0 - 192.0.2.255\n",
        "descr:   first\n",
        "         continued\n",
        "+        plus continued\n",
        "descr:   second descr is ignored\n",
        "# comment line inside an object\n",
        "netname: NET\n",
        "\n",
        "\n",
        "inetnum: 198.51.100.0 - 198.51.100.255\n",
    ]
    wanted = frozenset({"inetnum", "descr", "netname"})
    objects = list(iter_rpsl(lines, wanted))

    assert objects == [
        {
            "inetnum": "192.0.2.0 - 192.0.2.255",
            "descr": "first continued plus continued",
            "netname": "NET",
        },
        {"inetnum": "198.51.100.0 - 198.51.100.255"},
    ]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("A3-PROTON-GER # 3A-PROTON-GER", "A3-PROTON-GER"),
        ("GL-CL#3-PRICE", "GL-CL"),
        (
            "ALLOCATED-BY-RIR # This block was actually allocated by the IANA",
            "ALLOCATED-BY-RIR",
        ),
        ("# only a comment", None),
        (None, None),
    ],
)
def test_structured_strips_end_of_line_comments(value, expected) -> None:
    assert structured(value) == expected


@pytest.mark.parametrize(
    ("role", "value", "expected"),
    [
        ("inetnum", "192.0.2.0 - 192.0.2.255", (4, 0xC0000200, 0xC00002FF)),
        ("inetnum", "192.0.2.0-192.0.2.15 # note", (4, 0xC0000200, 0xC000020F)),
        ("inetnum", "198.51.100.0/25", (4, 0xC6336400, 0xC633647F)),
        ("inetnum", "192.0.2.9 - 192.0.2.1", None),
        ("inetnum", "2001:db8:: - 2001:db8::1", None),
        ("inetnum", "garbage", None),
        (
            "inet6num",
            "2001:db8::/32",
            (
                6,
                int(ip_network("2001:db8::/32")[0]),
                int(ip_network("2001:db8::/32")[-1]),
            ),
        ),
        ("inet6num", "192.0.2.0/24", None),
    ],
)
def test_parse_range(role, value, expected) -> None:
    assert parse_range(role, value) == expected


# --- flattening ------------------------------------------------------------------


def _innermost(intervals: list[tuple[int, int, int]], address: int) -> int | None:
    containing = [iv for iv in intervals if iv[0] <= address <= iv[1]]
    if not containing:
        return None
    # Laminar family: the innermost has the greatest first and least last;
    # identical ranges resolve to the later one in sort order.
    order = {iv: index for index, iv in enumerate(intervals)}
    return max(containing, key=lambda iv: (iv[0], -iv[1], order[iv]))[2]


@st.composite
def laminar_families(draw) -> list[tuple[int, int, int]]:
    """Random nested-or-disjoint interval families over a small universe."""
    candidates = draw(
        st.lists(
            st.tuples(st.integers(0, 63), st.integers(0, 63)).map(sorted),
            max_size=24,
        )
    )
    kept: list[tuple[int, int]] = []
    for first, last in candidates:
        if all(
            last < a
            or first > b
            or (a <= first and last <= b)
            or (first <= a and b <= last)
            for a, b in kept
        ):
            kept.append((first, last))
    family = [(first, last, owner) for owner, (first, last) in enumerate(kept)]
    return sorted(family, key=lambda iv: (iv[0], -iv[1], iv[2]))


@settings(max_examples=300, deadline=None)
@given(laminar_families())
def test_flatten_matches_brute_force_innermost_owner(family) -> None:
    segments = list(flatten(family))

    # Disjoint, ascending, non-empty.
    for (a_first, a_last, _), (b_first, _, _) in zip(
        segments, segments[1:], strict=False
    ):
        assert a_last < b_first
    assert all(first <= last for first, last, _ in segments)

    by_address = {
        address: owner
        for first, last, owner in segments
        for address in range(first, last + 1)
    }
    for address in range(64):
        assert by_address.get(address) == _innermost(family, address)


def test_flatten_clips_partial_overlap_to_the_enclosing_range() -> None:
    family = [(0, 10, 1), (5, 20, 2)]  # 5-20 escapes 0-10: forbidden, clipped
    assert list(flatten(family)) == [(0, 4, 1), (5, 10, 2)]


# --- build and lookup --------------------------------------------------------------


def test_lookup_returns_the_most_specific_owner(dataset: LocalDataset) -> None:
    parent = dataset.lookup(doc_ip(10))
    assert parent is not None
    assert (parent.start, parent.end) == (doc_ip(0), doc_ip(255))
    assert parent.org == "Synthetic Hosting LLC" and parent.net == "SYN-HOSTING"
    assert parent.registry == "SYNTHETIC RIR" and parent.ts == 1_000_000.0

    child = dataset.lookup(doc_ip(70))
    assert child is not None and (child.start, child.end) == (doc_ip(64), doc_ip(127))
    assert child.org == "Nested Customer GmbH" and child.net == "CUSTOMER-NET"

    innermost = dataset.lookup(doc_ip(90))
    assert innermost is not None and innermost.net == "GL-CL"
    assert innermost.org is None

    # Back in the child after the innermost range, then the parent's tail.
    assert dataset.lookup(doc_ip(100)).net == "CUSTOMER-NET"
    assert dataset.lookup(doc_ip(200)).net == "SYN-HOSTING"


def test_placeholders_never_answer(dataset: LocalDataset) -> None:
    assert dataset.lookup(doc_ip(5, net=3)) is None  # NON-RIPE-NCC-MANAGED
    assert dataset.lookup("100.64.0.1") is None  # only IANA-BLK covers it
    assert dataset.lookup(doc_ip(200, net=2)) is None  # past the /25
    assert dataset.lookup(doc_ip(5, net=2)).net == "CIDR-WRITTEN"


def test_ipv6_and_mapped_ipv4(dataset: LocalDataset) -> None:
    v6 = dataset.lookup("2001:db8:1::5")
    assert v6 is not None and v6.net == "SYN-V6-CUSTOMER"
    assert (v6.start, v6.end) == ("2001:db8:1::", "2001:db8:1:ffff:ffff:ffff:ffff:ffff")
    outer = dataset.lookup("2001:db8:2::1")
    assert outer is not None and outer.org == "Synthetic Hosting LLC"
    assert dataset.lookup("2001:db9::1") is None
    mapped = dataset.lookup(f"::ffff:{doc_ip(70)}")
    assert mapped is not None and mapped.net == "CUSTOMER-NET"


def test_build_reports_counts_and_skips_unparseable(tmp_path: Path) -> None:
    out = tmp_path / "index.sqlite"
    stats = build_index(SPEC, dump_files(tmp_path / "raw"), out)

    # 7 inetnum objects: 2 placeholders and 1 broken range are dropped.
    assert stats.objects == {4: 4, 6: 2}
    assert stats.organisations == 2
    assert not out.with_name(out.name + ".building").exists()
    meta = LocalDataset(out).meta
    assert meta["objects"] == {"4": 4, "6": 2}


# --- download and sync ---------------------------------------------------------------


class _DumpServer:
    def __init__(self, files: dict[str, bytes], last_modified: float) -> None:
        self.files = files
        self.last_modified = formatdate(last_modified, usegmt=True)
        self.requests: list[tuple[str, str | None]] = []
        server = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                since = self.headers.get("If-Modified-Since")
                server.requests.append((self.path, since))
                body = server.files.get(self.path.lstrip("/"))
                if body is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                if since == server.last_modified:
                    self.send_response(304)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Last-Modified", server.last_modified)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}/"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def dump_server(tmp_path: Path):
    raw = dump_files(tmp_path / "served")
    server = _DumpServer(
        {
            name: path.read_bytes()
            for name, path in (
                ("org.gz", raw["organisation"]),
                ("inetnum.gz", raw["inetnum"]),
                ("inet6num.gz", raw["inet6num"]),
            )
        },
        last_modified=1_700_000_000.0,
    )
    yield server
    server.close()


def test_download_is_conditional_and_atomic(tmp_path: Path, dump_server) -> None:
    dest = tmp_path / "data" / "inetnum.gz"
    first = download_file(dump_server.base + "inetnum.gz", dest, role="inetnum")
    assert first.status == "downloaded" and dest.read_bytes()
    assert dump_server.requests[-1][1] is None

    again = download_file(dump_server.base + "inetnum.gz", dest, role="inetnum")
    assert again.status == "not-modified"
    assert dump_server.requests[-1][1] == dump_server.last_modified

    before = dest.read_bytes()
    with pytest.raises(Exception):
        download_file(dump_server.base + "missing.gz", dest, role="inetnum")
    assert dest.read_bytes() == before
    assert [p.name for p in dest.parent.iterdir() if p.name.startswith(".")] == []


def test_sync_builds_once_and_then_reports_current(tmp_path: Path, dump_server) -> None:
    spec = DatasetSpec(
        key="syn",
        registry="SYNTHETIC RIR",
        files=(
            ("organisation", dump_server.base + "org.gz"),
            ("inetnum", dump_server.base + "inetnum.gz"),
            ("inet6num", dump_server.base + "inet6num.gz"),
        ),
        placeholder_netnames=SPEC.placeholder_netnames,
    )
    data_dir = tmp_path / "whois-data"

    first = sync_dataset(spec, data_dir)
    assert first.built is not None and first.reason == "dumps changed"
    built = LocalDataset(index_path(data_dir, spec))
    assert built.as_of == 1_700_000_000.0  # the dumps' Last-Modified
    assert built.lookup(doc_ip(70)).org == "Nested Customer GmbH"

    second = sync_dataset(spec, data_dir)
    assert second.built is None and second.reason == "index current"
    assert {d.status for d in second.downloads} == {"not-modified"}


# --- resolver and log-audit integration ------------------------------------------------


class _Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def _resolver(
    dataset: LocalDataset, clock: _Clock, fetches: list[str], **kw
) -> WhoisResolver:
    def fetch(url: str, timeout: float) -> FetchResult:
        fetches.append(url)
        return FetchResult("not-found")

    return WhoisResolver(
        fetch_fn=fetch,
        bootstrap=RdapBootstrap([]),  # routes everything to the fallback base
        time_fn=clock.time,
        sleep_fn=clock.sleep,
        queryable_fn=lambda _ip: True,
        published_limits={},
        local_sources=[dataset],
        **kw,
    )


def test_local_dataset_answers_before_the_network(tmp_path: Path, dataset) -> None:
    clock = _Clock(1_000_000.0 + 3600)
    fetches: list[str] = []
    cache = tmp_path / "whois.json"
    resolver = _resolver(dataset, clock, fetches, cache_path=cache)

    resolver.resolve_many([doc_ip(70), doc_ip(5, net=3)])
    resolver.save()

    assert [url.rsplit("/", 1)[1] for url in fetches] == [doc_ip(5, net=3)]
    assert resolver.local_hits == 1
    assert resolver.describe(doc_ip(70)) == (
        f"Nested Customer GmbH  {doc_ip(64)}/26  CUSTOMER-NET  [SYNTHETIC RIR]"
    )
    records, _misses, _registries, answers = read_cache_file(cache)
    assert records == {} and answers == {}  # local answers are never cached


def test_old_dataset_is_still_used_without_complaint(dataset) -> None:
    # A year past the cache TTL: ownership barely moves, so the dump answers.
    clock = _Clock(1_000_000.0 + 365 * 86400)
    fetches: list[str] = []
    resolver = _resolver(dataset, clock, fetches)

    resolver.resolve_many([doc_ip(70)])

    assert fetches == [] and resolver.local_hits == 1
    assert resolver.lookup(doc_ip(70)).net == "CUSTOMER-NET"
    assert resolver.status_note() is None


def test_recent_view_hydrates_org_from_local_data_without_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import lgu.whois_data as whois_data

    data_dir = tmp_path / "whois-data"
    spec = DatasetSpec("syn", "SYNTHETIC RIR", SPEC.files, SPEC.placeholder_netnames)
    monkeypatch.setattr(whois_data, "DATASETS", {"syn": spec})
    build_index(
        spec,
        dump_files(tmp_path / "raw"),
        index_path(data_dir, spec),
        published=time.time(),
    )

    def no_network(url: str, timeout: float) -> FetchResult:
        raise AssertionError(f"network used for {url}")

    monkeypatch.setattr("lgu.whois_lookup.fetch_json", no_network)
    args = audit_args(
        whois=True,
        whois_data=str(data_dir),
        whois_cache=str(tmp_path / "whois.json"),
        ptr_cache="none",
        reverse_dns=False,
    )
    resolver = build_whois_resolver(args)
    assert resolver is not None and len(resolver._local_sources) == 1

    rows = [row(ts=2_000_000.0, ip=doc_ip(90), ua=CHROME_133_UA, path="/synthetic")]
    print_recent_view(rows, args, build_runtime(args), bot_ips=set())

    assert f"org GL-CL  {doc_ip(80)}/28  [SYNTHETIC RIR]" in capsys.readouterr().out


def test_cli_info_and_lookup(tmp_path: Path, monkeypatch, capsys) -> None:
    import lgu.whois_data as whois_data

    data_dir = tmp_path / "whois-data"
    spec = DatasetSpec("syn", "SYNTHETIC RIR", SPEC.files, SPEC.placeholder_netnames)
    monkeypatch.setattr(whois_data, "DATASETS", {"syn": spec})

    assert main(["--data-dir", str(data_dir), "info"]) == 1
    build_index(spec, dump_files(tmp_path / "raw"), index_path(data_dir, spec))
    assert len(load_datasets(data_dir)) == 1

    assert main(["--data-dir", str(data_dir), "info"]) == 0
    assert "syn (SYNTHETIC RIR)" in capsys.readouterr().out
    assert (
        main(["--data-dir", str(data_dir), "lookup", doc_ip(70), doc_ip(5, net=3)]) == 0
    )
    out = capsys.readouterr().out
    assert "Nested Customer GmbH" in out and f"{doc_ip(5, net=3)}" in out


# --- probe: crosscheck and entity inspection -------------------------------------------


def _recorded(
    ip: str, payload: dict[str, object], ts: float = 5.0
) -> dict[str, object]:
    import json

    return {
        "schema": 1,
        "ip": ip,
        "ts": ts,
        "http_status": 200,
        "answered_by": "SYNTHETIC RIR",
        "body": json.dumps(payload),
    }


def _rdap_answer(start: str, end: str, name: str, org: str | None = None):
    entities = []
    if org is not None:
        entities.append(
            {
                "handle": "ORG-SYN2-TEST",
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [["fn", {}, "text", org], ["kind", {}, "text", "org"]],
                ],
            }
        )
    entities.append(
        {
            "handle": "SYN-MNT",
            "roles": ["registrant"],
            "vcardArray": [
                "vcard",
                [["fn", {}, "text", "SYN-MNT"], ["kind", {}, "text", "individual"]],
            ],
        }
    )
    return {
        "startAddress": start,
        "endAddress": end,
        "name": name,
        "entities": entities,
        "port43": "whois.example.test",
    }


def test_offline_crosscheck_reparses_recorded_answers(dataset) -> None:
    from lgu.whois_probe import crosscheck_evidence, inspect_entities

    records = [
        _recorded(
            doc_ip(70), _rdap_answer(doc_ip(64), doc_ip(127), "STALE", None), 1.0
        ),
        _recorded(
            doc_ip(70),
            _rdap_answer(
                doc_ip(64), doc_ip(127), "CUSTOMER-NET", "Nested Customer GmbH"
            ),
            2.0,
        ),
        _recorded(doc_ip(90), _rdap_answer(doc_ip(80), doc_ip(95), "GL-CL")),
        _recorded(
            doc_ip(200),
            _rdap_answer(doc_ip(0), doc_ip(255), "SYN-HOSTING", "Other Name"),
        ),
        {"ip": doc_ip(5), "http_status": 429, "body": "{}", "ts": 1.0},
    ]

    rows = {row["ip"]: row for row in crosscheck_evidence(records, dataset)}

    assert set(rows) == {doc_ip(70), doc_ip(90), doc_ip(200)}  # latest 200s only
    assert rows[doc_ip(70)]["verdict"] == "match"
    assert rows[doc_ip(90)]["verdict"] == "match"  # maintainer ignored, org None
    assert rows[doc_ip(200)]["verdict"] == "mismatch"
    assert rows[doc_ip(200)]["differences"] == ["org"]

    (entity_row,) = inspect_entities(records, [doc_ip(90)])
    assert entity_row["org"] is None
    assert [c["verdict"] for c in entity_row["registrants"]] == [
        "account (maintainer), not an owner"
    ]


def test_live_crosscheck_compares_through_the_production_parser(dataset) -> None:
    import json

    from lgu.whois_lookup import HttpExchange
    from lgu.whois_probe import EvidenceLog, RecordingFetch, run_crosscheck

    answers = {
        doc_ip(70): _rdap_answer(
            doc_ip(64), doc_ip(127), "CUSTOMER-NET", "Nested Customer GmbH"
        ),
    }

    def exchange(url: str, timeout: float) -> HttpExchange:
        ip = url.rsplit("/ip/", 1)[1]
        if ip not in answers:
            return HttpExchange(
                url=url, started=0.0, elapsed=0.0, status=429, final_url=url
            )
        return HttpExchange(
            url=url,
            started=0.0,
            elapsed=0.0,
            status=200,
            final_url=url,
            body=json.dumps(answers[ip]).encode(),
        )

    fetch = RecordingFetch(exchange, EvidenceLog(None), "t", "crosscheck")
    clock = _Clock(0.0)
    rows = run_crosscheck(
        ips=[doc_ip(70), doc_ip(90), doc_ip(100)],
        dataset=dataset,
        fetch=fetch,
        bootstrap=RdapBootstrap([]),
        time_fn=clock.time,
        sleep_fn=clock.sleep,
    )

    assert [row["verdict"] for row in rows] == ["match", "refused"]  # stops at refusal
    assert len(fetch.records) == 2


def test_sample_addresses_are_distinct_and_resolvable(dataset) -> None:
    picked = dataset.sample_addresses(5, seed=3)
    assert len(picked) == len(set(picked)) and picked
    assert all(dataset.lookup(ip) is not None for ip in picked)


def test_nesting_by_status_counts_objects_with_registrations_inside() -> None:
    objects = [
        (4, 0, 255, "ALLOCATED PA"),  # holds the assignments below
        (4, 0, 15, "ASSIGNED PA"),
        (4, 0, 15, "ASSIGNED PA"),  # same range again: a duplicate, not a child
        (4, 16, 31, "ASSIGNED PA"),
        (4, 512, 767, "ALLOCATED PA"),  # nothing inside
        (6, 0, 255, "ASSIGNED PA"),  # versions never nest into each other
    ]

    assert nesting_by_status(objects) == {
        "ALLOCATED PA": {"objects": 2, "with_children": 1},
        "ASSIGNED PA": {"objects": 4, "with_children": 0},
    }
