from __future__ import annotations

from collections.abc import Iterable

from lgu.audit import (
    DetectorConfig,
    RequestRow,
    build_parser,
    build_runtime,
    detect_behavioral_bots,
)
from lgu.watch import build_parser as build_watch_parser

DOC_NET_PREFIXES = {
    1: "192.0.2",
    2: "198.51.100",
    3: "203.0.113",
}

CHROME_120_UA = "Mozilla/5.0 Chrome/120.0 Safari/537.36"
CHROME_133_UA = "Mozilla/5.0 Chrome/133.0 Safari/537.36"
FIREFOX_122_UA = "Mozilla/5.0 Firefox/122.0"
FIREFOX_150_UA = "Mozilla/5.0 Firefox/150.0"
SAFARI_17_UA = "Mozilla/5.0 Version/17.0 Safari/605.1.15"
EDGE_LIKE_UA = "Mozilla/5.0 Chrome/121.0 Safari/537.36 Edg/121.0"
BOT_UA = "SyntheticFetcher/2.0.0"
SHARED_UA = "SharedSyntheticUA/1.0"

CHROME_WIN_134_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
)
CHROME_WIN_135_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
)
CHROME_MAC_135_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
)

REFERRER = "https://referrer.example.test/"
ALT_REFERRER = "https://other-referrer.example.test/"
JUNK_REFERRER = "https://referrer.example.test/search?q=%27%22%27%22"
RAW_TS = "08/Apr/2026:02:30:52 +0000"


def doc_ip(octet: int, net: int = 1) -> str:
    # RFC 5737 documentation ranges: never use routable production IPs in tests.
    return f"{DOC_NET_PREFIXES[net]}.{octet}"


def audit_args(**overrides):
    parser = build_parser()
    args = parser.parse_args([])
    args.detector_config = overrides.pop("detector_config", DetectorConfig())
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


def watch_args(**overrides):
    parser = build_watch_parser()
    args = parser.parse_args([])
    args.detector_config = overrides.pop("detector_config", DetectorConfig())
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


def row(
    ts: float,
    ip: str | None = None,
    path: str = "/synthetic/content",
    ua: str = CHROME_120_UA,
    referer: str = "-",
    method: str = "GET",
    status: str = "200",
    raw_ts: str = RAW_TS,
) -> RequestRow:
    return RequestRow(
        raw_ts=raw_ts,
        ts=ts,
        ip=ip or doc_ip(1),
        method=method,
        path=path,
        status=status,
        referer=referer,
        ua=ua,
        input_index=0,
        line_start=0,
        line_len=0,
    )


def rows_for_paths(
    paths: Iterable[str],
    *,
    start: float = 0.0,
    step: float = 1.0,
    ip: str | None = None,
    ua: str = CHROME_120_UA,
    referer: str = "-",
    method: str = "GET",
) -> list[RequestRow]:
    return [
        row(
            ts=start + index * step,
            ip=ip,
            path=path,
            ua=ua,
            referer=referer,
            method=method,
        )
        for index, path in enumerate(paths)
    ]


def synthetic_paths(prefix: str, count: int) -> list[str]:
    return [f"/synthetic/{prefix}-{index:02d}" for index in range(count)]


def access_line(
    *,
    ip: str,
    ts: str,
    path: str,
    referer: str = "-",
    ua: str = CHROME_120_UA,
    method: str = "GET",
    status: str = "200",
) -> str:
    return (
        f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} 123 "{referer}" "{ua}"\n'
    )


def proof_kinds(rows: list[RequestRow], args=None) -> list[str]:
    args = args or audit_args()
    runtime = build_runtime(args)
    forced = detect_behavioral_bots({rows[0].ip: rows}, args, runtime)
    return [proof.kind for proof in forced.get(rows[0].ip, [])]
