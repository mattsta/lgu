from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from lgu.audit import parse_log_line, parse_request, parse_timestamp

REFERRER_PRIMARY = "https://referrer.example.test/"
REFERRER_OTHER = "https://other-referrer.example.test/"

_DOC_NETWORKS = (
    (ipaddress.ip_network("192.0.2.0/24"), 1),
    (ipaddress.ip_network("198.51.100.0/24"), 2),
    (ipaddress.ip_network("203.0.113.0/24"), 3),
)

_UA_ALIASES_BY_FAMILY = {
    "chrome": (
        "chrome_120",
        "chrome_133",
        "chrome_win_134",
        "chrome_win_135",
        "chrome_mac_135",
    ),
    "edge": ("edge_like",),
    "firefox": ("firefox_122", "firefox_150"),
    "safari": ("safari_17",),
}


@dataclass(frozen=True)
class ParsedAccessLine:
    line_number: int
    ip: str
    raw_ts: str
    ts: float
    method: str
    path: str
    status: str
    referer: str
    ua: str


@dataclass(frozen=True)
class SanitizedAccessLine:
    actor: str
    at: int | float
    ip_alias: str
    method: str
    path: str
    status: str
    referer: str
    ua: str


def sanitize_log_snippet(
    snippet: str | Iterable[str], *, name: str = "sanitized_access_log"
) -> dict[str, Any]:
    rows = list(parse_access_log_snippet(snippet))
    if not rows:
        raise ValueError("no parseable access log lines found")

    ip_sanitizer = IPSanitizer()
    path_sanitizer = PathSanitizer()
    referer_sanitizer = RefererSanitizer()
    ua_sanitizer = UserAgentSanitizer()
    actor_by_ip: dict[str, str] = {}
    first_ts = min(row.ts for row in rows)
    sanitized_rows: list[SanitizedAccessLine] = []

    for row in rows:
        actor = actor_by_ip.setdefault(row.ip, f"source_{len(actor_by_ip) + 1:02d}")
        sanitized_rows.append(
            SanitizedAccessLine(
                actor=actor,
                at=_relative_seconds(row.ts - first_ts),
                ip_alias=ip_sanitizer.sanitize(row.ip),
                method=row.method,
                path=path_sanitizer.sanitize(row.path),
                status=row.status,
                referer=referer_sanitizer.sanitize(row.referer),
                ua=ua_sanitizer.sanitize(row.ua),
            )
        )

    actor_defaults = _actor_defaults(sanitized_rows)
    actors = {
        actor: {
            "ip": defaults["ip"],
            "ua": defaults["ua"],
            "referer": defaults["referer"],
            "method": defaults["method"],
            "status": defaults["status"],
        }
        for actor, defaults in actor_defaults.items()
    }
    events = [_event_from_row(row, actor_defaults[row.actor]) for row in sanitized_rows]
    return {"name": name, "actors": actors, "events": events}


def parse_access_log_snippet(snippet: str | Iterable[str]) -> list[ParsedAccessLine]:
    lines = snippet.splitlines() if isinstance(snippet, str) else snippet
    ts_cache: dict[str, float] = {}
    rows: list[ParsedAccessLine] = []
    for line_number, line in enumerate(lines, start=1):
        parsed = parse_log_line(line)
        if parsed is None:
            continue
        ip, raw_ts, request, status, referer, ua = parsed
        ts = parse_timestamp(raw_ts, ts_cache)
        if ts is None:
            continue
        method, path = parse_request(request)
        rows.append(
            ParsedAccessLine(
                line_number=line_number,
                ip=ip,
                raw_ts=raw_ts,
                ts=ts,
                method=method,
                path=path,
                status=status,
                referer=referer,
                ua=ua,
            )
        )
    return rows


class IPSanitizer:
    def __init__(self) -> None:
        self._aliases_by_ip: dict[str, str] = {}
        self._ip_by_alias: dict[str, str] = {}

    def sanitize(self, ip: str) -> str:
        alias = self._aliases_by_ip.get(ip)
        if alias is not None:
            return alias

        preferred = _doc_alias_for_ip(ip)
        if preferred is not None and preferred not in self._ip_by_alias:
            alias = preferred
        else:
            alias = self._next_generated_alias()

        self._aliases_by_ip[ip] = alias
        self._ip_by_alias[alias] = ip
        return alias

    def _next_generated_alias(self) -> str:
        for net in (1, 2, 3):
            for octet in range(10, 250):
                alias = f"doc:{net}:{octet}"
                if alias not in self._ip_by_alias:
                    return alias
        raise ValueError("ran out of RFC 5737 documentation IP aliases")


class PathSanitizer:
    def __init__(self) -> None:
        self._base_aliases: dict[str, str] = {}
        self._query_aliases: dict[tuple[str, str], str] = {}
        self._query_counts: Counter[str] = Counter()

    def sanitize(self, request_target: str) -> str:
        base, query = _split_request_target(request_target)
        safe_base = self._base_alias(base)
        if not query:
            return safe_base

        key = (base, query)
        query_alias = self._query_aliases.get(key)
        if query_alias is None:
            query_alias = f"variant={self._query_counts[base]:02d}"
            self._query_counts[base] += 1
            self._query_aliases[key] = query_alias
        return f"{safe_base}?{query_alias}"

    def _base_alias(self, base: str) -> str:
        alias = self._base_aliases.get(base)
        if alias is not None:
            return alias

        index = len(self._base_aliases) + 1
        extension = _safe_extension(base)
        if extension:
            alias = f"/synthetic/asset-{index:02d}{extension}"
        else:
            alias = f"/synthetic/path-{index:02d}"
        self._base_aliases[base] = alias
        return alias


class RefererSanitizer:
    def __init__(self) -> None:
        self._referer_by_host: dict[str, str] = {}

    def sanitize(self, referer: str) -> str:
        if referer in {"", "-"}:
            return "-"

        try:
            parsed = urlsplit(referer)
        except ValueError:
            return REFERRER_PRIMARY

        host = (parsed.hostname or parsed.netloc or referer).lower()
        safe = self._referer_by_host.get(host)
        if safe is not None:
            return safe

        safe = REFERRER_PRIMARY if not self._referer_by_host else REFERRER_OTHER
        self._referer_by_host[host] = safe
        return safe


class UserAgentSanitizer:
    def __init__(self) -> None:
        self._aliases_by_ua: dict[str, str] = {}
        self._used_aliases: set[str] = set()
        self._unknown_count = 0

    def sanitize(self, ua: str) -> str:
        if ua in {"", "-"}:
            return "-"

        alias = self._aliases_by_ua.get(ua)
        if alias is not None:
            return alias

        alias = self._alias_for_browser_ua(ua)
        if alias is None:
            self._unknown_count += 1
            alias = f"SyntheticUA/{self._unknown_count:02d}"

        self._aliases_by_ua[ua] = alias
        self._used_aliases.add(alias)
        return alias

    def _alias_for_browser_ua(self, ua: str) -> str | None:
        family = _ua_family(ua)
        if family is None:
            return None

        preferred = _preferred_browser_alias(ua, family)
        if preferred is not None and preferred not in self._used_aliases:
            return preferred

        for alias in _UA_ALIASES_BY_FAMILY[family]:
            if alias not in self._used_aliases:
                return alias

        used_for_family = sum(
            1
            for alias in self._used_aliases
            if alias.startswith(f"synthetic_{family}_")
        )
        return f"synthetic_{family}_{used_for_family + 1:02d}"


def _actor_defaults(rows: Sequence[SanitizedAccessLine]) -> dict[str, dict[str, str]]:
    rows_by_actor: dict[str, list[SanitizedAccessLine]] = {}
    for row in rows:
        rows_by_actor.setdefault(row.actor, []).append(row)

    defaults: dict[str, dict[str, str]] = {}
    for actor, actor_rows in rows_by_actor.items():
        defaults[actor] = {
            "ip": actor_rows[0].ip_alias,
            "ua": _most_common(row.ua for row in actor_rows),
            "referer": _most_common(row.referer for row in actor_rows),
            "method": _most_common(row.method for row in actor_rows),
            "status": _most_common(row.status for row in actor_rows),
        }
    return defaults


def _event_from_row(
    row: SanitizedAccessLine, defaults: dict[str, str]
) -> dict[str, str | int | float]:
    event: dict[str, str | int | float] = {
        "actor": row.actor,
        "at": row.at,
        "path": row.path,
    }
    for field in ("ua", "referer", "method", "status"):
        value = getattr(row, field)
        if value != defaults[field]:
            event[field] = value
    return event


def _most_common(values: Iterable[str]) -> str:
    counts: Counter[str] = Counter()
    first_seen: dict[str, int] = {}
    for index, value in enumerate(values):
        counts[value] += 1
        first_seen.setdefault(value, index)
    return max(counts, key=lambda value: (counts[value], -first_seen[value]))


def _doc_alias_for_ip(ip: str) -> str | None:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if address.version != 4:
        return None

    for network, net in _DOC_NETWORKS:
        if address in network:
            octet = int(address) - int(network.network_address)
            return f"doc:{net}:{octet}"
    return None


def _split_request_target(request_target: str) -> tuple[str, str]:
    try:
        parsed = urlsplit(request_target)
    except ValueError:
        return request_target or "/", ""

    if parsed.scheme or parsed.netloc:
        return parsed.path or "/", parsed.query

    base, separator, query = request_target.partition("?")
    if not separator:
        return base or "/", ""
    return base or "/", query


def _safe_extension(base: str) -> str:
    leaf = base.rsplit("/", 1)[-1]
    match = re.search(r"(\.[A-Za-z0-9]{1,8})$", leaf)
    if not match:
        return ""
    return match.group(1).lower()


def _relative_seconds(delta: float) -> int | float:
    rounded = round(delta, 6)
    if rounded.is_integer():
        return int(rounded)
    return rounded


def _ua_family(ua: str) -> str | None:
    lowered = ua.lower()
    if "firefox/" in lowered:
        return "firefox"
    if "edg/" in lowered or "edge/" in lowered:
        return "edge"
    if "chrome/" in lowered or "crios/" in lowered:
        return "chrome"
    if "safari/" in lowered:
        return "safari"
    return None


def _preferred_browser_alias(ua: str, family: str) -> str | None:
    if family == "chrome":
        if "windows nt" in ua.lower() and "Chrome/134." in ua:
            return "chrome_win_134"
        if "windows nt" in ua.lower() and "Chrome/135." in ua:
            return "chrome_win_135"
        if "macintosh" in ua.lower() and "Chrome/135." in ua:
            return "chrome_mac_135"
        if "Chrome/120." in ua or "CriOS/120." in ua:
            return "chrome_120"
        if "Chrome/133." in ua or "CriOS/133." in ua:
            return "chrome_133"
    if family == "edge":
        return "edge_like"
    if family == "firefox":
        if "Firefox/150." in ua:
            return "firefox_150"
        if "Firefox/122." in ua:
            return "firefox_122"
    if family == "safari" and "Version/17." in ua:
        return "safari_17"
    return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sanitize a small access-log snippet into draft scenario JSON."
    )
    parser.add_argument(
        "input",
        nargs="?",
        type=Path,
        help="Access-log snippet path. Reads stdin when omitted.",
    )
    parser.add_argument(
        "--name",
        default="sanitized_access_log",
        help="Scenario name to place in the emitted draft.",
    )
    parser.add_argument(
        "--wrap",
        action="store_true",
        help="Emit {'scenarios': [...]} instead of a single scenario object.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.input is None:
        text = sys.stdin.read()
    else:
        text = args.input.read_text(encoding="utf-8", errors="replace")

    scenario = sanitize_log_snippet(text, name=args.name)
    output: dict[str, Any] = {"scenarios": [scenario]} if args.wrap else scenario
    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
