#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import heapq
import json
import os
import re
import sys
import tempfile
from collections import Counter, deque
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import TextIO
from urllib.parse import urlparse

try:
    from .detector_catalog import STRONG_PROOF_KINDS
    from .provider_ranges import (
        ProviderMatch,
        ProviderRangeLookup,
        provider_label,
        provider_source_names,
    )
except ImportError:  # pragma: no cover - supports direct script execution.
    from detector_catalog import STRONG_PROOF_KINDS
    from provider_ranges import (
        ProviderMatch,
        ProviderRangeLookup,
        provider_label,
        provider_source_names,
    )

REQUEST_RE = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+HTTP/\d(?:\.\d)?)?$")
INJECTION_RE = re.compile(
    r"union(?:%20|\+|\s)+all(?:%20|\+|\s)+select|"
    r"xp_cmdshell|"
    r"%3cscript%3e|<script>|"
    r"information_schema|"
    r"%2f%2a%2a%2f|/\*\*/|"
    r"(?:\?|&)[A-Za-z]{4}=\d{3,6}(?:%20|\+|\s)+and(?:%20|\+|\s)+1=1",
    re.IGNORECASE,
)
REFERER_JUNK_RE = re.compile(r"['\"(),]{4,}|<[\"']|%27|%22", re.IGNORECASE)
EXPOSURE_REPOSITORY_SEGMENTS = frozenset((".git", ".svn", ".hg", ".bzr"))
EXPOSURE_REPOSITORY_LEAVES = frozenset(
    ("head", "config", "entries", "hgrc", "packed-refs", "index")
)
EXPOSURE_CONFIG_LEAVES = frozenset(
    (
        ".env",
        ".env.local",
        ".env.production",
        "wp-config.php",
        "web.config",
        "phpinfo.php",
        "server-status",
    )
)
EXPOSURE_DISCOVERY_LEAVES = frozenset(("security.txt",))
PAGE_DEPENDENCY_LEAVES = frozenset(
    ("js", "style", "css", "favicon.ico", "app.js", "app.css")
)
PAGE_DEPENDENCY_SUFFIXES = (
    ".css",
    ".js",
    ".mjs",
    ".ico",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".woff",
    ".woff2",
)
DEFAULT_DETECTOR_CONFIG_PATH = (
    Path(__file__).resolve().parents[2] / "defaults" / "detector-config.json"
)
PACKAGE_DETECTOR_CONFIG_PATH = "defaults/detector-config.json"


MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


@dataclass(slots=True)
class Event:
    ts: float
    path: str
    method: str
    referer: str


@dataclass(slots=True)
class RequestRow:
    raw_ts: str
    ts: float
    ip: str
    method: str
    path: str
    status: str
    referer: str
    ua: str
    input_index: int
    line_start: int
    line_len: int


@dataclass(slots=True)
class ForcedProof:
    kind: str
    detail: str


@dataclass(slots=True)
class AnalysisResult:
    ip_stats: dict[str, IPStats]
    parsed_lines: int
    matched_lines: int
    rows: list[RequestRow]
    rows_by_ip: dict[str, list[RequestRow]]


@dataclass(slots=True)
class CampaignSummary:
    family: str
    request_count: int
    unique_ips: int
    unique_paths: int
    first_ts: float
    last_ts: float
    sample_paths: tuple[str, ...]
    sample_ips: tuple[str, ...]


@dataclass(slots=True)
class PayloadCampaignAnalysis:
    forced_proofs_by_ip: dict[str, list[ForcedProof]]
    summaries: list[CampaignSummary]
    degraded: bool = False
    degraded_reason: str = ""


@dataclass(slots=True)
class DetectorConfig:
    known_bot_any_patterns: tuple[str, ...] = ()
    known_bot_ua_patterns: tuple[str, ...] = ()
    known_bot_referer_patterns: tuple[str, ...] = ()
    payload_marker_patterns: tuple[str, ...] = ()


@dataclass(slots=True)
class AuditRuntime:
    detector_config: DetectorConfig
    known_bot_any_pattern: re.Pattern[str] | None
    known_bot_ua_pattern: re.Pattern[str] | None
    known_bot_referer_pattern: re.Pattern[str] | None
    payload_marker_patterns: tuple[str, ...]
    provider_lookup: ProviderRangeLookup | None = None
    known_bot_cache: dict[tuple[str, str], bool] = field(default_factory=dict)


@dataclass(slots=True)
class CoordinatedUAAnalysis:
    forced_proofs_by_ip: dict[str, list[ForcedProof]]
    degraded: bool = False
    degraded_reason: str = ""


@dataclass(slots=True)
class HeuristicAssessment:
    score: float
    reasons: tuple[str, ...]


@dataclass(slots=True)
class DecisionEvaluation:
    action: str
    heuristic: HeuristicAssessment
    proofs: tuple[ForcedProof, ...]


@dataclass(slots=True)
class ParseTask:
    path: str
    start: int
    end: int
    include_patterns: list[str]
    exclude_patterns: list[str]
    include_fast_tokens: list[bytes]


@dataclass(slots=True)
class ParseChunkResult:
    parsed_lines: int
    matched_lines: int
    rows: list[RequestRow]


@dataclass(slots=True)
class IPStats:
    ip: str
    total: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    methods: Counter[str] = field(default_factory=Counter)
    statuses: Counter[str] = field(default_factory=Counter)
    user_agents: Counter[str] = field(default_factory=Counter)
    referers: Counter[str] = field(default_factory=Counter)
    total_paths_seen: set[str] = field(default_factory=set)
    window: deque[Event] = field(default_factory=deque)
    window_path_counts: Counter[str] = field(default_factory=Counter)
    window_heads: int = 0
    max_burst: int = 0
    max_unique_paths_window: int = 0
    max_heads_window: int = 0
    sweep_window: deque[Event] = field(default_factory=deque)
    sweep_window_path_counts: Counter[str] = field(default_factory=Counter)
    sweep_window_referers: Counter[str] = field(default_factory=Counter)
    max_paced_sweep: int = 0
    max_paced_sweep_unique_paths: int = 0
    max_paced_sweep_dominant_referer_ratio: float = 0.0
    small_gap_streak: int = 1
    max_small_gap_streak: int = 1
    last_path: str | None = None
    prev_ts: float | None = None
    matched_known_bot: bool = False

    def score(self, args: argparse.Namespace) -> float:
        score = 0.0
        if self.matched_known_bot:
            score += 100.0
        score += max(0, self.max_burst - args.burst_count + 1) * 4.0
        score += max(0, self.max_unique_paths_window - args.unique_paths + 1) * 3.0
        score += max(0, self.max_heads_window - args.head_burst + 1) * 2.5
        score += max(0, self.max_paced_sweep - args.sweep_count + 1) * 2.0
        score += max(0, self.max_small_gap_streak - args.streak_count + 1) * 1.0
        if self.total:
            unique_ratio = len(self.total_paths_seen) / self.total
            if unique_ratio > 0.7:
                score += unique_ratio * 5.0
            head_ratio = self.methods["HEAD"] / self.total
            score += head_ratio * 8.0
        return score

    def is_bot(self, args: argparse.Namespace) -> bool:
        if self.matched_known_bot:
            return True
        if (
            self.max_burst >= args.burst_count
            and self.max_unique_paths_window >= args.unique_paths
        ):
            return True
        if (
            self.max_heads_window >= args.head_burst
            and self.max_unique_paths_window >= args.head_unique_paths
        ):
            return True
        if (
            self.max_paced_sweep >= args.sweep_count
            and self.max_paced_sweep_unique_paths >= args.sweep_unique_paths
            and self.max_paced_sweep_dominant_referer_ratio
            >= args.sweep_dominant_referer_ratio
        ):
            return True
        return bool(
            self.max_small_gap_streak >= args.streak_count
            and len(self.total_paths_seen) >= args.streak_unique_total
        )


def parse_timestamp(raw: str, cache: dict[str, float]) -> float | None:
    try:
        cache_key = raw[:11] + raw[21:26]
        midnight = cache.get(cache_key)
        if midnight is None:
            midnight = datetime.strptime(
                f"{raw[:11]} {raw[21:26]}", "%d/%b/%Y %z"
            ).timestamp()
            cache[cache_key] = midnight
        hour = int(raw[12:14])
        minute = int(raw[15:17])
        second = int(raw[18:20])
        return midnight + hour * 3600 + minute * 60 + second
    except (KeyError, ValueError, IndexError):
        return None


def parse_request(raw: str) -> tuple[str, str]:
    match = REQUEST_RE.match(raw)
    if not match:
        return "-", raw.strip() or "-"
    return match.group("method"), match.group("path")


def line_matches(
    path: str, include: list[re.Pattern[str]], exclude: list[re.Pattern[str]]
) -> bool:
    if include and not any(p.search(path) for p in include):
        return False
    return not (exclude and any(p.search(path) for p in exclude))


def compile_patterns(patterns: list[str]) -> list[re.Pattern[str]]:
    return [re.compile(pattern) for pattern in patterns]


def require_pattern_list(
    source: str | Path, data: object, field: str
) -> tuple[str, ...]:
    if data is None:
        return ()
    if not isinstance(data, list) or not all(
        isinstance(pattern, str) for pattern in data
    ):
        raise ValueError(f"{source}: expected {field} to be a list of regex strings")
    return tuple(data)


def detector_config_from_mapping(source: str | Path, data: object) -> DetectorConfig:
    if not isinstance(data, dict):
        raise ValueError(f"{source}: expected top-level detector config object")
    return DetectorConfig(
        known_bot_any_patterns=require_pattern_list(
            source, data.get("known_bot_any_patterns"), "known_bot_any_patterns"
        ),
        known_bot_ua_patterns=require_pattern_list(
            source, data.get("known_bot_ua_patterns"), "known_bot_ua_patterns"
        ),
        known_bot_referer_patterns=require_pattern_list(
            source,
            data.get("known_bot_referer_patterns"),
            "known_bot_referer_patterns",
        ),
        payload_marker_patterns=require_pattern_list(
            source, data.get("payload_marker_patterns"), "payload_marker_patterns"
        ),
    )


def load_detector_config(path: Path) -> DetectorConfig:
    return detector_config_from_mapping(
        path,
        json.loads(path.read_text(encoding="utf-8")),
    )


def load_default_detector_config() -> DetectorConfig | None:
    if DEFAULT_DETECTOR_CONFIG_PATH.exists():
        return load_detector_config(DEFAULT_DETECTOR_CONFIG_PATH)
    resource = files("lgu").joinpath(PACKAGE_DETECTOR_CONFIG_PATH)
    if not resource.is_file():
        return None
    return detector_config_from_mapping(
        f"lgu/{PACKAGE_DETECTOR_CONFIG_PATH}",
        json.loads(resource.read_text(encoding="utf-8")),
    )


def merge_detector_configs(configs: list[DetectorConfig]) -> DetectorConfig:
    merged_known_bot_any_patterns: list[str] = []
    merged_known_bot_ua_patterns: list[str] = []
    merged_known_bot_referer_patterns: list[str] = []
    merged_payload_marker_patterns: list[str] = []
    for config in configs:
        merged_known_bot_any_patterns.extend(config.known_bot_any_patterns)
        merged_known_bot_ua_patterns.extend(config.known_bot_ua_patterns)
        merged_known_bot_referer_patterns.extend(config.known_bot_referer_patterns)
        merged_payload_marker_patterns.extend(config.payload_marker_patterns)
    return DetectorConfig(
        known_bot_any_patterns=tuple(merged_known_bot_any_patterns),
        known_bot_ua_patterns=tuple(merged_known_bot_ua_patterns),
        known_bot_referer_patterns=tuple(merged_known_bot_referer_patterns),
        payload_marker_patterns=tuple(merged_payload_marker_patterns),
    )


def resolve_detector_config(args: argparse.Namespace) -> DetectorConfig:
    configs: list[DetectorConfig] = []
    if not args.no_default_detector_config:
        if default_config := load_default_detector_config():
            configs.append(default_config)
    for config_path in args.detector_config:
        configs.append(load_detector_config(Path(config_path)))
    return merge_detector_configs(configs)


def build_runtime(args: argparse.Namespace) -> AuditRuntime:
    provider_lookup = None
    provider_ranges = getattr(args, "provider_ranges", ())
    if provider_ranges:
        provider_lookup = ProviderRangeLookup.from_paths(
            provider_ranges,
            source_format=getattr(args, "provider_source_format", "auto"),
            provider_include=getattr(args, "provider_include", ()),
            provider_exclude=getattr(args, "provider_exclude", ()),
        )
    runtime = AuditRuntime(
        detector_config=args.detector_config,
        known_bot_any_pattern=compiled_regex_union(
            args.detector_config.known_bot_any_patterns + tuple(args.bot_pattern)
        ),
        known_bot_ua_pattern=compiled_regex_union(
            args.detector_config.known_bot_ua_patterns
        ),
        known_bot_referer_pattern=compiled_regex_union(
            args.detector_config.known_bot_referer_patterns
        ),
        payload_marker_patterns=args.detector_config.payload_marker_patterns,
        provider_lookup=provider_lookup,
    )
    has_payload_marker.cache_clear()
    has_payload_marker_mutation.cache_clear()
    payload_family.cache_clear()
    payload_campaign_key.cache_clear()
    return runtime


def extract_fast_tokens(patterns: list[str]) -> list[bytes]:
    tokens: set[bytes] = set()
    for pattern in patterns:
        for token in re.findall(r"[A-Za-z0-9._/-]{4,}", pattern):
            if token in {"HTTP", "https", "http"}:
                continue
            tokens.add(token.encode("utf-8"))
    return sorted(tokens)


def iter_lines(handle: TextIO) -> Iterator[str]:
    yield from handle


def parse_log_line(line: str) -> tuple[str, str, str, str, str, str] | None:
    parts = line.rstrip("\n").split('"')
    if len(parts) < 6:
        return None

    prefix = parts[0]
    request = parts[1]
    trailer = parts[2].strip()
    referer = parts[3]
    ua = parts[5]

    ip_end = prefix.find(" ")
    ts_start = prefix.find("[")
    ts_end = prefix.rfind("]")
    if ip_end <= 0 or ts_start < 0 or ts_end <= ts_start:
        return None

    ip = prefix[:ip_end]
    ts = prefix[ts_start + 1 : ts_end]
    status = trailer.split(" ", 1)[0] if trailer else "-"
    return ip, ts, request, status, referer, ua


def spool_input(source: str | None) -> tuple[Path, bool]:
    if source:
        return Path(source), False

    with tempfile.NamedTemporaryFile(
        "w+", delete=False, encoding="utf-8", errors="replace"
    ) as tmp:
        for line in sys.stdin:
            tmp.write(line)
        tmp_path = Path(tmp.name)
    return tmp_path, True


def matches_known_bot(
    ua: str,
    referer: str,
    any_pattern: re.Pattern[str] | None,
    ua_pattern: re.Pattern[str] | None,
    referer_pattern: re.Pattern[str] | None,
) -> bool:
    return bool(
        (any_pattern and (any_pattern.search(ua) or any_pattern.search(referer)))
        or (ua_pattern and ua_pattern.search(ua))
        or (referer_pattern and referer_pattern.search(referer))
    )


def matches_known_bot_cached(
    ua: str,
    referer: str,
    any_pattern: re.Pattern[str] | None,
    ua_pattern: re.Pattern[str] | None,
    referer_pattern: re.Pattern[str] | None,
    cache: dict[tuple[str, str], bool],
) -> bool:
    key = (ua, referer)
    cached = cache.get(key)
    if cached is not None:
        return cached
    matched = matches_known_bot(ua, referer, any_pattern, ua_pattern, referer_pattern)
    cache[key] = matched
    return matched


@lru_cache(maxsize=256)
def compiled_regex_union(patterns: tuple[str, ...]) -> re.Pattern[str] | None:
    if not patterns:
        return None
    return re.compile("|".join(f"(?:{pattern})" for pattern in patterns), re.IGNORECASE)


@lru_cache(maxsize=1)
def process_pool_available() -> bool:
    try:
        with ProcessPoolExecutor(max_workers=1) as executor:
            future = executor.submit(int, 1)
            return future.result() == 1
    except (PermissionError, OSError):
        return False


def parse_chunk(task: ParseTask) -> ParseChunkResult:
    include = compile_patterns(task.include_patterns)
    exclude = compile_patterns(task.exclude_patterns)
    ts_cache: dict[str, float] = {}
    parsed = 0
    matched = 0
    rows: list[RequestRow] = []

    with Path(task.path).open("rb") as handle:
        if task.start > 0:
            handle.seek(task.start - 1)
            handle.readline()
        else:
            handle.seek(0)

        while True:
            line_start = handle.tell()
            if task.end >= 0 and line_start > task.end:
                break
            raw = handle.readline()
            if not raw:
                break
            if task.include_fast_tokens and not any(
                token in raw for token in task.include_fast_tokens
            ):
                continue
            line = raw.decode("utf-8", errors="replace")
            parsed_line = parse_log_line(line)
            if parsed_line is None:
                continue
            parsed += 1
            ip, raw_ts, request, status, referer, ua = parsed_line
            ts = parse_timestamp(raw_ts, ts_cache)
            if ts is None:
                continue
            method, req_path = parse_request(request)
            if not line_matches(req_path, include, exclude):
                continue
            matched += 1
            rows.append(
                RequestRow(
                    raw_ts=raw_ts,
                    ts=ts,
                    ip=ip,
                    method=method,
                    path=req_path,
                    status=status,
                    referer=referer,
                    ua=ua,
                    input_index=matched,
                    line_start=line_start,
                    line_len=len(raw),
                )
            )

    return ParseChunkResult(parsed_lines=parsed, matched_lines=matched, rows=rows)


def canonicalize_rows(rows: list[RequestRow]) -> None:
    ip_pool: dict[str, str] = {}
    method_pool: dict[str, str] = {}
    path_pool: dict[str, str] = {}
    status_pool: dict[str, str] = {}
    referer_pool: dict[str, str] = {}
    ua_pool: dict[str, str] = {}
    ts_pool: dict[str, str] = {}

    for row in rows:
        row.ip = ip_pool.setdefault(row.ip, row.ip)
        row.method = method_pool.setdefault(row.method, row.method)
        row.path = path_pool.setdefault(row.path, row.path)
        row.status = status_pool.setdefault(row.status, row.status)
        row.referer = referer_pool.setdefault(row.referer, row.referer)
        row.ua = ua_pool.setdefault(row.ua, row.ua)
        row.raw_ts = ts_pool.setdefault(row.raw_ts, row.raw_ts)


def assign_input_indices(rows: list[RequestRow]) -> None:
    ordered = sorted(rows, key=lambda row: (row.line_start, row.line_len, row.ip))
    for index, row in enumerate(ordered, start=1):
        row.input_index = index


def update_stats(
    stats: IPStats,
    ts: float,
    path: str,
    method: str,
    status: str,
    referer: str,
    ua: str,
    known_bot_any_pattern: re.Pattern[str] | None,
    known_bot_ua_pattern: re.Pattern[str] | None,
    known_bot_referer_pattern: re.Pattern[str] | None,
    known_bot_cache: dict[tuple[str, str], bool],
    args: argparse.Namespace,
) -> None:
    stats.total += 1
    stats.first_ts = ts if stats.first_ts is None else stats.first_ts
    stats.methods[method] += 1
    stats.statuses[status] += 1
    stats.user_agents[ua] += 1
    stats.referers[referer] += 1
    stats.total_paths_seen.add(path)
    stats.matched_known_bot = stats.matched_known_bot or matches_known_bot_cached(
        ua,
        referer,
        known_bot_any_pattern,
        known_bot_ua_pattern,
        known_bot_referer_pattern,
        known_bot_cache,
    )

    if (
        stats.prev_ts is not None
        and (ts - stats.prev_ts) <= args.streak_gap
        and stats.last_path != path
    ):
        stats.small_gap_streak += 1
    else:
        stats.small_gap_streak = 1
    stats.max_small_gap_streak = max(stats.max_small_gap_streak, stats.small_gap_streak)
    stats.prev_ts = ts
    stats.last_ts = ts
    stats.last_path = path

    stats.window.append(Event(ts=ts, path=path, method=method, referer=referer))
    stats.window_path_counts[path] += 1
    if method == "HEAD":
        stats.window_heads += 1

    cutoff = ts - args.window_seconds
    while stats.window and stats.window[0].ts < cutoff:
        expired = stats.window.popleft()
        stats.window_path_counts[expired.path] -= 1
        if stats.window_path_counts[expired.path] <= 0:
            del stats.window_path_counts[expired.path]
        if expired.method == "HEAD":
            stats.window_heads -= 1

    stats.max_burst = max(stats.max_burst, len(stats.window))
    stats.max_unique_paths_window = max(
        stats.max_unique_paths_window, len(stats.window_path_counts)
    )
    stats.max_heads_window = max(stats.max_heads_window, stats.window_heads)

    stats.sweep_window.append(Event(ts=ts, path=path, method=method, referer=referer))
    stats.sweep_window_path_counts[path] += 1
    stats.sweep_window_referers[referer] += 1

    sweep_cutoff = ts - args.sweep_window_seconds
    while stats.sweep_window and stats.sweep_window[0].ts < sweep_cutoff:
        expired = stats.sweep_window.popleft()
        stats.sweep_window_path_counts[expired.path] -= 1
        if stats.sweep_window_path_counts[expired.path] <= 0:
            del stats.sweep_window_path_counts[expired.path]
        stats.sweep_window_referers[expired.referer] -= 1
        if stats.sweep_window_referers[expired.referer] <= 0:
            del stats.sweep_window_referers[expired.referer]

    sweep_len = len(stats.sweep_window)
    if sweep_len:
        dominant_referer_ratio = max(stats.sweep_window_referers.values()) / sweep_len
        unique_paths = len(stats.sweep_window_path_counts)
        if sweep_len > stats.max_paced_sweep:
            stats.max_paced_sweep = sweep_len
            stats.max_paced_sweep_unique_paths = unique_paths
            stats.max_paced_sweep_dominant_referer_ratio = dominant_referer_ratio
        elif sweep_len == stats.max_paced_sweep:
            stats.max_paced_sweep_unique_paths = max(
                stats.max_paced_sweep_unique_paths, unique_paths
            )
            stats.max_paced_sweep_dominant_referer_ratio = max(
                stats.max_paced_sweep_dominant_referer_ratio,
                dominant_referer_ratio,
            )


def top_counter(
    counter: Counter[str], limit: int = 3, skip: Iterable[str] = ("-",)
) -> str:
    values = []
    for key, count in counter.most_common():
        if key in skip:
            continue
        label = key
        if len(label) > 60:
            label = label[:57] + "..."
        values.append(f"{label} ({count})")
        if len(values) >= limit:
            break
    return ", ".join(values) or "-"


def dominant_referer_share(rows: list[RequestRow]) -> float:
    if not rows:
        return 0.0
    return max(Counter(row.referer for row in rows).values()) / len(rows)


def dedupe_proofs(proofs: list[ForcedProof]) -> list[ForcedProof]:
    seen: set[tuple[str, str]] = set()
    result: list[ForcedProof] = []
    for proof in proofs:
        key = (proof.kind, proof.detail)
        if key in seen:
            continue
        seen.add(key)
        result.append(proof)
    return result


def summarize_reasons(stats: IPStats, args: argparse.Namespace) -> str:
    reasons: list[str] = []
    if stats.matched_known_bot:
        reasons.append("known-ua-or-referer")
    if (
        stats.max_burst >= args.burst_count
        and stats.max_unique_paths_window >= args.unique_paths
    ):
        reasons.append(
            f"burst={stats.max_burst}/{args.window_seconds:.1f}s unique={stats.max_unique_paths_window}"
        )
    if (
        stats.max_heads_window >= args.head_burst
        and stats.max_unique_paths_window >= args.head_unique_paths
    ):
        reasons.append(f"head-burst={stats.max_heads_window}")
    if (
        stats.max_paced_sweep >= args.sweep_count
        and stats.max_paced_sweep_unique_paths >= args.sweep_unique_paths
        and stats.max_paced_sweep_dominant_referer_ratio
        >= args.sweep_dominant_referer_ratio
    ):
        reasons.append(
            f"paced-sweep={stats.max_paced_sweep}/{args.sweep_window_seconds:.0f}s"
            f" unique={stats.max_paced_sweep_unique_paths}"
            f" ref-dom={stats.max_paced_sweep_dominant_referer_ratio:.0%}"
        )
    if (
        stats.max_small_gap_streak >= args.streak_count
        and len(stats.total_paths_seen) >= args.streak_unique_total
    ):
        reasons.append(f"fast-streak={stats.max_small_gap_streak}")
    return ",".join(reasons) or "-"


def evaluate_ip_decision(
    stats: IPStats, proofs: list[ForcedProof], args: argparse.Namespace
) -> DecisionEvaluation:
    proof_kinds = tuple(dict.fromkeys(proof.kind for proof in proofs))
    reasons: list[str] = []
    stat_reasons = summarize_reasons(stats, args)
    if stat_reasons != "-":
        reasons.extend(stat_reasons.split(","))
    reasons.extend(kind for kind in proof_kinds if kind not in reasons)
    heuristic = HeuristicAssessment(score=stats.score(args), reasons=tuple(reasons))
    action = "clean"
    if proof_kinds:
        action = "suspect"
    if set(proof_kinds) & STRONG_PROOF_KINDS or heuristic.score >= getattr(
        args, "ban_score", 12.0
    ):
        action = "ban"
    elif reasons or heuristic.score >= getattr(args, "suspect_score", 6.0):
        action = "suspect"
    return DecisionEvaluation(
        action=action,
        heuristic=heuristic,
        proofs=tuple(proofs),
    )


def shorten(value: str, width: int) -> str:
    if value == "-":
        return value
    if len(value) <= width:
        return value
    return value[: max(0, width - 3)] + "..."


def compact_ts(raw_ts: str) -> str:
    try:
        return datetime.strptime(raw_ts, "%d/%b/%Y:%H:%M:%S %z").strftime(
            "%m-%d %H:%M:%S"
        )
    except ValueError:
        return raw_ts


def compact_referer(referer: str, width: int) -> str:
    if referer == "-":
        return "-"
    try:
        parsed = urlparse(referer)
        host = parsed.netloc or "-"
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return shorten(f"{host}{path}", width)
    except ValueError:
        return shorten(referer, width)


@lru_cache(maxsize=65536)
def summarize_ua_base(ua: str) -> str:
    if ua == "-":
        return "-"

    browser = None
    browser_patterns = [
        (r"YaSearchBrowser/([0-9.]+)", "YaBrowser"),
        (r"CriOS/([0-9.]+)", "Chrome iOS"),
        (r"Chrome/([0-9.]+)", "Chrome"),
        (r"Firefox/([0-9.]+)", "Firefox"),
        (r"MSIE ([0-9.]+)", "IE"),
        (r"Trident/.*rv:([0-9.]+)", "IE"),
        (r"Version/([0-9.]+).*Safari/", "Safari"),
        (r"Safari/([0-9.]+)", "Safari"),
    ]
    for pattern, label in browser_patterns:
        match = re.search(pattern, ua)
        if match:
            browser = f"{label} {match.group(1).split('.')[0]}"
            break

    platform = None
    platform_patterns = [
        (r"Windows NT 10\.0", "Win10"),
        (r"Windows NT 6\.1", "Win7"),
        (r"Windows NT 5\.1", "WinXP"),
        (r"Android ([0-9.]+)", "Android"),
        (r"iPhone OS ([0-9_]+)", "iPhone"),
        (r"Mac OS X ([0-9_]+)", "macOS"),
        (r"X11; Ubuntu", "Ubuntu"),
        (r"Linux", "Linux"),
    ]
    for pattern, label in platform_patterns:
        match = re.search(pattern, ua)
        if match:
            if match.groups():
                version = match.group(1).replace("_", ".").split(".")[0]
                platform = f"{label} {version}"
            else:
                platform = label
            break

    markers = []
    if "Mobile" in ua:
        markers.append("mobile")
    if "YaSearchBrowser" in ua and (not browser or "YaBrowser" not in browser):
        markers.append("Yandex")

    parts = [part for part in (browser, platform) if part]
    if markers:
        parts.append(",".join(markers))
    if not parts:
        return ua
    return " / ".join(parts)


def summarize_ua(ua: str, width: int) -> str:
    return shorten(summarize_ua_base(ua), width)


def is_effective_bot(
    stats: IPStats, args: argparse.Namespace, forced_bot_ips: set[str]
) -> bool:
    return stats.ip in forced_bot_ips or stats.is_bot(args)


@lru_cache(maxsize=65536)
def ua_browser_family(ua: str) -> str:
    if ua == "-":
        return "-"

    browser_patterns = [
        (r"YaSearchBrowser/", "YaBrowser"),
        (r"CriOS/", "Chrome iOS"),
        (r"Chrome/", "Chrome"),
        (r"Firefox/", "Firefox"),
        (r"Version/.*Safari/", "Safari"),
        (r"Safari/", "Safari"),
    ]
    for pattern, label in browser_patterns:
        if re.search(pattern, ua):
            return label
    return ua


def ua_family(ua: str) -> str:
    pieces = []
    browser = ua_browser_family(ua)
    pieces.append(browser)
    if "Firefox/" in ua:
        pieces.append("gecko")
    elif "Chrome/" in ua or "Safari/" in ua:
        pieces.append("webkit")
    if "Mobile" in ua:
        pieces.append("mobile")
    return "|".join(pieces)


@lru_cache(maxsize=131072)
def has_payload_marker(path: str, configured_patterns: tuple[str, ...]) -> bool:
    pattern = compiled_regex_union(configured_patterns)
    return bool(pattern and pattern.search(path))


@lru_cache(maxsize=131072)
def has_payload_marker_mutation(
    path: str, configured_patterns: tuple[str, ...]
) -> bool:
    if not has_payload_marker(path, configured_patterns):
        return False
    parsed = urlparse(path)
    query = parsed.query
    if not query:
        return False
    return (
        len(query.split("&")) > 1
        or query.endswith(("'", '"'))
        or "%27" in query
        or "%22" in query
    )


@lru_cache(maxsize=131072)
def has_injection_payload(text: str) -> bool:
    return bool(INJECTION_RE.search(text))


@lru_cache(maxsize=131072)
def has_referer_junk(referer: str) -> bool:
    if referer == "-":
        return False
    parsed = urlparse(referer)
    if not parsed.scheme and not parsed.netloc:
        return bool(REFERER_JUNK_RE.search(referer))
    target = parsed.path
    if parsed.query:
        target = f"{target}?{parsed.query}"
    return bool(REFERER_JUNK_RE.search(target))


@lru_cache(maxsize=131072)
def base_path(path: str) -> str:
    return path.split("?", 1)[0]


@lru_cache(maxsize=131072)
def referer_base_path(referer: str) -> str:
    if referer == "-":
        return "-"
    parsed = urlparse(referer)
    if parsed.scheme or parsed.netloc:
        return base_path(parsed.path or "/")
    return base_path(referer)


@lru_cache(maxsize=131072)
def path_segments(path: str) -> tuple[str, ...]:
    return tuple(segment.lower() for segment in base_path(path).split("/") if segment)


@lru_cache(maxsize=131072)
def is_high_risk_exposure_probe_path(path: str) -> bool:
    segments = path_segments(path)
    if not segments:
        return False
    leaf = segments[-1]
    if any(segment in EXPOSURE_REPOSITORY_SEGMENTS for segment in segments):
        return leaf in EXPOSURE_REPOSITORY_LEAVES
    return leaf in EXPOSURE_CONFIG_LEAVES


@lru_cache(maxsize=131072)
def is_exposure_probe_path(path: str) -> bool:
    segments = path_segments(path)
    if not segments:
        return False
    leaf = segments[-1]
    return is_high_risk_exposure_probe_path(path) or leaf in EXPOSURE_DISCOVERY_LEAVES


@lru_cache(maxsize=131072)
def is_page_dependency_path(path: str) -> bool:
    if is_exposure_probe_path(path):
        return False
    base = base_path(path).lower()
    leaf = path_segments(base)[-1] if path_segments(base) else ""
    return (
        target_profile(base) == "asset"
        or leaf in PAGE_DEPENDENCY_LEAVES
        or base.endswith(PAGE_DEPENDENCY_SUFFIXES)
    )


@lru_cache(maxsize=131072)
def is_content_page_path(path: str) -> bool:
    return not is_exposure_probe_path(path) and not is_page_dependency_path(path)


@lru_cache(maxsize=131072)
def target_profile(path: str) -> str:
    base = base_path(path)
    if base == "/":
        return "root"
    stripped = base.lstrip("/")
    segments = [segment for segment in stripped.split("/") if segment]
    leaf = segments[-1] if segments else ""

    if "." in leaf:
        return "asset"
    if len(segments) > 1:
        return "nested"
    if re.search(r"\d{4}", leaf):
        return "dated-slug"
    hyphen_count = leaf.count("-")
    if hyphen_count >= 3:
        return "long-slug"
    if hyphen_count >= 1:
        return "slug"
    if len(leaf) <= 8:
        return "short-path"
    return "flat-path"


@lru_cache(maxsize=262144)
def payload_family(
    path: str, referer: str, configured_patterns: tuple[str, ...]
) -> str | None:
    payload_marker = has_payload_marker(path, configured_patterns)
    mutated_marker = has_payload_marker_mutation(path, configured_patterns)
    injection = has_injection_payload(path) or has_injection_payload(referer)
    referer_junk = has_referer_junk(referer)

    if not (payload_marker or injection or referer_junk):
        return None

    if injection:
        family = "injection-probe"
    elif mutated_marker and referer_junk:
        family = "ref-junk-fuzzer"
    elif mutated_marker:
        family = "param-mutation"
    elif payload_marker:
        family = "payload-marker-walker"
    else:
        family = "referer-fuzzer"

    suffixes: list[str] = []
    if (
        injection
        and referer_junk
        or referer_junk
        and family not in {"ref-junk-fuzzer", "referer-fuzzer"}
    ):
        suffixes.append("ref-junk")
    if mutated_marker and family not in {"param-mutation", "ref-junk-fuzzer"}:
        suffixes.append("param-mutation")

    if suffixes:
        return family + "+" + "+".join(suffixes)
    return family


@lru_cache(maxsize=262144)
def payload_campaign_key(
    path: str, referer: str, configured_patterns: tuple[str, ...]
) -> str | None:
    family = payload_family(path, referer, configured_patterns)
    if family is None:
        return None
    return f"{family}:{target_profile(path)}"


def provider_match_for_ip(runtime: AuditRuntime, ip: str) -> ProviderMatch | None:
    if runtime.provider_lookup is None:
        return None
    return runtime.provider_lookup.lookup(ip)


def provider_is_watched(match: ProviderMatch | None, args: argparse.Namespace) -> bool:
    if match is None:
        return False
    watched = {value.lower() for value in getattr(args, "provider_watch", ())}
    return "*" in watched or match.provider.lower() in watched


def provider_activity_proofs(
    stats: IPStats, args: argparse.Namespace, runtime: AuditRuntime
) -> list[ForcedProof]:
    match = provider_match_for_ip(runtime, stats.ip)
    if not provider_is_watched(match, args):
        return []
    unique_paths = len(stats.total_paths_seen)
    score = stats.score(args)
    if (
        stats.total < args.provider_request_count
        or unique_paths < args.provider_unique_paths
        or score < args.provider_min_score
    ):
        return []
    assert match is not None
    return [
        ForcedProof(
            kind="provider-hosted-activity",
            detail=(
                f"provider={provider_label(match)} network={match.network} "
                f"requests={stats.total} unique_paths={unique_paths} "
                f"score={score:.1f}"
            ),
        )
    ]


def provider_exclusion_proofs(
    stats: IPStats, args: argparse.Namespace, runtime: AuditRuntime
) -> list[ForcedProof]:
    if not getattr(args, "exclude_provider_traffic", False):
        return []
    match = provider_match_for_ip(runtime, stats.ip)
    if match is None:
        return []
    return [
        ForcedProof(
            kind="provider-hosted-activity",
            detail=(
                f"provider={provider_label(match)} network={match.network} "
                "mode=exclude-provider-traffic"
            ),
        )
    ]


def detect_provider_activity(
    ip_stats: dict[str, IPStats], args: argparse.Namespace, runtime: AuditRuntime
) -> dict[str, list[ForcedProof]]:
    if runtime.provider_lookup is None or not getattr(args, "provider_watch", ()):
        return {}
    return {
        ip: proofs
        for ip, stats in ip_stats.items()
        if (proofs := provider_activity_proofs(stats, args, runtime))
    }


def detect_provider_exclusions(
    ip_stats: dict[str, IPStats], args: argparse.Namespace, runtime: AuditRuntime
) -> dict[str, list[ForcedProof]]:
    if runtime.provider_lookup is None or not getattr(
        args, "exclude_provider_traffic", False
    ):
        return {}
    return {
        ip: proofs
        for ip, stats in ip_stats.items()
        if (proofs := provider_exclusion_proofs(stats, args, runtime))
    }


def build_ip_stats(
    rows: list[RequestRow], args: argparse.Namespace, runtime: AuditRuntime
) -> dict[str, IPStats]:
    ip_stats: dict[str, IPStats] = {}
    for row in rows:
        stats = ip_stats.setdefault(row.ip, IPStats(ip=row.ip))
        update_stats(
            stats=stats,
            ts=row.ts,
            path=row.path,
            method=row.method,
            status=row.status,
            referer=row.referer,
            ua=row.ua,
            known_bot_any_pattern=runtime.known_bot_any_pattern,
            known_bot_ua_pattern=runtime.known_bot_ua_pattern,
            known_bot_referer_pattern=runtime.known_bot_referer_pattern,
            known_bot_cache=runtime.known_bot_cache,
            args=args,
        )
    return ip_stats


def group_rows_by_ip(rows: list[RequestRow]) -> dict[str, list[RequestRow]]:
    rows_by_ip: dict[str, list[RequestRow]] = {}
    for row in rows:
        rows_by_ip.setdefault(row.ip, []).append(row)
    return rows_by_ip


def collect_rows_and_stats(
    path: Path, args: argparse.Namespace, runtime: AuditRuntime
) -> AnalysisResult:
    file_size = path.stat().st_size
    include_fast_tokens = extract_fast_tokens(args.path_include)
    use_process_parallel = (
        args.jobs > 1
        and file_size >= args.parallel_min_bytes
        and process_pool_available()
    )
    if not use_process_parallel:
        chunk = parse_chunk(
            ParseTask(
                path=str(path),
                start=0,
                end=-1,
                include_patterns=args.path_include,
                exclude_patterns=args.path_exclude,
                include_fast_tokens=include_fast_tokens,
            )
        )
        rows = sorted(
            chunk.rows,
            key=lambda row: (row.ts, row.ip, row.ua, row.path, row.method, row.status),
        )
        canonicalize_rows(rows)
        assign_input_indices(rows)
        return AnalysisResult(
            ip_stats=build_ip_stats(rows, args, runtime),
            parsed_lines=chunk.parsed_lines,
            matched_lines=chunk.matched_lines,
            rows=rows,
            rows_by_ip=group_rows_by_ip(rows),
        )

    chunk_size = max(args.parallel_chunk_bytes, file_size // args.jobs)
    tasks: list[ParseTask] = []
    start = 0
    while start < file_size:
        end = min(file_size - 1, start + chunk_size - 1)
        tasks.append(
            ParseTask(
                path=str(path),
                start=start,
                end=end,
                include_patterns=args.path_include,
                exclude_patterns=args.path_exclude,
                include_fast_tokens=include_fast_tokens,
            )
        )
        start = end + 1

    parsed_lines = 0
    matched_lines = 0
    rows: list[RequestRow] = []
    with ProcessPoolExecutor(max_workers=args.jobs) as executor:
        futures = [executor.submit(parse_chunk, task) for task in tasks]
        for future in futures:
            chunk = future.result()
            parsed_lines += chunk.parsed_lines
            matched_lines += chunk.matched_lines
            rows.extend(chunk.rows)

    rows.sort(
        key=lambda row: (row.ts, row.ip, row.ua, row.path, row.method, row.status)
    )
    canonicalize_rows(rows)
    assign_input_indices(rows)
    return AnalysisResult(
        ip_stats=build_ip_stats(rows, args, runtime),
        parsed_lines=parsed_lines,
        matched_lines=matched_lines,
        rows=rows,
        rows_by_ip=group_rows_by_ip(rows),
    )


def detect_coordinated_ua_ips(
    rows: list[RequestRow], args: argparse.Namespace
) -> CoordinatedUAAnalysis:
    degraded = False
    degraded_reason = ""
    if len(rows) > args.coord_max_rows:
        degraded = True
        degraded_reason = (
            f"bounded to most recent {args.coord_max_rows} rows from {len(rows)}"
        )
        rows = heapq.nlargest(
            args.coord_max_rows,
            rows,
            key=lambda row: (row.ts, row.ua, row.ip, row.path),
        )
    sorted_rows = sorted(rows, key=lambda row: (row.ts, row.ua, row.ip, row.path))

    suspicious_ips: dict[str, list[ForcedProof]] = {}
    ua_windows: dict[str, deque[RequestRow]] = {}
    ua_path_counts: dict[str, Counter[str]] = {}
    ua_ip_counts: dict[str, Counter[str]] = {}

    for row in sorted_rows:
        window = ua_windows.setdefault(row.ua, deque())
        path_counts = ua_path_counts.setdefault(row.ua, Counter())
        ip_counts = ua_ip_counts.setdefault(row.ua, Counter())

        window.append(row)
        path_counts[row.path] += 1
        ip_counts[row.ip] += 1

        cutoff = row.ts - args.coord_window_seconds
        while window and window[0].ts < cutoff:
            expired = window.popleft()
            path_counts[expired.path] -= 1
            if path_counts[expired.path] <= 0:
                del path_counts[expired.path]
            ip_counts[expired.ip] -= 1
            if ip_counts[expired.ip] <= 0:
                del ip_counts[expired.ip]

        window_len = len(window)
        if window_len < args.coord_count:
            continue

        unique_paths = len(path_counts)
        unique_ips = len(ip_counts)
        max_ip_share = max(ip_counts.values()) / window_len if window_len else 1.0
        if (
            unique_paths >= args.coord_unique_paths
            and unique_ips >= args.coord_unique_ips
            and max_ip_share <= args.coord_max_ip_share
        ):
            sample_paths = ", ".join(list(path_counts.keys())[:4])
            detail = (
                f"ua={summarize_ua(row.ua, 50)} ips={unique_ips} reqs={window_len} "
                f"unique={unique_paths} paths={sample_paths}"
            )
            for suspicious_ip in ip_counts:
                suspicious_ips.setdefault(suspicious_ip, []).append(
                    ForcedProof(kind="coordinated-ua", detail=detail)
                )

    return CoordinatedUAAnalysis(
        forced_proofs_by_ip=suspicious_ips,
        degraded=degraded,
        degraded_reason=degraded_reason,
    )


def detect_coordinated_target_fanout(
    rows: list[RequestRow], args: argparse.Namespace
) -> CoordinatedUAAnalysis:
    degraded = False
    degraded_reason = ""
    if len(rows) > args.target_fanout_max_rows:
        degraded = True
        degraded_reason = f"bounded to most recent {args.target_fanout_max_rows} rows from {len(rows)}"
        rows = heapq.nlargest(
            args.target_fanout_max_rows,
            rows,
            key=lambda row: (row.ts, row.ua, row.ip, row.path),
        )
    suspicious_ips: dict[str, list[ForcedProof]] = {}
    time_ordered_rows = sorted(rows, key=lambda row: (row.ts, row.ua, row.ip, row.path))

    def scan_mode(
        *,
        mode: str,
        window_seconds: float,
        request_count: int,
        unique_ips_required: int,
        key_for_row: Callable[[RequestRow], tuple[str, str]],
    ) -> None:
        keyed_windows: dict[tuple[str, str], deque[RequestRow]] = {}
        keyed_ip_counts: dict[tuple[str, str], Counter[str]] = {}
        keyed_referer_counts: dict[tuple[str, str], Counter[str]] = {}
        keyed_ua_counts: dict[tuple[str, str], Counter[str]] = {}

        for row in time_ordered_rows:
            key = key_for_row(row)
            path = base_path(row.path)
            window = keyed_windows.setdefault(key, deque())
            ip_counts = keyed_ip_counts.setdefault(key, Counter())
            referer_counts = keyed_referer_counts.setdefault(key, Counter())
            ua_counts = keyed_ua_counts.setdefault(key, Counter())

            window.append(row)
            ip_counts[row.ip] += 1
            referer_counts[row.referer] += 1
            ua_counts[row.ua] += 1

            cutoff = row.ts - window_seconds
            while window and window[0].ts < cutoff:
                expired = window.popleft()
                ip_counts[expired.ip] -= 1
                if ip_counts[expired.ip] <= 0:
                    del ip_counts[expired.ip]
                referer_counts[expired.referer] -= 1
                if referer_counts[expired.referer] <= 0:
                    del referer_counts[expired.referer]
                ua_counts[expired.ua] -= 1
                if ua_counts[expired.ua] <= 0:
                    del ua_counts[expired.ua]

            window_len = len(window)
            if window_len < request_count:
                continue
            unique_ips = len(ip_counts)
            if unique_ips < unique_ips_required:
                continue
            max_ip_share = max(ip_counts.values()) / window_len if window_len else 1.0
            dominant_referer_ratio = (
                max(referer_counts.values()) / window_len if window_len else 1.0
            )
            if (
                max_ip_share > args.target_fanout_max_ip_share
                or dominant_referer_ratio < args.target_fanout_dominant_referer_ratio
            ):
                continue

            sample_ua = summarize_ua(row.ua, 50)
            ua_variants = len(ua_counts)
            detail_parts: list[str] = []
            if mode:
                detail_parts.append(f"mode={mode}")
            detail_parts.extend(
                (
                    f"family={ua_family(row.ua)}",
                    f"sample-ua={sample_ua}",
                    f"path={path}",
                    f"ips={unique_ips}",
                    f"reqs={window_len}",
                    f"ua-variants={ua_variants}",
                    f"ref-dom={dominant_referer_ratio:.0%}",
                )
            )
            detail = " ".join(detail_parts)
            for suspicious_ip in ip_counts:
                suspicious_ips.setdefault(suspicious_ip, []).append(
                    ForcedProof(kind="coordinated-target-fanout", detail=detail)
                )

    scan_mode(
        mode="",
        window_seconds=args.target_fanout_window_seconds,
        request_count=args.target_fanout_count,
        unique_ips_required=args.target_fanout_unique_ips,
        key_for_row=lambda row: (ua_family(row.ua), base_path(row.path)),
    )
    scan_mode(
        mode="same-ua-target-fanout",
        window_seconds=args.target_fanout_same_ua_window_seconds,
        request_count=args.target_fanout_same_ua_count,
        unique_ips_required=args.target_fanout_same_ua_unique_ips,
        key_for_row=lambda row: (row.ua, base_path(row.path)),
    )

    return CoordinatedUAAnalysis(
        forced_proofs_by_ip=suspicious_ips,
        degraded=degraded,
        degraded_reason=degraded_reason,
    )


def analyze_payload_campaigns(
    rows: list[RequestRow], args: argparse.Namespace, runtime: AuditRuntime
) -> PayloadCampaignAnalysis:
    candidate_rows = []
    for row in rows:
        family = payload_campaign_key(
            row.path, row.referer, runtime.payload_marker_patterns
        )
        if family is not None:
            candidate_rows.append((family, row))
    if not candidate_rows:
        return PayloadCampaignAnalysis(forced_proofs_by_ip={}, summaries=[])

    degraded = False
    degraded_reason = ""
    if len(candidate_rows) > args.payload_campaign_max_rows:
        degraded = True
        degraded_reason = (
            "bounded to most recent "
            f"{args.payload_campaign_max_rows} candidate rows from {len(candidate_rows)}"
        )
        candidate_rows = heapq.nlargest(
            args.payload_campaign_max_rows,
            candidate_rows,
            key=lambda item: (item[1].ts, item[1].ip, item[1].path),
        )
    candidate_rows.sort(key=lambda item: (item[1].ts, item[1].ip, item[1].path))
    family_windows: dict[str, deque[RequestRow]] = {}
    family_ip_counts: dict[str, Counter[str]] = {}
    family_path_counts: dict[str, Counter[str]] = {}
    best_by_family: dict[str, CampaignSummary] = {}
    forced_proofs_by_ip: dict[str, list[ForcedProof]] = {}

    for family, row in candidate_rows:
        window = family_windows.setdefault(family, deque())
        ip_counts = family_ip_counts.setdefault(family, Counter())
        path_counts = family_path_counts.setdefault(family, Counter())

        window.append(row)
        ip_counts[row.ip] += 1
        path_counts[base_path(row.path)] += 1

        cutoff = row.ts - args.payload_campaign_window_seconds
        while window and window[0].ts < cutoff:
            expired = window.popleft()
            ip_counts[expired.ip] -= 1
            if ip_counts[expired.ip] <= 0:
                del ip_counts[expired.ip]
            expired_base = base_path(expired.path)
            path_counts[expired_base] -= 1
            if path_counts[expired_base] <= 0:
                del path_counts[expired_base]

        window_len = len(window)
        unique_ips = len(ip_counts)
        unique_paths = len(path_counts)
        if (
            window_len < args.payload_campaign_count
            or unique_ips < args.payload_campaign_unique_ips
            or unique_paths < args.payload_campaign_unique_paths
        ):
            continue

        sample_paths = tuple(list(path_counts.keys())[:4])
        detail = (
            f"family={family} ips={unique_ips} reqs={window_len} "
            f"unique={unique_paths} paths={', '.join(sample_paths)}"
        )
        for suspicious_ip in ip_counts:
            forced_proofs_by_ip.setdefault(suspicious_ip, []).append(
                ForcedProof(kind="payload-campaign", detail=detail)
            )

        current = CampaignSummary(
            family=family,
            request_count=window_len,
            unique_ips=unique_ips,
            unique_paths=unique_paths,
            first_ts=window[0].ts,
            last_ts=window[-1].ts,
            sample_paths=sample_paths,
            sample_ips=tuple(list(ip_counts.keys())[:4]),
        )
        previous = best_by_family.get(family)
        if previous is None or (
            current.request_count,
            current.unique_ips,
            current.unique_paths,
        ) > (
            previous.request_count,
            previous.unique_ips,
            previous.unique_paths,
        ):
            best_by_family[family] = current

    return PayloadCampaignAnalysis(
        forced_proofs_by_ip=forced_proofs_by_ip,
        summaries=sorted(
            best_by_family.values(),
            key=lambda item: (
                -item.request_count,
                -item.unique_ips,
                -item.unique_paths,
                item.family,
            ),
        ),
        degraded=degraded,
        degraded_reason=degraded_reason,
    )


def exposure_probe_proof_for_window(
    window_rows: list[RequestRow], args: argparse.Namespace
) -> ForcedProof | None:
    page_candidates = {
        referer_base_path(row.referer)
        for row in window_rows
        if is_exposure_probe_path(row.path) and referer_base_path(row.referer) != "-"
    }
    for page_path in sorted(page_candidates):
        content_rows = [
            row
            for row in window_rows
            if row.method == "GET"
            and base_path(row.path) == page_path
            and is_content_page_path(row.path)
        ]
        if not content_rows:
            continue
        asset_rows = [
            row
            for row in window_rows
            if row.method == "GET"
            and is_page_dependency_path(row.path)
            and referer_base_path(row.referer) == page_path
        ]
        if len(asset_rows) < args.exposure_probe_asset_count:
            continue
        probe_rows = [
            row
            for row in window_rows
            if row.method == "GET"
            and is_exposure_probe_path(row.path)
            and referer_base_path(row.referer) == page_path
        ]
        unique_probe_paths = {base_path(row.path) for row in probe_rows}
        high_risk_probe_paths = {
            base_path(row.path)
            for row in probe_rows
            if is_high_risk_exposure_probe_path(row.path)
        }
        if len(unique_probe_paths) < args.exposure_probe_count:
            continue
        if not high_risk_probe_paths:
            continue
        window_start = min(row.ts for row in content_rows + asset_rows + probe_rows)
        window_end = max(row.ts for row in content_rows + asset_rows + probe_rows)
        probe_samples = ", ".join(sorted(unique_probe_paths)[:4])
        return ForcedProof(
            kind="asset-primed-probe",
            detail=(
                f"page={page_path} assets={len(asset_rows)} "
                f"probes={len(unique_probe_paths)} high-risk={len(high_risk_probe_paths)} "
                f"window={window_end - window_start:.1f}s paths={probe_samples}"
            ),
        )
    return None


def analyze_ip_behaviors(
    ip: str, rows: list[RequestRow], args: argparse.Namespace, runtime: AuditRuntime
) -> tuple[str, list[ForcedProof]]:
    proofs: list[ForcedProof] = []

    rows.sort(key=lambda row: (row.ts, row.path, row.method))

    payload_marker_rows = 0
    injection_rows = 0
    referer_junk_rows = 0
    injection_examples: list[str] = []
    referer_examples: list[str] = []
    mutated_payload_marker_pairs = 0
    mutated_examples: list[str] = []
    twin_ua_mutation_pairs = 0
    twin_ua_examples: list[str] = []
    ua_switch_window: deque[RequestRow] = deque()
    ua_switch_counts: Counter[str] = Counter()
    ua_switch_family_counts: Counter[str] = Counter()
    ua_switch_path_counts: Counter[str] = Counter()
    max_ua_switch_rows = 0
    max_ua_switch_distinct_uas = 0
    max_ua_switch_distinct_families = 0
    max_ua_switch_distinct_paths = 0
    ua_switch_examples: list[str] = []
    for left, right in zip(rows, rows[1:]):
        ua_switch_window.append(left)
        ua_switch_counts[left.ua] += 1
        ua_switch_family_counts[ua_family(left.ua)] += 1
        ua_switch_path_counts[base_path(left.path)] += 1
        cutoff = left.ts - args.ua_switch_window_seconds
        while ua_switch_window and ua_switch_window[0].ts < cutoff:
            expired = ua_switch_window.popleft()
            ua_switch_counts[expired.ua] -= 1
            if ua_switch_counts[expired.ua] <= 0:
                del ua_switch_counts[expired.ua]
            expired_family = ua_family(expired.ua)
            ua_switch_family_counts[expired_family] -= 1
            if ua_switch_family_counts[expired_family] <= 0:
                del ua_switch_family_counts[expired_family]
            expired_path = base_path(expired.path)
            ua_switch_path_counts[expired_path] -= 1
            if ua_switch_path_counts[expired_path] <= 0:
                del ua_switch_path_counts[expired_path]
        window_len = len(ua_switch_window)
        distinct_uas = len(ua_switch_counts)
        distinct_families = len(ua_switch_family_counts)
        distinct_paths = len(ua_switch_path_counts)
        if (
            window_len >= args.ua_switch_count
            and distinct_uas >= args.ua_switch_distinct_uas
            and distinct_families >= args.ua_switch_distinct_families
        ):
            if (
                window_len,
                distinct_uas,
                distinct_families,
                distinct_paths,
            ) > (
                max_ua_switch_rows,
                max_ua_switch_distinct_uas,
                max_ua_switch_distinct_families,
                max_ua_switch_distinct_paths,
            ):
                max_ua_switch_rows = window_len
                max_ua_switch_distinct_uas = distinct_uas
                max_ua_switch_distinct_families = distinct_families
                max_ua_switch_distinct_paths = distinct_paths
                sample_rows = list(ua_switch_window)[:2]
                ua_switch_examples = [
                    shorten(
                        f"{compact_ts(sample.raw_ts)} {base_path(sample.path)} ua={summarize_ua(sample.ua, 32)}",
                        110,
                    )
                    for sample in sample_rows
                ]

        if has_payload_marker(left.path, runtime.payload_marker_patterns):
            payload_marker_rows += 1
        if has_injection_payload(left.path) or has_injection_payload(left.referer):
            injection_rows += 1
            if len(injection_examples) < 2:
                injection_examples.append(shorten(left.path, 90))
        if has_referer_junk(left.referer):
            referer_junk_rows += 1
            if len(referer_examples) < 2:
                referer_examples.append(shorten(left.referer, 90))

        left_base = base_path(left.path)
        right_base = base_path(right.path)
        if (
            left_base == right_base
            and left.path != right.path
            and right.ts - left.ts <= args.payload_pair_gap_seconds
            and (
                has_payload_marker(left.path, runtime.payload_marker_patterns)
                or has_payload_marker(right.path, runtime.payload_marker_patterns)
            )
        ):
            mutated_payload_marker_pairs += 1
            if len(mutated_examples) < 2:
                mutated_examples.append(shorten(f"{left.path} -> {right.path}", 110))
            if (
                left.ip == right.ip
                and int(left.ts) == int(right.ts)
                and left.ua != right.ua
            ):
                twin_ua_mutation_pairs += 1
                if len(twin_ua_examples) < 2:
                    twin_ua_examples.append(
                        shorten(
                            f"{compact_ts(left.raw_ts)} {left_base} ua={summarize_ua(left.ua, 32)} -> {summarize_ua(right.ua, 32)}",
                            120,
                        )
                    )

    if rows:
        last = rows[-1]
        ua_switch_window.append(last)
        ua_switch_counts[last.ua] += 1
        ua_switch_family_counts[ua_family(last.ua)] += 1
        ua_switch_path_counts[base_path(last.path)] += 1
        cutoff = last.ts - args.ua_switch_window_seconds
        while ua_switch_window and ua_switch_window[0].ts < cutoff:
            expired = ua_switch_window.popleft()
            ua_switch_counts[expired.ua] -= 1
            if ua_switch_counts[expired.ua] <= 0:
                del ua_switch_counts[expired.ua]
            expired_family = ua_family(expired.ua)
            ua_switch_family_counts[expired_family] -= 1
            if ua_switch_family_counts[expired_family] <= 0:
                del ua_switch_family_counts[expired_family]
            expired_path = base_path(expired.path)
            ua_switch_path_counts[expired_path] -= 1
            if ua_switch_path_counts[expired_path] <= 0:
                del ua_switch_path_counts[expired_path]
        window_len = len(ua_switch_window)
        distinct_uas = len(ua_switch_counts)
        distinct_families = len(ua_switch_family_counts)
        distinct_paths = len(ua_switch_path_counts)
        if (
            window_len >= args.ua_switch_count
            and distinct_uas >= args.ua_switch_distinct_uas
            and distinct_families >= args.ua_switch_distinct_families
            and (
                window_len,
                distinct_uas,
                distinct_families,
                distinct_paths,
            )
            > (
                max_ua_switch_rows,
                max_ua_switch_distinct_uas,
                max_ua_switch_distinct_families,
                max_ua_switch_distinct_paths,
            )
        ):
            max_ua_switch_rows = window_len
            max_ua_switch_distinct_uas = distinct_uas
            max_ua_switch_distinct_families = distinct_families
            max_ua_switch_distinct_paths = distinct_paths
            sample_rows = list(ua_switch_window)[:2]
            ua_switch_examples = [
                shorten(
                    f"{compact_ts(sample.raw_ts)} {base_path(sample.path)} ua={summarize_ua(sample.ua, 32)}",
                    110,
                )
                for sample in sample_rows
            ]
        if has_payload_marker(last.path, runtime.payload_marker_patterns):
            payload_marker_rows += 1
        if has_injection_payload(last.path) or has_injection_payload(last.referer):
            injection_rows += 1
            if len(injection_examples) < 2:
                injection_examples.append(shorten(last.path, 90))
        if has_referer_junk(last.referer):
            referer_junk_rows += 1
            if len(referer_examples) < 2:
                referer_examples.append(shorten(last.referer, 90))

    # Repeated pair detector: many sessions of page A then page B within a few seconds.
    pair_counts: Counter[tuple[str, str]] = Counter()
    pair_examples: dict[tuple[str, str], tuple[str, str]] = {}
    for left, right in zip(rows, rows[1:]):
        if right.ts - left.ts > args.pair_gap_seconds:
            continue
        if left.path == right.path:
            continue
        pair = (left.path, right.path)
        pair_counts[pair] += 1
        pair_examples.setdefault(pair, (left.raw_ts, right.raw_ts))
    if pair_counts:
        top_pair, top_pair_count = pair_counts.most_common(1)[0]
        if top_pair_count >= args.pair_repeat_count:
            start_ts, end_ts = pair_examples[top_pair]
            proofs.append(
                ForcedProof(
                    kind="repeated-pair",
                    detail=f"{top_pair_count}x {top_pair[0]} -> {top_pair[1]} first={start_ts} next={end_ts}",
                )
            )

    # Tight multi-fetch detector: compact clusters with simultaneous or repeated
    # content fetches, which are distinct from larger burst/sweep behavior.
    multifetch_window: deque[RequestRow] = deque()
    multifetch_path_counts: Counter[str] = Counter()
    multifetch_referer_counts: Counter[str] = Counter()
    multifetch_second_path_counts: dict[int, Counter[str]] = {}
    for row in rows:
        row_base = base_path(row.path)
        if is_page_dependency_path(row_base) or is_exposure_probe_path(row_base):
            continue
        multifetch_window.append(row)
        multifetch_path_counts[row_base] += 1
        multifetch_referer_counts[row.referer] += 1
        second = int(row.ts)
        second_counts = multifetch_second_path_counts.setdefault(second, Counter())
        second_counts[row_base] += 1

        cutoff = row.ts - args.multi_fetch_window_seconds
        while multifetch_window and multifetch_window[0].ts < cutoff:
            expired = multifetch_window.popleft()
            expired_base = base_path(expired.path)
            multifetch_path_counts[expired_base] -= 1
            if multifetch_path_counts[expired_base] <= 0:
                del multifetch_path_counts[expired_base]
            multifetch_referer_counts[expired.referer] -= 1
            if multifetch_referer_counts[expired.referer] <= 0:
                del multifetch_referer_counts[expired.referer]
            expired_second = int(expired.ts)
            expired_second_counts = multifetch_second_path_counts[expired_second]
            expired_second_counts[expired_base] -= 1
            if expired_second_counts[expired_base] <= 0:
                del expired_second_counts[expired_base]
            if not expired_second_counts:
                del multifetch_second_path_counts[expired_second]

        window_len = len(multifetch_window)
        if window_len < args.multi_fetch_count:
            continue
        unique_paths = len(multifetch_path_counts)
        if unique_paths < args.multi_fetch_unique_paths:
            continue
        repeated_paths = sum(
            1 for count in multifetch_path_counts.values() if count >= 2
        )
        same_second_unique_paths = max(
            (
                len(path_counts)
                for path_counts in multifetch_second_path_counts.values()
            ),
            default=0,
        )
        dominant_referer_ratio = (
            max(multifetch_referer_counts.values()) / window_len
            if multifetch_referer_counts
            else 1.0
        )
        if dominant_referer_ratio < args.multi_fetch_dominant_referer_ratio:
            continue
        if (
            repeated_paths < args.multi_fetch_repeat_paths
            and same_second_unique_paths < args.multi_fetch_same_second_unique_paths
        ):
            continue
        window_rows = list(multifetch_window)
        sample_paths = ", ".join(list(multifetch_path_counts.keys())[:4])
        proofs.append(
            ForcedProof(
                kind="tight-multifetch",
                detail=(
                    f"{window_len} reqs/{args.multi_fetch_window_seconds:.0f}s "
                    f"unique={unique_paths} repeated-paths={repeated_paths} "
                    f"same-second-unique={same_second_unique_paths} "
                    f"ref-dom={dominant_referer_ratio:.0%} "
                    f"window={compact_ts(window_rows[0].raw_ts)}..{compact_ts(window_rows[-1].raw_ts)} "
                    f"paths={sample_paths}"
                ),
            )
        )
        break

    # Asset-primed exposure probe detector: browser-like page rendering with
    # same-page asset referers followed by hidden repository/config discovery.
    exposure_window: deque[RequestRow] = deque()
    for row in rows:
        exposure_window.append(row)
        cutoff = row.ts - args.exposure_probe_window_seconds
        while exposure_window and exposure_window[0].ts < cutoff:
            exposure_window.popleft()
        if not is_exposure_probe_path(row.path):
            continue
        proof = exposure_probe_proof_for_window(list(exposure_window), args)
        if proof:
            proofs.append(proof)
            break

    # Redundant revisit detector: many base paths revisited with strongly dominant referer behavior.
    base_rows: dict[str, list[RequestRow]] = {}
    referer_counts = Counter(row.referer for row in rows)
    for row in rows:
        base_rows.setdefault(base_path(row.path), []).append(row)
    revisited_paths = {
        path: path_rows for path, path_rows in base_rows.items() if len(path_rows) >= 2
    }
    repeat_requests = sum(len(path_rows) - 1 for path_rows in revisited_paths.values())
    dominant_referer_ratio = (
        max(referer_counts.values()) / len(rows) if rows and referer_counts else 1.0
    )
    if (
        len(revisited_paths) >= args.revisit_paths
        and repeat_requests >= args.revisit_repeat_requests
        and dominant_referer_ratio >= args.revisit_dominant_referer_ratio
    ):
        sample_paths = ", ".join(list(revisited_paths.keys())[:4])
        proofs.append(
            ForcedProof(
                kind="redundant-revisit",
                detail=(
                    f"paths={len(revisited_paths)} extra={repeat_requests} "
                    f"ref-dom={dominant_referer_ratio:.0%} samples={sample_paths}"
                ),
            )
        )

    # Cadenced repeat detector: a small number of long-gap, same-path requests
    # landing on a stable interval is enough evidence for scheduled fetching.
    for path, path_rows in base_rows.items():
        if target_profile(path) == "asset":
            continue
        path_rows.sort(key=lambda row: row.ts)
        hour_repeat_count = getattr(args, "cadence_hour_repeat_count", 2)
        if hour_repeat_count >= 2 and len(path_rows) >= hour_repeat_count:
            for start in range(len(path_rows) - hour_repeat_count + 1):
                cadence_rows = path_rows[start : start + hour_repeat_count]
                gaps = [
                    cadence_rows[index + 1].ts - cadence_rows[index].ts
                    for index in range(len(cadence_rows) - 1)
                ]
                max_drift = max(
                    abs(gap - args.cadence_hour_gap_seconds) for gap in gaps
                )
                referer_ratio = dominant_referer_share(cadence_rows)
                if max_drift > args.cadence_hour_gap_tolerance_seconds:
                    continue
                if referer_ratio < args.cadence_dominant_referer_ratio:
                    continue
                interval = sum(gaps) / len(gaps)
                seconds = sorted({int(row.ts) % 60 for row in cadence_rows})
                second_slots = ",".join(str(second).zfill(2) for second in seconds)
                proofs.append(
                    ForcedProof(
                        kind="cadenced-repeat",
                        detail=(
                            f"near-hour path={path} repeats={len(cadence_rows)} "
                            f"interval~{interval:.0f}s target={args.cadence_hour_gap_seconds:.0f}s "
                            f"max-drift={max_drift:.0f}s seconds={second_slots} "
                            f"ref-dom={referer_ratio:.0%} "
                            f"window={compact_ts(cadence_rows[0].raw_ts)}..{compact_ts(cadence_rows[-1].raw_ts)}"
                        ),
                    )
                )
                break
        if any(proof.kind == "cadenced-repeat" for proof in proofs):
            break

        if len(path_rows) >= args.cadence_repeat_count:
            for start in range(len(path_rows) - args.cadence_repeat_count + 1):
                cadence_rows = path_rows[start : start + args.cadence_repeat_count]
                gaps = [
                    cadence_rows[index + 1].ts - cadence_rows[index].ts
                    for index in range(len(cadence_rows) - 1)
                ]
                if not gaps or min(gaps) < args.cadence_min_gap_seconds:
                    continue
                if max(gaps) - min(gaps) > args.cadence_gap_tolerance_seconds:
                    continue
                referer_ratio = dominant_referer_share(cadence_rows)
                if referer_ratio < args.cadence_dominant_referer_ratio:
                    continue
                interval = sum(gaps) / len(gaps)
                seconds = sorted({int(row.ts) % 60 for row in cadence_rows})
                second_slots = ",".join(str(second).zfill(2) for second in seconds)
                proofs.append(
                    ForcedProof(
                        kind="cadenced-repeat",
                        detail=(
                            f"path={path} repeats={len(cadence_rows)} "
                            f"interval~{interval:.0f}s gap-spread={max(gaps) - min(gaps):.0f}s "
                            f"seconds={second_slots} ref-dom={referer_ratio:.0%} "
                            f"window={compact_ts(cadence_rows[0].raw_ts)}..{compact_ts(cadence_rows[-1].raw_ts)}"
                        ),
                    )
                )
                break
        if any(proof.kind == "cadenced-repeat" for proof in proofs):
            break

    # Rotating UA detector.
    distinct_uas = len({row.ua for row in rows})
    distinct_families = len({ua_family(row.ua) for row in rows})
    if (
        distinct_uas >= args.rotate_ua_count
        and distinct_families >= args.rotate_ua_family_count
    ):
        proofs.append(
            ForcedProof(
                kind="rotating-ua",
                detail=f"{distinct_uas} uas {distinct_families} families top={top_counter(Counter(row.ua for row in rows), 2)}",
            )
        )

    # Periodic poller detector.
    rows_by_path: dict[str, list[RequestRow]] = {}
    for row in rows:
        rows_by_path.setdefault(row.path, []).append(row)
    for path, path_rows in rows_by_path.items():
        if len(path_rows) < args.poll_repeat_count:
            continue
        path_rows.sort(key=lambda row: row.ts)
        gaps = [
            int(path_rows[i + 1].ts - path_rows[i].ts)
            for i in range(len(path_rows) - 1)
        ]
        if not gaps:
            continue
        gap_mode, gap_mode_count = Counter(gaps).most_common(1)[0]
        methods = Counter(row.method for row in path_rows)
        if (
            gap_mode >= args.poll_min_gap_seconds
            and gap_mode_count >= args.poll_repeat_count - 1
        ):
            proofs.append(
                ForcedProof(
                    kind="periodic-poller",
                    detail=f"path={path} repeats={len(path_rows)} interval~{gap_mode}s methods={dict(methods)}",
                )
            )
            break

    # Strict serial sweep detector.
    longest = 1
    streak_start = 0
    current = 1
    current_start = 0
    for idx in range(1, len(rows)):
        gap = rows[idx].ts - rows[idx - 1].ts
        if (
            args.serial_min_gap_seconds <= gap <= args.serial_max_gap_seconds
            and rows[idx].path != rows[idx - 1].path
        ):
            current += 1
        else:
            if current > longest:
                longest = current
                streak_start = current_start
            current = 1
            current_start = idx
    if current > longest:
        longest = current
        streak_start = current_start
    if longest >= args.serial_count:
        streak_rows = rows[streak_start : streak_start + longest]
        unique_paths = len({row.path for row in streak_rows})
        if unique_paths >= args.serial_unique_paths:
            proofs.append(
                ForcedProof(
                    kind="serial-sweep",
                    detail=(
                        f"{longest} reqs {compact_ts(streak_rows[0].raw_ts)}..{compact_ts(streak_rows[-1].raw_ts)} "
                        f"unique={unique_paths} ref={top_counter(Counter(row.referer for row in streak_rows), 1)}"
                    ),
                )
            )

    if payload_marker_rows >= args.payload_show_analysis_count and (
        injection_rows >= args.payload_injection_count
        or referer_junk_rows >= args.payload_referer_junk_count
        or mutated_payload_marker_pairs >= args.payload_mutation_count
    ):
        detail_bits = [
            f"payload-markers={payload_marker_rows}",
            f"injection={injection_rows}",
            f"ref-junk={referer_junk_rows}",
            f"mutated-pairs={mutated_payload_marker_pairs}",
        ]
        examples = injection_examples or mutated_examples or referer_examples
        if examples:
            detail_bits.append("example=" + " | ".join(examples[:2]))
        proofs.append(
            ForcedProof(
                kind="payload-fuzzer",
                detail=" ".join(detail_bits),
            )
        )

    if twin_ua_mutation_pairs >= args.same_second_ua_swap_count:
        proofs.append(
            ForcedProof(
                kind="same-second-ua-swap",
                detail=(
                    f"{twin_ua_mutation_pairs} twin-ua mutations "
                    + (
                        "example=" + " | ".join(twin_ua_examples[:2])
                        if twin_ua_examples
                        else ""
                    )
                ).strip(),
            )
        )

    if max_ua_switch_rows >= args.ua_switch_count:
        detail = (
            f"{max_ua_switch_rows} reqs/{args.ua_switch_window_seconds:.1f}s "
            f"uas={max_ua_switch_distinct_uas} families={max_ua_switch_distinct_families} "
            f"paths={max_ua_switch_distinct_paths}"
        )
        if ua_switch_examples:
            detail += " example=" + " | ".join(ua_switch_examples[:2])
        proofs.append(
            ForcedProof(
                kind="rapid-ua-switch",
                detail=detail,
            )
        )

    return ip, proofs


def analyze_ip_behaviors_worker(
    ip: str,
    rows: list[RequestRow],
    args: argparse.Namespace,
    detector_config: DetectorConfig,
    bot_patterns: tuple[str, ...],
) -> tuple[str, list[ForcedProof]]:
    runtime = AuditRuntime(
        detector_config=detector_config,
        known_bot_any_pattern=compiled_regex_union(
            detector_config.known_bot_any_patterns + bot_patterns
        ),
        known_bot_ua_pattern=compiled_regex_union(
            detector_config.known_bot_ua_patterns
        ),
        known_bot_referer_pattern=compiled_regex_union(
            detector_config.known_bot_referer_patterns
        ),
        payload_marker_patterns=detector_config.payload_marker_patterns,
    )
    return analyze_ip_behaviors(ip, rows, args, runtime)


def detect_behavioral_bots(
    rows_by_ip: dict[str, list[RequestRow]],
    args: argparse.Namespace,
    runtime: AuditRuntime,
) -> dict[str, list[ForcedProof]]:
    forced: dict[str, list[ForcedProof]] = {}

    work_items = list(rows_by_ip.items())
    if args.jobs > 1 and len(work_items) > 8 and process_pool_available():
        with ProcessPoolExecutor(max_workers=args.jobs) as executor:
            futures = [
                executor.submit(
                    analyze_ip_behaviors_worker,
                    ip,
                    ip_rows,
                    args,
                    runtime.detector_config,
                    tuple(args.bot_pattern),
                )
                for ip, ip_rows in work_items
            ]
            for future in futures:
                ip, proofs = future.result()
                if proofs:
                    forced[ip] = proofs
    else:
        for ip, ip_rows in work_items:
            ip, proofs = analyze_ip_behaviors(ip, ip_rows, args, runtime)
            if proofs:
                forced[ip] = proofs

    return forced


def print_report(
    ip_stats: dict[str, IPStats],
    parsed: int,
    matched: int,
    args: argparse.Namespace,
    runtime: AuditRuntime,
    forced_bot_ips: set[str],
    forced_proofs: dict[str, list[ForcedProof]],
    coordinated_analysis: CoordinatedUAAnalysis,
    target_fanout_analysis: CoordinatedUAAnalysis,
    payload_analysis: PayloadCampaignAnalysis,
) -> None:
    suspects = [
        stats
        for stats in ip_stats.values()
        if is_effective_bot(stats, args, forced_bot_ips)
    ]
    suspects.sort(key=lambda s: (-s.score(args), -s.total, s.ip))

    clean_requests = sum(
        stats.total
        for stats in ip_stats.values()
        if not is_effective_bot(stats, args, forced_bot_ips)
    )
    suspect_requests = sum(stats.total for stats in suspects)

    print(f"parsed_lines={parsed}")
    print(f"matched_lines={matched}")
    print(f"bot_ips={len(suspects)}")
    print(f"bot_requests={suspect_requests}")
    print(f"clean_requests={clean_requests}")
    if (
        coordinated_analysis.degraded
        or target_fanout_analysis.degraded
        or payload_analysis.degraded
    ):
        print("detector_health:")
        if coordinated_analysis.degraded:
            print(
                f"  coordinated-ua: degraded ({coordinated_analysis.degraded_reason})"
            )
        if target_fanout_analysis.degraded:
            print(
                "  coordinated-target-fanout: degraded "
                f"({target_fanout_analysis.degraded_reason})"
            )
        if payload_analysis.degraded:
            print(f"  payload-campaign: degraded ({payload_analysis.degraded_reason})")
    print()
    print("top_suspects:")

    for stats in suspects[: args.report_top]:
        reasons = summarize_reasons(stats, args)
        proofs = dedupe_proofs(forced_proofs.get(stats.ip, []))
        proof_kinds = ",".join(dict.fromkeys(proof.kind for proof in proofs))
        if proof_kinds:
            reasons = proof_kinds if reasons == "-" else f"{reasons},{proof_kinds}"
        ua = top_counter(stats.user_agents, limit=2)
        referers = top_counter(stats.referers, limit=2)
        provider = provider_label(provider_match_for_ip(runtime, stats.ip))
        proof_detail = " | ".join(proof.detail for proof in proofs[:2]) or "-"
        print(
            f"{stats.ip}\trequests={stats.total}\tscore={stats.score(args):.1f}\t"
            f"burst={stats.max_burst}\tunique_window={stats.max_unique_paths_window}\t"
            f"heads={stats.methods['HEAD']}\tstreak={stats.max_small_gap_streak}\t"
            f"provider={provider}\treasons={reasons}\tproof={proof_detail}\t"
            f"ua={ua}\treferer={referers}"
        )

    if payload_analysis.summaries and args.campaign_report_top > 0:
        print()
        print("payload_campaigns:")
        for campaign in payload_analysis.summaries[: args.campaign_report_top]:
            start = datetime.fromtimestamp(campaign.first_ts).strftime("%m-%d %H:%M:%S")
            end = datetime.fromtimestamp(campaign.last_ts).strftime("%m-%d %H:%M:%S")
            print(
                f"{campaign.family}\trequests={campaign.request_count}\tips={campaign.unique_ips}\t"
                f"unique_paths={campaign.unique_paths}\twindow={start}..{end}\t"
                f"paths={', '.join(campaign.sample_paths) or '-'}\t"
                f"ips_sample={', '.join(campaign.sample_ips) or '-'}"
            )

    if args.clean_report_top > 0:
        clean = [
            stats
            for stats in ip_stats.values()
            if not is_effective_bot(stats, args, forced_bot_ips)
        ]
        clean.sort(key=lambda s: (-s.total, s.ip))
        print()
        print("top_clean_ips:")
        for stats in clean[: args.clean_report_top]:
            referers = top_counter(stats.referers, limit=2)
            provider = provider_label(provider_match_for_ip(runtime, stats.ip))
            print(
                f"{stats.ip}\trequests={stats.total}\tmethods={dict(stats.methods)}\t"
                f"provider={provider}\treferer={referers}"
            )


def print_recent_view(
    all_rows: list[RequestRow],
    args: argparse.Namespace,
    runtime: AuditRuntime,
    bot_ips: set[str],
    inverse: bool = False,
) -> None:
    rows: deque[RequestRow] = deque(maxlen=args.recent_limit)
    for row in all_rows:
        is_bot = row.ip in bot_ips
        if inverse:
            if is_bot:
                rows.append(row)
        else:
            if not is_bot:
                rows.append(row)

    if not rows:
        print("no matching rows")
        return

    sorted_rows = sorted(
        rows,
        key=lambda row: (row.ts, row.ip, row.ua, row.path, row.method, row.status),
    )

    grouped: dict[tuple[str, str], list[RequestRow]] = {}
    for row in sorted_rows:
        key = (row.ip, row.ua)
        grouped.setdefault(key, []).append(row)

    ordered_groups = sorted(
        grouped.items(),
        key=lambda item: (item[1][0].ts, item[0][0], item[0][1]),
    )

    for (ip, ua_raw), group_rows in ordered_groups:
        ua = summarize_ua(ua_raw, args.ua_width)
        provider = provider_label(provider_match_for_ip(runtime, ip))
        provider_part = "" if provider == "-" else f"  provider={provider}"
        print(f"{ip:<15}  {ua}{provider_part}")
        if args.show_raw_ua:
            print(f"{'':15}  ua* {shorten(ua_raw, args.raw_ua_width)}")
        for row in group_rows:
            referer = compact_referer(row.referer, args.referer_width)
            print(
                f"  #{row.input_index:04d} {compact_ts(row.raw_ts):>14}  {row.method:<4} {row.status:>3}  "
                f"{shorten(row.path, args.path_width)}"
            )
            print(f"{'':24}  ref {referer}")
        print()


def emit_filtered(
    path: Path, rows: list[RequestRow], bot_ips: set[str], inverse: bool
) -> None:
    with path.open("rb") as handle:
        for row in rows:
            is_bot = row.ip in bot_ips
            if inverse:
                if not is_bot:
                    continue
            else:
                if is_bot:
                    continue
            handle.seek(row.line_start)
            raw = handle.read(row.line_len)
            sys.stdout.write(raw.decode("utf-8", errors="replace"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Detect and filter bursty sequential crawler traffic from access logs."
    )
    parser.add_argument(
        "input", nargs="?", help="Path to access log. Reads stdin when omitted."
    )
    parser.add_argument(
        "--path-include",
        action="append",
        default=[],
        help="Regex to include request paths.",
    )
    parser.add_argument(
        "--path-exclude",
        action="append",
        default=[],
        help="Regex to exclude request paths.",
    )
    parser.add_argument(
        "--bot-pattern",
        action="append",
        default=[],
        help="Additional regex marking known bot UAs or referers.",
    )
    parser.add_argument(
        "--detector-config",
        action="append",
        default=[],
        help="JSON file with detector defaults such as known_bot_any_patterns.",
    )
    parser.add_argument(
        "--no-default-detector-config",
        action="store_true",
        help="Disable the built-in shipped detector defaults.",
    )
    parser.add_argument(
        "--provider-ranges",
        action="append",
        default=[],
        help="Optional provider IP range source path. Repeat to load multiple sources.",
    )
    parser.add_argument(
        "--provider-source-format",
        choices=("auto", *provider_source_names()),
        default="auto",
        help="Optional provider range source adapter override; default auto-detects.",
    )
    parser.add_argument(
        "--provider-include",
        action="append",
        default=[],
        help="Only load this provider from provider range sources. Repeatable.",
    )
    parser.add_argument(
        "--provider-exclude",
        action="append",
        default=[],
        help="Exclude this provider from provider range sources. Repeatable.",
    )
    parser.add_argument(
        "--provider-watch",
        action="append",
        default=[],
        help="Opt-in provider name for provider-hosted activity proofs. Use '*' for all loaded providers.",
    )
    parser.add_argument(
        "--exclude-provider-traffic",
        action="store_true",
        help=(
            "Treat all traffic matching loaded provider ranges as filtered "
            "provider-hosted traffic."
        ),
    )
    parser.add_argument(
        "--provider-request-count",
        type=int,
        default=20,
        help="Requests from a watched provider before provider-hosted activity can fire.",
    )
    parser.add_argument(
        "--provider-unique-paths",
        type=int,
        default=12,
        help="Unique paths from a watched provider before provider-hosted activity can fire.",
    )
    parser.add_argument(
        "--provider-min-score",
        type=float,
        default=6.0,
        help="Minimum existing behavior score before provider-hosted activity can fire.",
    )
    parser.add_argument(
        "--window-seconds",
        type=float,
        default=2.0,
        help="Sliding burst window in seconds.",
    )
    parser.add_argument(
        "--burst-count",
        type=int,
        default=12,
        help="Requests in window to mark as bursty.",
    )
    parser.add_argument(
        "--unique-paths",
        type=int,
        default=8,
        help="Unique paths in burst window to mark as sequential.",
    )
    parser.add_argument(
        "--head-burst",
        type=int,
        default=6,
        help="HEAD requests in window to mark as suspicious.",
    )
    parser.add_argument(
        "--head-unique-paths",
        type=int,
        default=4,
        help="Unique paths paired with HEAD burst.",
    )
    parser.add_argument(
        "--sweep-window-seconds",
        type=float,
        default=45.0,
        help="Window for paced sequential sweeps.",
    )
    parser.add_argument(
        "--sweep-count",
        type=int,
        default=10,
        help="Requests in sweep window to mark as suspicious.",
    )
    parser.add_argument(
        "--sweep-unique-paths",
        type=int,
        default=8,
        help="Unique paths in sweep window to mark as suspicious.",
    )
    parser.add_argument(
        "--sweep-dominant-referer-ratio",
        type=float,
        default=0.7,
        help="Dominant referer ratio required for paced sweep detection.",
    )
    parser.add_argument(
        "--coord-window-seconds",
        type=float,
        default=45.0,
        help="Window for coordinated same-UA multi-IP sweeps.",
    )
    parser.add_argument(
        "--coord-count",
        type=int,
        default=10,
        help="Requests in coordinated UA window to mark as suspicious.",
    )
    parser.add_argument(
        "--coord-unique-paths",
        type=int,
        default=8,
        help="Unique paths in coordinated UA window.",
    )
    parser.add_argument(
        "--coord-unique-ips",
        type=int,
        default=3,
        help="Distinct IPs required for coordinated UA detection.",
    )
    parser.add_argument(
        "--coord-max-ip-share",
        type=float,
        default=0.6,
        help="Largest single-IP share allowed in a coordinated UA window.",
    )
    parser.add_argument(
        "--coord-max-rows",
        type=int,
        default=250000,
        help="Max matching rows to sort for coordinated UA detection.",
    )
    parser.add_argument(
        "--target-fanout-window-seconds",
        type=float,
        default=600.0,
        help="Window for distributed same-target same-UA fanout detection.",
    )
    parser.add_argument(
        "--target-fanout-count",
        type=int,
        default=5,
        help="Requests in focused target fanout window before flagging.",
    )
    parser.add_argument(
        "--target-fanout-unique-ips",
        type=int,
        default=5,
        help="Distinct IPs required for focused target fanout detection.",
    )
    parser.add_argument(
        "--target-fanout-max-ip-share",
        type=float,
        default=0.5,
        help="Largest single-IP share allowed in a focused target fanout window.",
    )
    parser.add_argument(
        "--target-fanout-dominant-referer-ratio",
        type=float,
        default=0.8,
        help="Dominant referer ratio required for focused target fanout detection.",
    )
    parser.add_argument(
        "--target-fanout-same-ua-window-seconds",
        type=float,
        default=5.0,
        help=("Tight window for exact-UA same-target distributed fanout detection."),
    )
    parser.add_argument(
        "--target-fanout-same-ua-count",
        type=int,
        default=3,
        help="Requests in exact-UA same-target fanout window before flagging.",
    )
    parser.add_argument(
        "--target-fanout-same-ua-unique-ips",
        type=int,
        default=3,
        help="Distinct IPs required for exact-UA same-target fanout detection.",
    )
    parser.add_argument(
        "--target-fanout-max-rows",
        type=int,
        default=250000,
        help="Max matching rows to sort for focused target fanout detection.",
    )
    parser.add_argument(
        "--pair-gap-seconds",
        type=float,
        default=8.0,
        help="Max gap between repeated pair requests.",
    )
    parser.add_argument(
        "--pair-repeat-count",
        type=int,
        default=8,
        help="Repeated pair count to mark an IP suspicious.",
    )
    parser.add_argument(
        "--multi-fetch-window-seconds",
        type=float,
        default=30.0,
        help="Window for tight same-IP multi-path fetch clusters.",
    )
    parser.add_argument(
        "--multi-fetch-count",
        type=int,
        default=4,
        help="Requests in a tight multi-fetch cluster before flagging.",
    )
    parser.add_argument(
        "--multi-fetch-unique-paths",
        type=int,
        default=2,
        help="Distinct non-asset base paths required in a tight multi-fetch cluster.",
    )
    parser.add_argument(
        "--multi-fetch-repeat-paths",
        type=int,
        default=2,
        help="Repeated base paths required in a tight multi-fetch cluster.",
    )
    parser.add_argument(
        "--multi-fetch-same-second-unique-paths",
        type=int,
        default=2,
        help="Distinct base paths fetched in one exact second before flagging a tight cluster.",
    )
    parser.add_argument(
        "--multi-fetch-dominant-referer-ratio",
        type=float,
        default=0.8,
        help="Dominant referer ratio required for tight multi-fetch detection.",
    )
    parser.add_argument(
        "--exposure-probe-window-seconds",
        type=float,
        default=10.0,
        help="Window for asset-backed exposed-file probe detection.",
    )
    parser.add_argument(
        "--exposure-probe-asset-count",
        type=int,
        default=2,
        help="Same-page dependency requests required before exposed-file probing.",
    )
    parser.add_argument(
        "--exposure-probe-count",
        type=int,
        default=2,
        help="Distinct exposed-file probe paths required after page dependency loading.",
    )
    parser.add_argument(
        "--revisit-paths",
        type=int,
        default=5,
        help="Distinct revisited base paths before flagging a low-rate revisit crawler.",
    )
    parser.add_argument(
        "--revisit-repeat-requests",
        type=int,
        default=10,
        help="Extra repeat requests across revisited paths before flagging.",
    )
    parser.add_argument(
        "--revisit-dominant-referer-ratio",
        type=float,
        default=0.8,
        help="Dominant referer ratio required for redundant revisit detection.",
    )
    parser.add_argument(
        "--cadence-repeat-count",
        type=int,
        default=3,
        help="Long-gap same-path repeats before flagging a cadenced fetcher.",
    )
    parser.add_argument(
        "--cadence-min-gap-seconds",
        type=float,
        default=3000.0,
        help="Minimum gap between cadenced same-path repeats.",
    )
    parser.add_argument(
        "--cadence-gap-tolerance-seconds",
        type=float,
        default=5.0,
        help="Allowed spread between cadenced same-path repeat gaps.",
    )
    parser.add_argument(
        "--cadence-dominant-referer-ratio",
        type=float,
        default=0.8,
        help="Dominant referer ratio required for cadenced repeat detection.",
    )
    parser.add_argument(
        "--cadence-hour-repeat-count",
        type=int,
        default=2,
        help="Same-path hits needed for near-hour cadence shortcut detection.",
    )
    parser.add_argument(
        "--cadence-hour-gap-seconds",
        type=float,
        default=3600.0,
        help="Target gap for near-hour same-path cadence detection.",
    )
    parser.add_argument(
        "--cadence-hour-gap-tolerance-seconds",
        type=float,
        default=120.0,
        help="Allowed absolute drift from the near-hour cadence target.",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=1,
        help="Worker processes for embarrassingly parallel per-IP detectors.",
    )
    parser.add_argument(
        "--parallel-min-bytes",
        type=int,
        default=8_000_000,
        help="Minimum input size before parallel parse is used.",
    )
    parser.add_argument(
        "--parallel-chunk-bytes",
        type=int,
        default=32_000_000,
        help="Target chunk size for parallel byte-range parsing.",
    )
    parser.add_argument(
        "--rotate-ua-count",
        type=int,
        default=6,
        help="Distinct raw UAs from one IP before flagging.",
    )
    parser.add_argument(
        "--rotate-ua-family-count",
        type=int,
        default=4,
        help="Distinct UA families from one IP before flagging.",
    )
    parser.add_argument(
        "--poll-repeat-count",
        type=int,
        default=6,
        help="Repeated same-path polls before flagging.",
    )
    parser.add_argument(
        "--poll-min-gap-seconds",
        type=int,
        default=3000,
        help="Minimum periodic poll interval in seconds.",
    )
    parser.add_argument(
        "--serial-min-gap-seconds",
        type=float,
        default=0.8,
        help="Min gap for long serial sweep detector.",
    )
    parser.add_argument(
        "--serial-max-gap-seconds",
        type=float,
        default=3.5,
        help="Max gap for long serial sweep detector.",
    )
    parser.add_argument(
        "--serial-count",
        type=int,
        default=12,
        help="Serial sweep request count before flagging.",
    )
    parser.add_argument(
        "--serial-unique-paths",
        type=int,
        default=10,
        help="Unique paths required for serial sweep detector.",
    )
    parser.add_argument(
        "--payload-pair-gap-seconds",
        type=float,
        default=8.0,
        help="Max gap for mutated same-page payload-marker fuzz pairs.",
    )
    parser.add_argument(
        "--payload-show-analysis-count",
        type=int,
        default=12,
        help="Minimum payload-marker requests before payload-fuzzer can fire.",
    )
    parser.add_argument(
        "--payload-injection-count",
        type=int,
        default=3,
        help="Minimum explicit injection payload requests before flagging.",
    )
    parser.add_argument(
        "--payload-referer-junk-count",
        type=int,
        default=6,
        help="Minimum malformed referer count before flagging.",
    )
    parser.add_argument(
        "--payload-mutation-count",
        type=int,
        default=4,
        help="Minimum mutated same-page payload-marker pairs before flagging.",
    )
    parser.add_argument(
        "--same-second-ua-swap-count",
        type=int,
        default=1,
        help="Same-IP same-second mutated payload-marker pairs with different UAs before flagging.",
    )
    parser.add_argument(
        "--ua-switch-window-seconds",
        type=float,
        default=2.0,
        help="Window for detecting same-IP rapid UA switching.",
    )
    parser.add_argument(
        "--ua-switch-count",
        type=int,
        default=2,
        help="Requests in the UA switch window before flagging.",
    )
    parser.add_argument(
        "--ua-switch-distinct-uas",
        type=int,
        default=2,
        help="Distinct raw UAs in the UA switch window before flagging.",
    )
    parser.add_argument(
        "--ua-switch-distinct-families",
        type=int,
        default=2,
        help="Distinct UA families in the UA switch window before flagging.",
    )
    parser.add_argument(
        "--payload-campaign-window-seconds",
        type=float,
        default=120.0,
        help="Window for distributed payload-fuzzing campaign detection.",
    )
    parser.add_argument(
        "--payload-campaign-count",
        type=int,
        default=8,
        help="Requests in payload campaign window before flagging.",
    )
    parser.add_argument(
        "--payload-campaign-unique-ips",
        type=int,
        default=3,
        help="Distinct IPs required for payload campaign detection.",
    )
    parser.add_argument(
        "--payload-campaign-unique-paths",
        type=int,
        default=4,
        help="Distinct paths required for payload campaign detection.",
    )
    parser.add_argument(
        "--payload-campaign-max-rows",
        type=int,
        default=250000,
        help="Max candidate rows to scan for payload campaign detection.",
    )
    parser.add_argument(
        "--streak-gap",
        type=float,
        default=1.0,
        help="Max seconds between requests for a fast streak.",
    )
    parser.add_argument(
        "--streak-count",
        type=int,
        default=20,
        help="Fast sequential requests before flagging.",
    )
    parser.add_argument(
        "--streak-unique-total",
        type=int,
        default=12,
        help="Distinct paths required for fast streak rule.",
    )
    parser.add_argument(
        "--report-top",
        type=int,
        default=25,
        help="Number of suspect IPs to show in the report.",
    )
    parser.add_argument(
        "--campaign-report-top",
        type=int,
        default=8,
        help="Number of distributed payload campaign clusters to show in summary.",
    )
    parser.add_argument(
        "--clean-report-top",
        type=int,
        default=10,
        help="Number of non-bot IPs to show in summary.",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Show classifier summary report instead of recent request view.",
    )
    parser.add_argument(
        "--raw-filtered-lines",
        dest="raw_filtered_output",
        action="store_true",
        help=(
            "Emit raw access-log lines after filtering instead of the grouped "
            "recent view."
        ),
    )
    parser.add_argument(
        "--bots-only",
        action="store_true",
        help="Invert output selection to bot-classified or excluded-provider traffic.",
    )
    parser.add_argument(
        "--recent-limit",
        type=int,
        default=200,
        help="Number of recent matching requests to display in view mode.",
    )
    parser.add_argument(
        "--ua-width",
        type=int,
        default=44,
        help="Width for compact UA summary in recent view.",
    )
    parser.add_argument(
        "--referer-width",
        type=int,
        default=72,
        help="Width for compact referer display in recent view.",
    )
    parser.add_argument(
        "--path-width",
        type=int,
        default=72,
        help="Width for request path display in recent view.",
    )
    parser.add_argument(
        "--show-raw-ua",
        action="store_true",
        help="Also print the raw user agent in recent view.",
    )
    parser.add_argument(
        "--raw-ua-width",
        type=int,
        default=120,
        help="Width for raw UA display in recent view.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    args.jobs = max(1, min(getattr(args, "jobs", 1), os.cpu_count() or 1))
    try:
        args.detector_config = resolve_detector_config(args)
        runtime = build_runtime(args)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))

    source_path, temporary = spool_input(args.input)
    try:
        analysis = collect_rows_and_stats(source_path, args, runtime)
        forced_proofs = detect_behavioral_bots(analysis.rows_by_ip, args, runtime)
        coordinated_analysis = detect_coordinated_ua_ips(analysis.rows, args)
        for ip, proofs in coordinated_analysis.forced_proofs_by_ip.items():
            forced_proofs.setdefault(ip, []).extend(proofs)
        target_fanout_analysis = detect_coordinated_target_fanout(analysis.rows, args)
        for ip, proofs in target_fanout_analysis.forced_proofs_by_ip.items():
            forced_proofs.setdefault(ip, []).extend(proofs)
        payload_campaign_analysis = analyze_payload_campaigns(
            analysis.rows, args, runtime
        )
        for ip, proofs in payload_campaign_analysis.forced_proofs_by_ip.items():
            forced_proofs.setdefault(ip, []).extend(proofs)
        for ip, proofs in detect_provider_activity(
            analysis.ip_stats, args, runtime
        ).items():
            forced_proofs.setdefault(ip, []).extend(proofs)
        for ip, proofs in detect_provider_exclusions(
            analysis.ip_stats, args, runtime
        ).items():
            forced_proofs.setdefault(ip, []).extend(proofs)
        bot_ips = {ip for ip, stats in analysis.ip_stats.items() if stats.is_bot(args)}
        bot_ips |= set(forced_proofs.keys())

        if args.raw_filtered_output:
            emit_filtered(source_path, analysis.rows, bot_ips, inverse=args.bots_only)
        elif args.summary:
            if args.bots_only:
                filtered_stats = {
                    ip: stats
                    for ip, stats in analysis.ip_stats.items()
                    if ip in bot_ips
                }
                print_report(
                    filtered_stats,
                    analysis.parsed_lines,
                    analysis.matched_lines,
                    args,
                    runtime,
                    bot_ips,
                    forced_proofs,
                    coordinated_analysis,
                    target_fanout_analysis,
                    payload_campaign_analysis,
                )
            else:
                print_report(
                    analysis.ip_stats,
                    analysis.parsed_lines,
                    analysis.matched_lines,
                    args,
                    runtime,
                    bot_ips,
                    forced_proofs,
                    coordinated_analysis,
                    target_fanout_analysis,
                    payload_campaign_analysis,
                )
        else:
            print_recent_view(
                analysis.rows, args, runtime, bot_ips, inverse=args.bots_only
            )
    finally:
        if temporary:
            with contextlib.suppress(OSError):
                source_path.unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
