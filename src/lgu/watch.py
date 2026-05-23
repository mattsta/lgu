#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import signal
import sys
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

from .audit import (
    AuditRuntime,
    CampaignSummary,
    CoordinatedUAAnalysis,
    ForcedProof,
    IPStats,
    PayloadCampaignAnalysis,
    RequestRow,
    analyze_ip_behaviors,
    base_path,
    build_ip_stats,
    build_runtime,
    compact_referer,
    compact_ts,
    evaluate_ip_decision,
    is_low_context_fanout_candidate,
    low_context_referer_key,
    parse_log_line,
    parse_request,
    parse_timestamp,
    payload_campaign_key,
    provider_activity_proofs,
    provider_exclusion_proofs,
    provider_label,
    provider_match_for_ip,
    resolve_detector_config,
    shorten,
    summarize_ua,
    ua_family,
    update_stats,
)
from .audit import (
    build_parser as build_batch_parser,
)

if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)


@dataclass(slots=True)
class LiveIPState:
    rows: deque[RequestRow] = field(default_factory=deque)
    stats: IPStats | None = None
    last_action: str = "clean"
    last_reasons: tuple[str, ...] = ()
    last_score: float = 0.0
    last_emitted_ts: float = 0.0


@dataclass(slots=True)
class CoordinatedUAWindow:
    rows: deque[RequestRow] = field(default_factory=deque)
    path_counts: Counter[str] = field(default_factory=Counter)
    ip_counts: Counter[str] = field(default_factory=Counter)
    degraded: bool = False


@dataclass(slots=True)
class PayloadCampaignWindow:
    family: str
    rows: deque[RequestRow] = field(default_factory=deque)
    ip_counts: Counter[str] = field(default_factory=Counter)
    path_counts: Counter[str] = field(default_factory=Counter)
    degraded: bool = False
    best_summary: CampaignSummary | None = None


@dataclass(slots=True)
class TargetFanoutWindow:
    family: str
    path: str
    rows: deque[RequestRow] = field(default_factory=deque)
    ip_counts: Counter[str] = field(default_factory=Counter)
    referer_counts: Counter[str] = field(default_factory=Counter)
    ua_counts: Counter[str] = field(default_factory=Counter)
    degraded: bool = False


@dataclass(slots=True)
class LowContextFanoutWindow:
    path: str
    ref_key: str
    rows: deque[RequestRow] = field(default_factory=deque)
    ip_counts: Counter[str] = field(default_factory=Counter)
    ua_family_counts: Counter[str] = field(default_factory=Counter)
    degraded: bool = False


@dataclass(slots=True)
class LiveContext:
    runtime: AuditRuntime
    ip_states: dict[str, LiveIPState] = field(default_factory=dict)
    coordinated_windows: dict[str, CoordinatedUAWindow] = field(default_factory=dict)
    payload_windows: dict[str, PayloadCampaignWindow] = field(default_factory=dict)
    target_fanout_windows: dict[tuple[str, str], TargetFanoutWindow] = field(
        default_factory=dict
    )
    target_same_ua_fanout_windows: dict[tuple[str, str], TargetFanoutWindow] = field(
        default_factory=dict
    )
    low_context_fanout_windows: dict[tuple[str, str], LowContextFanoutWindow] = field(
        default_factory=dict
    )
    ts_cache: dict[str, float] = field(default_factory=dict)
    last_summary_ts: float = 0.0
    last_gc_ts: float = 0.0
    last_status_ts: float = 0.0
    emitted_counts: Counter[str] = field(default_factory=Counter)
    detector_flags: set[str] = field(default_factory=set)


@dataclass(slots=True)
class LiveDecision:
    action: str
    ip: str
    ts: float
    raw_ts: str
    score: float
    reasons: tuple[str, ...]
    proof_detail: str
    path: str
    ua: str
    referer: str
    provider: str = "-"


def build_parser() -> argparse.ArgumentParser:
    parser = build_batch_parser()
    parser.description = (
        "Stream access log updates and emit human or machine-readable bot alerts."
    )
    suppress_dests = {
        "summary",
        "filter",
        "bots_only",
        "recent_limit",
        "ua_width",
        "referer_width",
        "path_width",
        "show_raw_ua",
        "raw_ua_width",
        "report_top",
        "campaign_report_top",
        "clean_report_top",
        "raw_filtered_output",
    }
    for action in parser._actions:
        if action.dest in suppress_dests:
            action.help = argparse.SUPPRESS
    parser.add_argument(
        "--follow",
        action="store_true",
        help="Follow the input file for appended lines. When omitted, reads stdin or a static file once.",
    )
    parser.add_argument(
        "--output-format",
        choices=("human", "json", "fail2ban"),
        default="human",
        help="Alert output format.",
    )
    parser.add_argument(
        "--emit-suspects",
        action="store_true",
        help="Also emit suspect transitions, not just ban transitions.",
    )
    parser.add_argument(
        "--ban-score",
        type=float,
        default=12.0,
        help="Minimum score for live ban emission when detector proofs are not already decisive.",
    )
    parser.add_argument(
        "--suspect-score",
        type=float,
        default=6.0,
        help="Minimum score for suspect emission.",
    )
    parser.add_argument(
        "--cooldown-seconds",
        type=float,
        default=600.0,
        help="Minimum seconds before re-emitting the same action for the same IP.",
    )
    parser.add_argument(
        "--summary-interval-seconds",
        type=float,
        default=60.0,
        help="Periodic live summary interval. Set to 0 to disable.",
    )
    parser.add_argument(
        "--live-ip-memory-seconds",
        type=float,
        default=21600.0,
        help="How long to retain per-IP rows for streaming analysis.",
    )
    parser.add_argument(
        "--live-global-memory-seconds",
        type=float,
        default=180.0,
        help="How long to retain global rows for coordinated campaign analysis.",
    )
    parser.add_argument(
        "--alerts-log",
        help="Optional file to append emitted alert lines to.",
    )
    parser.add_argument(
        "--fail2ban-action",
        default="ban",
        help="Action string to emit in fail2ban mode.",
    )
    parser.add_argument(
        "--top-summary",
        type=int,
        default=8,
        help="Number of suspicious IPs to include in periodic human summaries.",
    )
    parser.add_argument(
        "--status-interval-seconds",
        type=float,
        default=60.0,
        help="Periodic human health/status interval. Set to 0 to disable.",
    )
    return parser


def iter_follow(path: Path, poll_interval: float = 0.5) -> TextIO:
    handle = path.open("r", encoding="utf-8", errors="replace")
    handle.seek(0, os.SEEK_END)
    current_inode = path.stat().st_ino
    try:
        while True:
            line = handle.readline()
            if line:
                yield line
                continue

            time.sleep(poll_interval)
            with_context = False
            try:
                new_inode = path.stat().st_ino
                if new_inode != current_inode:
                    handle.close()
                    handle = path.open("r", encoding="utf-8", errors="replace")
                    current_inode = new_inode
                    with_context = True
            except FileNotFoundError:
                with_context = True

            if with_context:
                continue
    finally:
        handle.close()


def decision_priority(action: str) -> int:
    if action == "ban":
        return 2
    if action == "suspect":
        return 1
    return 0


def format_human(decision: LiveDecision) -> str:
    provider = "" if decision.provider == "-" else f" provider={decision.provider}"
    return (
        f"[{compact_ts(decision.raw_ts)}] {decision.action.upper():<7} ip={decision.ip} "
        f"score={decision.score:.1f} reasons={','.join(decision.reasons) or '-'} "
        f"path={shorten(decision.path, 72)} ua={summarize_ua(decision.ua, 44)} "
        f"ref={compact_referer(decision.referer, 48)}{provider}"
    )


def format_json(decision: LiveDecision) -> str:
    return json.dumps(
        {
            "ts": datetime.fromtimestamp(decision.ts, UTC).isoformat(),
            "action": decision.action,
            "ip": decision.ip,
            "score": round(decision.score, 2),
            "reasons": list(decision.reasons),
            "proof": decision.proof_detail,
            "provider": decision.provider,
            "path": decision.path,
            "ua": decision.ua,
            "referer": decision.referer,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def format_fail2ban(decision: LiveDecision, action: str) -> str:
    provider = "" if decision.provider == "-" else f" provider={decision.provider}"
    return (
        f"{datetime.fromtimestamp(decision.ts, UTC).strftime('%Y-%m-%dT%H:%M:%SZ')} "
        f"action={action} ip={decision.ip} score={decision.score:.1f} "
        f"reasons={','.join(decision.reasons) or '-'} path={decision.path}{provider}"
    )


def write_alert(line: str, args: argparse.Namespace) -> None:
    try:
        print(line, flush=True)
    except BrokenPipeError:
        raise SystemExit(0)
    if args.alerts_log:
        with Path(args.alerts_log).open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def emit_decision(decision: LiveDecision, args: argparse.Namespace) -> None:
    if args.output_format == "json":
        write_alert(format_json(decision), args)
    elif args.output_format == "fail2ban":
        write_alert(format_fail2ban(decision, args.fail2ban_action), args)
    else:
        write_alert(format_human(decision), args)


def maybe_emit_summary(
    now_ts: float, context: LiveContext, args: argparse.Namespace
) -> None:
    if args.output_format != "human" or args.summary_interval_seconds <= 0:
        return
    if now_ts - context.last_summary_ts < args.summary_interval_seconds:
        return
    context.last_summary_ts = now_ts

    suspicious = []
    for ip, state in context.ip_states.items():
        if state.last_action == "clean" or not state.rows:
            continue
        if state.last_action == "suspect" and not args.emit_suspects:
            continue
        if state.stats is None:
            continue
        suspicious.append(
            (
                -decision_priority(state.last_action),
                -state.last_score,
                ip,
                state.stats,
                state,
            )
        )
    suspicious.sort()
    if not suspicious:
        return

    try:
        print(flush=True)
        print(
            f"top_live_suspects {datetime.fromtimestamp(now_ts, UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}",
            flush=True,
        )
        for index, (_, _, ip, stats, state) in enumerate(
            suspicious[: args.top_summary], start=1
        ):
            print(
                f"{index}. ip={ip} action={state.last_action} score={state.last_score:.1f} "
                f"requests={stats.total} reasons={','.join(state.last_reasons) or '-'}",
                flush=True,
            )
        print(flush=True)
    except BrokenPipeError:
        raise SystemExit(0)


def maybe_emit_status(
    now_ts: float, context: LiveContext, args: argparse.Namespace
) -> None:
    if args.output_format != "human" or args.status_interval_seconds <= 0:
        return
    if now_ts - context.last_status_ts < args.status_interval_seconds:
        return
    context.last_status_ts = now_ts
    degraded = ",".join(sorted(context.detector_flags)) or "-"
    target_window_count = len(context.target_fanout_windows) + len(
        context.target_same_ua_fanout_windows
    )
    try:
        print(
            "live_status "
            f"{datetime.fromtimestamp(now_ts, UTC).strftime('%Y-%m-%dT%H:%M:%SZ')} "
            f"active_ips={len(context.ip_states)} "
            f"ua_windows={len(context.coordinated_windows)} "
            f"campaign_windows={len(context.payload_windows)} "
            f"target_windows={target_window_count} "
            f"low_context_windows={len(context.low_context_fanout_windows)} "
            f"emitted_suspects={context.emitted_counts['suspect']} "
            f"emitted_bans={context.emitted_counts['ban']} "
            f"degraded={degraded}",
            flush=True,
        )
    except BrokenPipeError:
        raise SystemExit(0)


def prune_ip_rows(state: LiveIPState, now_ts: float, args: argparse.Namespace) -> bool:
    cutoff = now_ts - args.live_ip_memory_seconds
    pruned = False
    while state.rows and state.rows[0].ts < cutoff:
        state.rows.popleft()
        pruned = True
    return pruned


def refresh_ip_stats(
    ip: str, state: LiveIPState, runtime: AuditRuntime, args: argparse.Namespace
) -> IPStats:
    if not state.rows:
        state.stats = IPStats(ip=ip)
        return state.stats
    rebuilt = build_ip_stats(list(state.rows), args, runtime).get(ip)
    state.stats = rebuilt or IPStats(ip=ip)
    return state.stats


def update_ip_state(
    ip: str,
    row: RequestRow,
    state: LiveIPState,
    runtime: AuditRuntime,
    args: argparse.Namespace,
) -> IPStats:
    state.rows.append(row)
    expired = prune_ip_rows(state, row.ts, args)
    if state.stats is None or expired:
        return refresh_ip_stats(ip, state, runtime, args)
    update_stats(
        stats=state.stats,
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
    return state.stats


def update_coordinated_window(
    row: RequestRow, context: LiveContext, args: argparse.Namespace
) -> CoordinatedUAAnalysis:
    window = context.coordinated_windows.setdefault(row.ua, CoordinatedUAWindow())
    window.rows.append(row)
    window.path_counts[row.path] += 1
    window.ip_counts[row.ip] += 1
    cutoff = row.ts - args.coord_window_seconds
    while window.rows and window.rows[0].ts < cutoff:
        expired = window.rows.popleft()
        window.path_counts[expired.path] -= 1
        if window.path_counts[expired.path] <= 0:
            del window.path_counts[expired.path]
        window.ip_counts[expired.ip] -= 1
        if window.ip_counts[expired.ip] <= 0:
            del window.ip_counts[expired.ip]
    if not window.rows:
        context.coordinated_windows.pop(row.ua, None)
        return CoordinatedUAAnalysis(forced_proofs_by_ip={})
    if len(window.rows) > args.coord_max_rows:
        window.degraded = True
        while len(window.rows) > args.coord_max_rows:
            expired = window.rows.popleft()
            window.path_counts[expired.path] -= 1
            if window.path_counts[expired.path] <= 0:
                del window.path_counts[expired.path]
            window.ip_counts[expired.ip] -= 1
            if window.ip_counts[expired.ip] <= 0:
                del window.ip_counts[expired.ip]
        context.detector_flags.add("coordinated-ua")

    proofs: dict[str, list[ForcedProof]] = {}
    window_len = len(window.rows)
    unique_paths = len(window.path_counts)
    unique_ips = len(window.ip_counts)
    max_ip_share = max(window.ip_counts.values()) / window_len if window_len else 1.0
    if (
        window_len >= args.coord_count
        and unique_paths >= args.coord_unique_paths
        and unique_ips >= args.coord_unique_ips
        and max_ip_share <= args.coord_max_ip_share
    ):
        sample_paths = ", ".join(list(window.path_counts.keys())[:4])
        detail = (
            f"ua={summarize_ua(row.ua, 50)} ips={unique_ips} reqs={window_len} "
            f"unique={unique_paths} paths={sample_paths}"
        )
        for suspicious_ip in window.ip_counts:
            proofs.setdefault(suspicious_ip, []).append(
                ForcedProof(kind="coordinated-ua", detail=detail)
            )
    return CoordinatedUAAnalysis(
        forced_proofs_by_ip=proofs,
        degraded=window.degraded,
        degraded_reason=(
            f"bounded to most recent {args.coord_max_rows} rows for ua={summarize_ua(row.ua, 24)}"
            if window.degraded
            else ""
        ),
    )


def update_payload_window(
    row: RequestRow, context: LiveContext, args: argparse.Namespace
) -> PayloadCampaignAnalysis:
    family = payload_campaign_key(
        row.path, row.referer, context.runtime.payload_marker_patterns
    )
    if family is None:
        return PayloadCampaignAnalysis(forced_proofs_by_ip={}, summaries=[])

    window = context.payload_windows.setdefault(
        family, PayloadCampaignWindow(family=family)
    )
    window.rows.append(row)
    window.ip_counts[row.ip] += 1
    window.path_counts[row.path.split("?", 1)[0]] += 1
    cutoff = row.ts - args.payload_campaign_window_seconds
    while window.rows and window.rows[0].ts < cutoff:
        expired = window.rows.popleft()
        window.ip_counts[expired.ip] -= 1
        if window.ip_counts[expired.ip] <= 0:
            del window.ip_counts[expired.ip]
        expired_base = expired.path.split("?", 1)[0]
        window.path_counts[expired_base] -= 1
        if window.path_counts[expired_base] <= 0:
            del window.path_counts[expired_base]
    if not window.rows:
        context.payload_windows.pop(family, None)
        return PayloadCampaignAnalysis(forced_proofs_by_ip={}, summaries=[])
    if len(window.rows) > args.payload_campaign_max_rows:
        window.degraded = True
        while len(window.rows) > args.payload_campaign_max_rows:
            expired = window.rows.popleft()
            window.ip_counts[expired.ip] -= 1
            if window.ip_counts[expired.ip] <= 0:
                del window.ip_counts[expired.ip]
            expired_base = expired.path.split("?", 1)[0]
            window.path_counts[expired_base] -= 1
            if window.path_counts[expired_base] <= 0:
                del window.path_counts[expired_base]
        context.detector_flags.add("payload-campaign")

    summaries: list[CampaignSummary] = []
    proofs: dict[str, list[ForcedProof]] = {}
    window_len = len(window.rows)
    unique_ips = len(window.ip_counts)
    unique_paths = len(window.path_counts)
    if (
        window_len >= args.payload_campaign_count
        and unique_ips >= args.payload_campaign_unique_ips
        and unique_paths >= args.payload_campaign_unique_paths
    ):
        sample_paths = tuple(list(window.path_counts.keys())[:4])
        detail = (
            f"family={family} ips={unique_ips} reqs={window_len} "
            f"unique={unique_paths} paths={', '.join(sample_paths)}"
        )
        for suspicious_ip in window.ip_counts:
            proofs.setdefault(suspicious_ip, []).append(
                ForcedProof(kind="payload-campaign", detail=detail)
            )
        summary = CampaignSummary(
            family=family,
            request_count=window_len,
            unique_ips=unique_ips,
            unique_paths=unique_paths,
            first_ts=window.rows[0].ts,
            last_ts=window.rows[-1].ts,
            sample_paths=sample_paths,
            sample_ips=tuple(list(window.ip_counts.keys())[:4]),
        )
        window.best_summary = summary
        summaries.append(summary)
    return PayloadCampaignAnalysis(
        forced_proofs_by_ip=proofs,
        summaries=summaries,
        degraded=window.degraded,
        degraded_reason=(
            f"bounded to most recent {args.payload_campaign_max_rows} rows for family={family}"
            if window.degraded
            else ""
        ),
    )


def remove_target_fanout_row(window: TargetFanoutWindow, expired: RequestRow) -> None:
    window.ip_counts[expired.ip] -= 1
    if window.ip_counts[expired.ip] <= 0:
        del window.ip_counts[expired.ip]
    window.referer_counts[expired.referer] -= 1
    if window.referer_counts[expired.referer] <= 0:
        del window.referer_counts[expired.referer]
    window.ua_counts[expired.ua] -= 1
    if window.ua_counts[expired.ua] <= 0:
        del window.ua_counts[expired.ua]


def update_target_fanout_mode(
    row: RequestRow,
    windows: dict[tuple[str, str], TargetFanoutWindow],
    args: argparse.Namespace,
    *,
    key: tuple[str, str],
    mode: str,
    window_seconds: float,
    request_count: int,
    unique_ips_required: int,
) -> CoordinatedUAAnalysis:
    window = windows.setdefault(
        key, TargetFanoutWindow(family=ua_family(row.ua), path=base_path(row.path))
    )
    window.rows.append(row)
    window.ip_counts[row.ip] += 1
    window.referer_counts[row.referer] += 1
    window.ua_counts[row.ua] += 1

    cutoff = row.ts - window_seconds
    while window.rows and window.rows[0].ts < cutoff:
        remove_target_fanout_row(window, window.rows.popleft())

    if not window.rows:
        windows.pop(key, None)
        return CoordinatedUAAnalysis(forced_proofs_by_ip={})
    if len(window.rows) > args.target_fanout_max_rows:
        window.degraded = True
        while len(window.rows) > args.target_fanout_max_rows:
            remove_target_fanout_row(window, window.rows.popleft())

    proofs: dict[str, list[ForcedProof]] = {}
    window_len = len(window.rows)
    unique_ips = len(window.ip_counts)
    max_ip_share = max(window.ip_counts.values()) / window_len if window_len else 1.0
    dominant_referer_ratio = (
        max(window.referer_counts.values()) / window_len if window_len else 1.0
    )
    if (
        window_len >= request_count
        and unique_ips >= unique_ips_required
        and max_ip_share <= args.target_fanout_max_ip_share
        and dominant_referer_ratio >= args.target_fanout_dominant_referer_ratio
    ):
        ua_variants = len(window.ua_counts)
        detail_parts: list[str] = []
        if mode:
            detail_parts.append(f"mode={mode}")
        detail_parts.extend(
            (
                f"family={window.family}",
                f"sample-ua={summarize_ua(row.ua, 50)}",
                f"path={window.path}",
                f"ips={unique_ips}",
                f"reqs={window_len}",
                f"ua-variants={ua_variants}",
                f"ref-dom={dominant_referer_ratio:.0%}",
            )
        )
        detail = " ".join(detail_parts)
        for suspicious_ip in window.ip_counts:
            proofs.setdefault(suspicious_ip, []).append(
                ForcedProof(kind="coordinated-target-fanout", detail=detail)
            )
    return CoordinatedUAAnalysis(
        forced_proofs_by_ip=proofs,
        degraded=window.degraded,
        degraded_reason=(
            f"bounded to most recent {args.target_fanout_max_rows} rows for path={window.path}"
            if window.degraded
            else ""
        ),
    )


def update_target_fanout_window(
    row: RequestRow, context: LiveContext, args: argparse.Namespace
) -> CoordinatedUAAnalysis:
    family = ua_family(row.ua)
    path = base_path(row.path)
    family_analysis = update_target_fanout_mode(
        row,
        context.target_fanout_windows,
        args,
        key=(family, path),
        mode="",
        window_seconds=args.target_fanout_window_seconds,
        request_count=args.target_fanout_count,
        unique_ips_required=args.target_fanout_unique_ips,
    )
    same_ua_analysis = update_target_fanout_mode(
        row,
        context.target_same_ua_fanout_windows,
        args,
        key=(row.ua, path),
        mode="same-ua-target-fanout",
        window_seconds=args.target_fanout_same_ua_window_seconds,
        request_count=args.target_fanout_same_ua_count,
        unique_ips_required=args.target_fanout_same_ua_unique_ips,
    )

    proofs: dict[str, list[ForcedProof]] = {}
    for analysis in (family_analysis, same_ua_analysis):
        for ip, ip_proofs in analysis.forced_proofs_by_ip.items():
            proofs.setdefault(ip, []).extend(ip_proofs)
        if analysis.degraded:
            context.detector_flags.add("coordinated-target-fanout")

    degraded_reasons = [
        analysis.degraded_reason
        for analysis in (family_analysis, same_ua_analysis)
        if analysis.degraded_reason
    ]
    return CoordinatedUAAnalysis(
        forced_proofs_by_ip=proofs,
        degraded=family_analysis.degraded or same_ua_analysis.degraded,
        degraded_reason=" | ".join(degraded_reasons),
    )


def remove_low_context_fanout_row(
    window: LowContextFanoutWindow, expired: RequestRow
) -> None:
    window.ip_counts[expired.ip] -= 1
    if window.ip_counts[expired.ip] <= 0:
        del window.ip_counts[expired.ip]
    expired_family = ua_family(expired.ua)
    window.ua_family_counts[expired_family] -= 1
    if window.ua_family_counts[expired_family] <= 0:
        del window.ua_family_counts[expired_family]


def update_low_context_fanout_window(
    row: RequestRow, context: LiveContext, args: argparse.Namespace
) -> CoordinatedUAAnalysis:
    state = context.ip_states.get(row.ip)
    if state is not None and len(state.rows) > args.low_context_fanout_max_ip_requests:
        return CoordinatedUAAnalysis(forced_proofs_by_ip={})
    if not is_low_context_fanout_candidate(row):
        return CoordinatedUAAnalysis(forced_proofs_by_ip={})
    ref_key = low_context_referer_key(row.referer)
    if ref_key is None:
        return CoordinatedUAAnalysis(forced_proofs_by_ip={})
    path = base_path(row.path)
    key = (path, ref_key)
    window = context.low_context_fanout_windows.setdefault(
        key, LowContextFanoutWindow(path=path, ref_key=ref_key)
    )
    window.rows.append(row)
    window.ip_counts[row.ip] += 1
    window.ua_family_counts[ua_family(row.ua)] += 1

    cutoff = row.ts - args.low_context_fanout_window_seconds
    while window.rows and window.rows[0].ts < cutoff:
        remove_low_context_fanout_row(window, window.rows.popleft())

    if not window.rows:
        context.low_context_fanout_windows.pop(key, None)
        return CoordinatedUAAnalysis(forced_proofs_by_ip={})
    if len(window.rows) > args.low_context_fanout_max_rows:
        window.degraded = True
        while len(window.rows) > args.low_context_fanout_max_rows:
            remove_low_context_fanout_row(window, window.rows.popleft())
        context.detector_flags.add("low-context-fanout")

    proofs: dict[str, list[ForcedProof]] = {}
    window_len = len(window.rows)
    unique_ips = len(window.ip_counts)
    max_ip_share = max(window.ip_counts.values()) / window_len if window_len else 1.0
    if (
        window_len >= args.low_context_fanout_count
        and unique_ips >= args.low_context_fanout_unique_ips
        and max_ip_share <= args.low_context_fanout_max_ip_share
    ):
        dominant_family, dominant_family_count = window.ua_family_counts.most_common(1)[
            0
        ]
        dominant_family_ratio = dominant_family_count / window_len
        if dominant_family_ratio >= args.low_context_fanout_min_ua_family_ratio:
            detail = (
                f"path={window.path} ref={window.ref_key} ips={unique_ips} "
                f"reqs={window_len} family={dominant_family} "
                f"family-dom={dominant_family_ratio:.0%}"
            )
            for suspicious_ip in window.ip_counts:
                proofs.setdefault(suspicious_ip, []).append(
                    ForcedProof(kind="low-context-fanout", detail=detail)
                )

    return CoordinatedUAAnalysis(
        forced_proofs_by_ip=proofs,
        degraded=window.degraded,
        degraded_reason=(
            f"bounded to most recent {args.low_context_fanout_max_rows} rows for path={window.path}"
            if window.degraded
            else ""
        ),
    )


def gc_ip_states(context: LiveContext, now_ts: float, args: argparse.Namespace) -> None:
    interval = min(60.0, max(5.0, args.live_ip_memory_seconds / 12.0))
    if context.last_gc_ts and now_ts - context.last_gc_ts < interval:
        return
    context.last_gc_ts = now_ts

    stale_ips: list[str] = []
    for ip, state in context.ip_states.items():
        prune_ip_rows(state, now_ts, args)
        if state.rows:
            continue
        if state.last_action == "clean":
            stale_ips.append(ip)
            continue
        if now_ts - state.last_emitted_ts >= args.cooldown_seconds:
            stale_ips.append(ip)

    for ip in stale_ips:
        context.ip_states.pop(ip, None)


def gc_global_windows(
    context: LiveContext, now_ts: float, args: argparse.Namespace
) -> None:
    coord_cutoff = now_ts - args.coord_window_seconds
    stale_uas: list[str] = []
    for ua, window in context.coordinated_windows.items():
        while window.rows and window.rows[0].ts < coord_cutoff:
            expired = window.rows.popleft()
            window.path_counts[expired.path] -= 1
            if window.path_counts[expired.path] <= 0:
                del window.path_counts[expired.path]
            window.ip_counts[expired.ip] -= 1
            if window.ip_counts[expired.ip] <= 0:
                del window.ip_counts[expired.ip]
        if not window.rows:
            stale_uas.append(ua)
    for ua in stale_uas:
        context.coordinated_windows.pop(ua, None)

    payload_cutoff = now_ts - args.payload_campaign_window_seconds
    stale_families: list[str] = []
    for family, window in context.payload_windows.items():
        while window.rows and window.rows[0].ts < payload_cutoff:
            expired = window.rows.popleft()
            window.ip_counts[expired.ip] -= 1
            if window.ip_counts[expired.ip] <= 0:
                del window.ip_counts[expired.ip]
            expired_base = expired.path.split("?", 1)[0]
            window.path_counts[expired_base] -= 1
            if window.path_counts[expired_base] <= 0:
                del window.path_counts[expired_base]
        if not window.rows:
            stale_families.append(family)
    for family in stale_families:
        context.payload_windows.pop(family, None)

    target_cutoff = now_ts - args.target_fanout_window_seconds
    stale_targets: list[tuple[str, str]] = []
    for key, window in context.target_fanout_windows.items():
        while window.rows and window.rows[0].ts < target_cutoff:
            remove_target_fanout_row(window, window.rows.popleft())
        if not window.rows:
            stale_targets.append(key)
    for key in stale_targets:
        context.target_fanout_windows.pop(key, None)

    same_ua_cutoff = now_ts - args.target_fanout_same_ua_window_seconds
    stale_same_ua_targets: list[tuple[str, str]] = []
    for key, window in context.target_same_ua_fanout_windows.items():
        while window.rows and window.rows[0].ts < same_ua_cutoff:
            remove_target_fanout_row(window, window.rows.popleft())
        if not window.rows:
            stale_same_ua_targets.append(key)
    for key in stale_same_ua_targets:
        context.target_same_ua_fanout_windows.pop(key, None)

    low_context_cutoff = now_ts - args.low_context_fanout_window_seconds
    stale_low_context_targets: list[tuple[str, str]] = []
    for key, window in context.low_context_fanout_windows.items():
        while window.rows and window.rows[0].ts < low_context_cutoff:
            remove_low_context_fanout_row(window, window.rows.popleft())
        if not window.rows:
            stale_low_context_targets.append(key)
    for key in stale_low_context_targets:
        context.low_context_fanout_windows.pop(key, None)


def process_row(
    row: RequestRow, context: LiveContext, args: argparse.Namespace
) -> LiveDecision | None:
    gc_ip_states(context, row.ts, args)
    gc_global_windows(context, row.ts, args)
    state = context.ip_states.setdefault(row.ip, LiveIPState())
    stats = update_ip_state(row.ip, row, state, context.runtime, args)
    ip_rows = list(state.rows)
    _, per_ip_proofs = analyze_ip_behaviors(row.ip, ip_rows, args, context.runtime)
    coordinated = update_coordinated_window(row, context, args)
    target_fanout = update_target_fanout_window(row, context, args)
    low_context_fanout = update_low_context_fanout_window(row, context, args)
    payload_campaigns = update_payload_window(row, context, args)

    proofs = list(per_ip_proofs)
    proofs.extend(coordinated.forced_proofs_by_ip.get(row.ip, []))
    proofs.extend(target_fanout.forced_proofs_by_ip.get(row.ip, []))
    proofs.extend(low_context_fanout.forced_proofs_by_ip.get(row.ip, []))
    proofs.extend(payload_campaigns.forced_proofs_by_ip.get(row.ip, []))
    proofs.extend(provider_activity_proofs(stats, args, context.runtime))
    proofs.extend(provider_exclusion_proofs(stats, args, context.runtime))
    evaluation = evaluate_ip_decision(stats, proofs, args)

    if coordinated.degraded:
        context.detector_flags.add("coordinated-ua")
    if target_fanout.degraded:
        context.detector_flags.add("coordinated-target-fanout")
    if low_context_fanout.degraded:
        context.detector_flags.add("low-context-fanout")
    if payload_campaigns.degraded:
        context.detector_flags.add("payload-campaign")

    if evaluation.action == "clean":
        state.last_action = "clean"
        state.last_reasons = ()
        state.last_score = 0.0
        return None
    if evaluation.action == "suspect" and not args.emit_suspects:
        state.last_action = evaluation.action
        state.last_reasons = evaluation.heuristic.reasons
        state.last_score = evaluation.heuristic.score
        return None
    if (
        state.last_action == evaluation.action
        and row.ts - state.last_emitted_ts < args.cooldown_seconds
    ):
        return None
    if decision_priority(state.last_action) > decision_priority(evaluation.action):
        return None

    state.last_action = evaluation.action
    state.last_reasons = evaluation.heuristic.reasons
    state.last_score = evaluation.heuristic.score
    state.last_emitted_ts = row.ts
    proof_detail = " | ".join(proof.detail for proof in evaluation.proofs[:2]) or "-"
    context.emitted_counts[evaluation.action] += 1
    return LiveDecision(
        action=evaluation.action,
        ip=row.ip,
        ts=row.ts,
        raw_ts=row.raw_ts,
        score=evaluation.heuristic.score,
        reasons=evaluation.heuristic.reasons,
        proof_detail=proof_detail,
        path=row.path,
        ua=row.ua,
        referer=row.referer,
        provider=provider_label(provider_match_for_ip(context.runtime, row.ip)),
    )


def row_from_line(line: str, context: LiveContext) -> RequestRow | None:
    parsed = parse_log_line(line)
    if parsed is None:
        return None
    ip, raw_ts, request, status, referer, ua = parsed
    ts = parse_timestamp(raw_ts, context.ts_cache)
    if ts is None:
        return None
    method, path = parse_request(request)
    return RequestRow(
        raw_ts=raw_ts,
        ts=ts,
        ip=ip,
        method=method,
        path=path,
        status=status,
        referer=referer,
        ua=ua,
        input_index=0,
        line_start=0,
        line_len=0,
    )


def iter_source(args: argparse.Namespace):
    if args.input and args.follow:
        yield from iter_follow(Path(args.input))
        return
    if args.input:
        with Path(args.input).open("r", encoding="utf-8", errors="replace") as handle:
            yield from handle
        return
    yield from sys.stdin


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    args.jobs = max(1, min(getattr(args, "jobs", 1), os.cpu_count() or 1))
    try:
        args.detector_config = resolve_detector_config(args)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))
    runtime = build_runtime(args)
    include = [re.compile(pattern) for pattern in args.path_include]
    exclude = [re.compile(pattern) for pattern in args.path_exclude]
    context = LiveContext(runtime=runtime)
    try:
        for line in iter_source(args):
            row = row_from_line(line, context)
            if row is None:
                continue
            path = row.path
            if include and not any(pattern.search(path) for pattern in include):
                continue
            if exclude and any(pattern.search(path) for pattern in exclude):
                continue

            decision = process_row(row, context, args)
            if decision is not None:
                emit_decision(decision, args)
            maybe_emit_summary(row.ts, context, args)
            maybe_emit_status(row.ts, context, args)
    except KeyboardInterrupt:
        if args.output_format == "human" and sys.stderr.isatty():
            print(file=sys.stderr, flush=True)
        return 130

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except BrokenPipeError:
        try:
            sys.stdout.close()
        finally:
            os._exit(0)
