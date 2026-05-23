from __future__ import annotations

import json
import re
from collections import Counter, defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

from synthetic_access import (
    ALT_REFERRER,
    BOT_UA,
    CHROME_120_UA,
    CHROME_133_UA,
    CHROME_MAC_135_UA,
    CHROME_WIN_134_UA,
    CHROME_WIN_135_UA,
    EDGE_LIKE_UA,
    FIREFOX_122_UA,
    FIREFOX_150_UA,
    JUNK_REFERRER,
    REFERRER,
    SAFARI_17_UA,
    SHARED_UA,
    audit_args,
    doc_ip,
    row,
    watch_args,
)

from lgu.audit import (
    DetectorConfig,
    ForcedProof,
    RequestRow,
    analyze_payload_campaigns,
    base_path,
    build_ip_stats,
    build_runtime,
    detect_behavioral_bots,
    detect_coordinated_target_fanout,
    detect_coordinated_ua_ips,
    detect_provider_activity,
    detect_provider_exclusions,
    evaluate_ip_decision,
    payload_campaign_key,
    target_profile,
    ua_family,
)
from lgu.detector_catalog import DETECTOR_KINDS
from lgu.watch import LiveContext, LiveDecision, process_row

UA_ALIASES = {
    "bot": BOT_UA,
    "chrome_120": CHROME_120_UA,
    "chrome_133": CHROME_133_UA,
    "chrome_win_134": CHROME_WIN_134_UA,
    "chrome_win_135": CHROME_WIN_135_UA,
    "chrome_mac_135": CHROME_MAC_135_UA,
    "edge_like": EDGE_LIKE_UA,
    "firefox_122": FIREFOX_122_UA,
    "firefox_150": FIREFOX_150_UA,
    "safari_17": SAFARI_17_UA,
    "shared": SHARED_UA,
}

REFERER_ALIASES = {
    "-": "-",
    "none": "-",
    "referrer": REFERRER,
    "alt_referrer": ALT_REFERRER,
    "junk_referrer": JUNK_REFERRER,
}

ACTION_PRIORITY = {
    "clean": 0,
    "suspect": 1,
    "ban": 2,
}
TOP_LEVEL_KEYS = {"name", "args", "actors", "events", "expect"}
ACTOR_KEYS = {"ip", "ua", "referer", "method", "status", "path"}
EVENT_KEYS = {
    "actor",
    "at",
    "repeat",
    "every",
    "offset",
    "events",
    "path",
    "path_template",
    "ip",
    "ua",
    "referer",
    "method",
    "status",
}
BATCH_EXPECT_KEYS = {
    "bots",
    "clean",
    "proofs",
    "absent_proofs",
    "reasons",
    "absent_reasons",
    "actions",
    "max_action",
    "max_score",
    "allowed_extra_proofs",
    "allowed_extra_reasons",
}
LIVE_EXPECT_KEYS = {
    "emission_count",
    "emissions",
    "no_emissions",
    "forbidden_actions",
    "max_action",
    "max_score",
    "absent_reasons",
    "allowed_extra_reasons",
}
LIVE_EMISSION_KEYS = {"actor", "action", "reasons"}
DETECTOR_CONFIG_KEYS = frozenset(field.name for field in fields(DetectorConfig))
SCENARIO_ARG_KEYS = (
    frozenset(vars(audit_args())) | frozenset(vars(watch_args())) | {"detector_config"}
)


@dataclass(frozen=True)
class ScenarioCase:
    path: Path
    data: dict[str, Any]

    @property
    def name(self) -> str:
        return str(self.data["name"])

    @property
    def id(self) -> str:
        return f"{self.path.stem}::{self.name}"


@dataclass(frozen=True)
class BatchOutcome:
    bot_ips: set[str]
    proofs_by_ip: dict[str, list[ForcedProof]]
    actions_by_ip: dict[str, str]
    scores_by_ip: dict[str, float]
    reasons_by_ip: dict[str, tuple[str, ...]]


@dataclass(frozen=True)
class LiveEmission:
    actor: str
    decision: LiveDecision


@dataclass(frozen=True)
class LiveOutcome:
    emissions: list[LiveEmission]


def load_scenario_cases(root: Path) -> list[ScenarioCase]:
    cases: list[ScenarioCase] = []
    for path in sorted(root.rglob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            for item in data:
                cases.append(ScenarioCase(path=path, data=item))
        elif isinstance(data, dict) and isinstance(data.get("scenarios"), list):
            for item in data["scenarios"]:
                cases.append(ScenarioCase(path=path, data=item))
        elif isinstance(data, dict):
            cases.append(ScenarioCase(path=path, data=data))
        else:
            raise TypeError(f"{path}: expected scenario object or list")
    return cases


def validate_scenario_case(case: ScenarioCase) -> None:
    errors: list[str] = []
    data = case.data
    collect_unknown_keys(errors, case.id, data, TOP_LEVEL_KEYS)
    if not isinstance(data.get("name"), str) or not data.get("name"):
        errors.append(f"{case.id}: name must be a non-empty string")
    validate_args_shape(errors, case.id, data.get("args", {}))

    actors = data.get("actors")
    actor_names: set[str] = set()
    if not isinstance(actors, dict) or not actors:
        errors.append(f"{case.id}: actors must be a non-empty object")
    else:
        actor_names = set(actors)
        for actor, fields in actors.items():
            if not isinstance(fields, dict):
                errors.append(f"{case.id}: actors.{actor} must be an object")
                continue
            collect_unknown_keys(
                errors, f"{case.id}.actors.{actor}", fields, ACTOR_KEYS
            )
            if "ip" not in fields:
                errors.append(f"{case.id}: actors.{actor}.ip is required")

    events = data.get("events")
    if not isinstance(events, list) or not events:
        errors.append(f"{case.id}: events must be a non-empty list")
    else:
        for index, event in enumerate(events):
            validate_event_shape(
                errors, case.id, event, f"events[{index}]", actor_names
            )

    expect = data.get("expect", {})
    if expect is not None:
        if not isinstance(expect, dict):
            errors.append(f"{case.id}: expect must be an object")
        else:
            validate_expect_shape(errors, case.id, expect, actor_names)

    if errors:
        raise ValueError("; ".join(errors))


def collect_unknown_keys(
    errors: list[str], context: str, value: dict[str, Any], allowed: set[str]
) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        errors.append(f"{context}: unknown keys {unknown}")


def validate_args_shape(errors: list[str], case_id: str, args: Any) -> None:
    if args is None:
        return
    if not isinstance(args, dict):
        errors.append(f"{case_id}: args must be an object")
        return
    collect_unknown_keys(errors, f"{case_id}.args", args, SCENARIO_ARG_KEYS)
    detector_config = args.get("detector_config")
    if detector_config is None:
        return
    if not isinstance(detector_config, dict):
        errors.append(f"{case_id}.args.detector_config must be an object")
        return
    collect_unknown_keys(
        errors,
        f"{case_id}.args.detector_config",
        detector_config,
        DETECTOR_CONFIG_KEYS,
    )
    for key, value in detector_config.items():
        if key not in DETECTOR_CONFIG_KEYS:
            continue
        if not isinstance(value, list) or not all(
            isinstance(item, str) for item in value
        ):
            errors.append(
                f"{case_id}.args.detector_config.{key} must be a list of strings"
            )


def validate_event_shape(
    errors: list[str],
    case_id: str,
    event: Any,
    context: str,
    actor_names: set[str],
) -> None:
    if not isinstance(event, dict):
        errors.append(f"{case_id}.{context}: event must be an object")
        return
    collect_unknown_keys(errors, f"{case_id}.{context}", event, EVENT_KEYS)
    actor = event.get("actor")
    if actor is not None and str(actor) not in actor_names:
        errors.append(f"{case_id}.{context}: unknown actor {actor!r}")
    if "events" in event:
        children = event["events"]
        if not isinstance(children, list) or not children:
            errors.append(f"{case_id}.{context}.events must be a non-empty list")
            return
        for index, child in enumerate(children):
            validate_event_shape(
                errors,
                case_id,
                child,
                f"{context}.events[{index}]",
                actor_names,
            )


def validate_expect_shape(
    errors: list[str],
    case_id: str,
    expect: dict[str, Any],
    actor_names: set[str],
) -> None:
    collect_unknown_keys(errors, f"{case_id}.expect", expect, {"batch", "live"})
    batch = expect.get("batch")
    if batch is not None:
        if not isinstance(batch, dict):
            errors.append(f"{case_id}.expect.batch must be an object")
        else:
            collect_unknown_keys(
                errors, f"{case_id}.expect.batch", batch, BATCH_EXPECT_KEYS
            )
            validate_actor_list(errors, case_id, batch, ("bots", "clean"), actor_names)
            validate_detector_mappings(
                errors,
                case_id,
                batch,
                (
                    "proofs",
                    "absent_proofs",
                    "reasons",
                    "absent_reasons",
                    "allowed_extra_proofs",
                    "allowed_extra_reasons",
                ),
                actor_names,
            )
            validate_actor_value_mappings(
                errors,
                case_id,
                batch,
                ("actions", "max_action", "max_score"),
                actor_names,
            )
    live = expect.get("live")
    if live is not None:
        if not isinstance(live, dict):
            errors.append(f"{case_id}.expect.live must be an object")
        else:
            collect_unknown_keys(
                errors, f"{case_id}.expect.live", live, LIVE_EXPECT_KEYS
            )
            validate_actor_list(errors, case_id, live, ("no_emissions",), actor_names)
            validate_detector_mappings(
                errors,
                case_id,
                live,
                ("absent_reasons", "allowed_extra_reasons"),
                actor_names,
            )
            validate_actor_value_mappings(
                errors,
                case_id,
                live,
                ("forbidden_actions", "max_action", "max_score"),
                actor_names,
            )
            emissions = live.get("emissions", [])
            if not isinstance(emissions, list):
                errors.append(f"{case_id}.expect.live.emissions must be a list")
            else:
                for index, emission in enumerate(emissions):
                    if not isinstance(emission, dict):
                        errors.append(
                            f"{case_id}.expect.live.emissions[{index}] must be an object"
                        )
                        continue
                    collect_unknown_keys(
                        errors,
                        f"{case_id}.expect.live.emissions[{index}]",
                        emission,
                        LIVE_EMISSION_KEYS,
                    )
                    actor = emission.get("actor")
                    if actor is not None:
                        validate_actor_name(
                            errors,
                            case_id,
                            str(actor),
                            f"expect.live.emissions[{index}].actor",
                            actor_names,
                        )
                    for reason in emission.get("reasons", []):
                        validate_detector_kind(
                            errors,
                            case_id,
                            str(reason),
                            f"expect.live.emissions[{index}].reasons",
                        )


def validate_detector_mappings(
    errors: list[str],
    case_id: str,
    parent: dict[str, Any],
    keys: tuple[str, ...],
    actor_names: set[str],
) -> None:
    for key in keys:
        raw = parent.get(key, {})
        if not isinstance(raw, dict):
            errors.append(f"{case_id}: {key} must be an actor mapping")
            continue
        for actor, values in raw.items():
            validate_actor_name(errors, case_id, str(actor), key, actor_names)
            if not isinstance(values, list):
                errors.append(f"{case_id}: {key}.{actor} must be a list")
                continue
            for value in values:
                validate_detector_kind(errors, case_id, str(value), key)


def validate_actor_value_mappings(
    errors: list[str],
    case_id: str,
    parent: dict[str, Any],
    keys: tuple[str, ...],
    actor_names: set[str],
) -> None:
    for key in keys:
        raw = parent.get(key, {})
        if not isinstance(raw, dict):
            errors.append(f"{case_id}: {key} must be an actor mapping")
            continue
        for actor in raw:
            validate_actor_name(errors, case_id, str(actor), key, actor_names)


def validate_actor_list(
    errors: list[str],
    case_id: str,
    parent: dict[str, Any],
    keys: tuple[str, ...],
    actor_names: set[str],
) -> None:
    for key in keys:
        raw = parent.get(key, [])
        if not isinstance(raw, list):
            errors.append(f"{case_id}: {key} must be a list")
            continue
        for actor in raw:
            validate_actor_name(errors, case_id, str(actor), key, actor_names)


def validate_actor_name(
    errors: list[str],
    case_id: str,
    actor: str,
    context: str,
    actor_names: set[str],
) -> None:
    if actor != "*" and actor not in actor_names:
        errors.append(f"{case_id}: unknown actor {actor!r} in {context}")


def validate_detector_kind(
    errors: list[str], case_id: str, value: str, context: str
) -> None:
    kind = reason_kind(value)
    if kind not in DETECTOR_KINDS:
        errors.append(f"{case_id}: unknown detector kind {kind!r} in {context}")


def audit_args_from_case(case: ScenarioCase):
    return audit_args(**parse_args_overrides(case.data.get("args", {})))


def watch_args_from_case(case: ScenarioCase):
    return watch_args(**parse_args_overrides(case.data.get("args", {})))


def parse_args_overrides(raw_args: dict[str, Any]) -> dict[str, Any]:
    overrides = dict(raw_args)
    if "detector_config" in overrides:
        overrides["detector_config"] = detector_config_from_json(
            overrides["detector_config"]
        )
    return overrides


def detector_config_from_json(data: dict[str, Any]) -> DetectorConfig:
    return DetectorConfig(
        known_bot_any_patterns=tuple(data.get("known_bot_any_patterns", ())),
        known_bot_ua_patterns=tuple(data.get("known_bot_ua_patterns", ())),
        known_bot_referer_patterns=tuple(data.get("known_bot_referer_patterns", ())),
        payload_marker_patterns=tuple(data.get("payload_marker_patterns", ())),
    )


def build_rows(case: ScenarioCase) -> tuple[list[RequestRow], dict[str, str]]:
    actors = parse_actors(case)
    rows: list[RequestRow] = []
    for event in expand_events(case.data.get("events", [])):
        actor_name = str(event["actor"])
        actor = actors[actor_name]
        path = str(event.get("path", actor.get("path", "/synthetic/content")))
        referer = resolve_referer(str(event.get("referer", actor.get("referer", "-"))))
        validate_synthetic_path(case, path)
        validate_synthetic_referer(case, referer)
        rows.append(
            row(
                ts=float(event["at"]),
                ip=resolve_ip(event.get("ip", actor["ip"])),
                path=path,
                ua=resolve_ua(str(event.get("ua", actor.get("ua", "chrome_120")))),
                referer=referer,
                method=str(event.get("method", actor.get("method", "GET"))),
                status=str(event.get("status", actor.get("status", "200"))),
            )
        )
    rows.sort(key=lambda item: (item.ts, item.ip, item.ua, item.path, item.method))
    return rows, {actor: resolve_ip(fields["ip"]) for actor, fields in actors.items()}


def parse_actors(case: ScenarioCase) -> dict[str, dict[str, Any]]:
    actors = case.data.get("actors")
    if not isinstance(actors, dict) or not actors:
        raise ValueError(f"{case.id}: expected non-empty actors object")
    parsed: dict[str, dict[str, Any]] = {}
    seen_ips: dict[str, str] = {}
    for name, actor_fields in actors.items():
        if not isinstance(actor_fields, dict):
            raise ValueError(f"{case.id}: actor {name} must be an object")
        actor = {
            "ip": actor_fields.get("ip"),
            "ua": actor_fields.get("ua", "chrome_120"),
            "referer": actor_fields.get("referer", "-"),
            "method": actor_fields.get("method", "GET"),
            "status": actor_fields.get("status", "200"),
        }
        if actor["ip"] is None:
            raise ValueError(f"{case.id}: actor {name} missing ip")
        ip = resolve_ip(actor["ip"])
        validate_doc_ip(case, ip)
        if ip in seen_ips:
            raise ValueError(
                f"{case.id}: actors {seen_ips[ip]} and {name} share ip {ip}"
            )
        seen_ips[ip] = name
        parsed[str(name)] = actor
    return parsed


def expand_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    expanded: list[dict[str, Any]] = []
    for event in events:
        if "events" in event:
            count = int(event.get("repeat", 1))
            every = float(event.get("every", 0.0))
            base_at = float(event.get("at", 0.0))
            defaults = {
                key: value
                for key, value in event.items()
                if key not in {"events", "repeat", "every", "at"}
            }
            for index in range(count):
                for child in event["events"]:
                    merged = {
                        **defaults,
                        **child,
                        "at": base_at
                        + index * every
                        + float(child.get("offset", child.get("at", 0.0))),
                    }
                    expanded.append(format_event(merged, index))
            continue

        count = int(event.get("repeat", 1))
        every = float(event.get("every", 0.0))
        base_at = float(event.get("at", 0.0))
        for index in range(count):
            generated = {**event, "at": base_at + index * every}
            expanded.append(format_event(generated, index))
    return expanded


def format_event(event: dict[str, Any], index: int) -> dict[str, Any]:
    formatted = {}
    for key, value in event.items():
        if key in {"repeat", "every", "offset"}:
            continue
        if isinstance(value, str):
            formatted[key] = value.format(i=index)
        else:
            formatted[key] = value
    if "path_template" in formatted:
        formatted["path"] = str(formatted.pop("path_template")).format(i=index)
    return formatted


def resolve_ip(value: Any) -> str:
    text = str(value)
    if text.startswith("doc:"):
        _, net, octet = text.split(":", 2)
        return doc_ip(int(octet), net=int(net))
    return text


def resolve_ua(value: str) -> str:
    return UA_ALIASES.get(value, value)


def resolve_referer(value: str) -> str:
    return REFERER_ALIASES.get(value, value)


def validate_doc_ip(case: ScenarioCase, ip: str) -> None:
    if not re.match(r"^(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$", ip):
        raise ValueError(f"{case.id}: non-documentation IP in scenario: {ip}")


def validate_synthetic_path(case: ScenarioCase, path: str) -> None:
    if not path.startswith("/synthetic/"):
        raise ValueError(f"{case.id}: non-synthetic path in scenario: {path}")


def validate_synthetic_referer(case: ScenarioCase, referer: str) -> None:
    if referer == "-":
        return
    parsed = urlparse_or_none(referer)
    if parsed is None or not parsed.netloc.endswith(".example.test"):
        raise ValueError(f"{case.id}: non-synthetic referer in scenario: {referer}")


def urlparse_or_none(value: str):
    from urllib.parse import urlparse

    try:
        return urlparse(value)
    except ValueError:
        return None


def run_batch(case: ScenarioCase) -> BatchOutcome:
    rows, _ = build_rows(case)
    args = audit_args_from_case(case)
    runtime = build_runtime(args)
    rows_by_ip: dict[str, list[RequestRow]] = defaultdict(list)
    for request in rows:
        rows_by_ip[request.ip].append(request)

    stats_by_ip = build_ip_stats(rows, args, runtime)
    proofs_by_ip = detect_behavioral_bots(rows_by_ip, args, runtime)
    for analysis in (
        detect_coordinated_ua_ips(rows, args),
        detect_coordinated_target_fanout(rows, args),
    ):
        for ip, proofs in analysis.forced_proofs_by_ip.items():
            proofs_by_ip.setdefault(ip, []).extend(proofs)
    payload_analysis = analyze_payload_campaigns(rows, args, runtime)
    for ip, proofs in payload_analysis.forced_proofs_by_ip.items():
        proofs_by_ip.setdefault(ip, []).extend(proofs)
    for ip, proofs in detect_provider_activity(stats_by_ip, args, runtime).items():
        proofs_by_ip.setdefault(ip, []).extend(proofs)
    for ip, proofs in detect_provider_exclusions(stats_by_ip, args, runtime).items():
        proofs_by_ip.setdefault(ip, []).extend(proofs)

    bot_ips = {ip for ip, stats in stats_by_ip.items() if stats.is_bot(args)}
    bot_ips |= set(proofs_by_ip)
    actions_by_ip: dict[str, str] = {}
    scores_by_ip: dict[str, float] = {}
    reasons_by_ip: dict[str, tuple[str, ...]] = {}
    for ip, stats in stats_by_ip.items():
        evaluation = evaluate_ip_decision(stats, proofs_by_ip.get(ip, []), args)
        actions_by_ip[ip] = evaluation.action
        scores_by_ip[ip] = evaluation.heuristic.score
        reasons_by_ip[ip] = evaluation.heuristic.reasons

    return BatchOutcome(
        bot_ips=bot_ips,
        proofs_by_ip=proofs_by_ip,
        actions_by_ip=actions_by_ip,
        scores_by_ip=scores_by_ip,
        reasons_by_ip=reasons_by_ip,
    )


def run_live(case: ScenarioCase) -> LiveOutcome:
    rows, actor_ips = build_rows(case)
    actor_by_ip = {ip: actor for actor, ip in actor_ips.items()}
    args = watch_args_from_case(case)
    context = LiveContext(runtime=build_runtime(args))
    emissions: list[LiveEmission] = []
    for request in rows:
        decision = process_row(request, context, args)
        if decision is not None:
            emissions.append(
                LiveEmission(actor=actor_by_ip[decision.ip], decision=decision)
            )
    return LiveOutcome(emissions=emissions)


def scenario_diagnostics(case: ScenarioCase) -> dict[str, list[str]]:
    rows, actor_ips = build_rows(case)
    args = audit_args_from_case(case)
    runtime = build_runtime(args)
    actor_by_ip = {ip: actor for actor, ip in actor_ips.items()}
    rows_by_ip: dict[str, list[RequestRow]] = defaultdict(list)
    for request in rows:
        rows_by_ip[request.ip].append(request)

    diagnostics: dict[str, list[str]] = defaultdict(list)
    for ip, ip_rows in rows_by_ip.items():
        actor = actor_by_ip.get(ip, ip)
        diagnostics[actor].extend(per_ip_near_misses(ip_rows, args, runtime))
    diagnostics["global"].extend(cross_ip_near_misses(rows, args, runtime))
    return {key: value for key, value in diagnostics.items() if value}


def per_ip_near_misses(rows: list[RequestRow], args, runtime) -> list[str]:
    if not rows:
        return []
    rows = sorted(rows, key=lambda item: (item.ts, item.path, item.method))
    messages = []
    pair_counts: Counter[tuple[str, str]] = Counter()
    for left, right in zip(rows, rows[1:]):
        if right.ts - left.ts <= args.pair_gap_seconds and left.path != right.path:
            pair_counts[(left.path, right.path)] += 1
    if pair_counts:
        pair, count = pair_counts.most_common(1)[0]
        if count < args.pair_repeat_count:
            messages.append(
                f"repeated-pair near miss: top={count}/{args.pair_repeat_count} pair={pair[0]} -> {pair[1]}"
            )

    cadence = best_cadence(rows, args)
    if cadence:
        messages.append(cadence)
    multifetch = best_multifetch(rows, args)
    if multifetch:
        messages.append(multifetch)
    payload = payload_marker_diagnostic(rows, args, runtime)
    if payload:
        messages.append(payload)
    return messages


def best_cadence(rows: list[RequestRow], args) -> str | None:
    rows_by_base: dict[str, list[RequestRow]] = defaultdict(list)
    for request in rows:
        rows_by_base[base_path(request.path)].append(request)
    candidates = []
    for path, path_rows in rows_by_base.items():
        if target_profile(path) == "asset" or len(path_rows) < 2:
            continue
        path_rows.sort(key=lambda item: item.ts)
        if cadence_hour_shortcut_fires(path_rows, args):
            continue
        gaps = [
            path_rows[index + 1].ts - path_rows[index].ts
            for index in range(len(path_rows) - 1)
        ]
        if not gaps:
            continue
        candidates.append((len(path_rows), path, min(gaps), max(gaps) - min(gaps)))
    if not candidates:
        return None
    repeats, path, min_gap, spread = max(candidates)
    if (
        repeats >= args.cadence_repeat_count
        and min_gap >= args.cadence_min_gap_seconds
        and spread <= args.cadence_gap_tolerance_seconds
    ):
        return None
    return (
        "cadenced-repeat near miss: "
        f"path={path} repeats={repeats}/{args.cadence_repeat_count} "
        f"min-gap={min_gap:.0f}/{args.cadence_min_gap_seconds:.0f}s "
        f"spread={spread:.0f}/{args.cadence_gap_tolerance_seconds:.0f}s"
    )


def cadence_hour_shortcut_fires(rows: list[RequestRow], args) -> bool:
    count = getattr(args, "cadence_hour_repeat_count", 2)
    if count < 2 or len(rows) < count:
        return False
    for start in range(len(rows) - count + 1):
        sample = rows[start : start + count]
        gaps = [
            sample[index + 1].ts - sample[index].ts for index in range(len(sample) - 1)
        ]
        max_drift = max(abs(gap - args.cadence_hour_gap_seconds) for gap in gaps)
        referer_counts = Counter(row.referer for row in sample)
        referer_ratio = max(referer_counts.values()) / len(sample)
        if (
            max_drift <= args.cadence_hour_gap_tolerance_seconds
            and referer_ratio >= args.cadence_dominant_referer_ratio
        ):
            return True
    return False


def best_multifetch(rows: list[RequestRow], args) -> str | None:
    window: deque[RequestRow] = deque()
    path_counts: Counter[str] = Counter()
    referer_counts: Counter[str] = Counter()
    second_path_counts: dict[int, Counter[str]] = {}
    best: tuple[int, int, int, int, float] | None = None
    for request in rows:
        path = base_path(request.path)
        if target_profile(path) == "asset":
            continue
        window.append(request)
        path_counts[path] += 1
        referer_counts[request.referer] += 1
        second_path_counts.setdefault(int(request.ts), Counter())[path] += 1

        cutoff = request.ts - args.multi_fetch_window_seconds
        while window and window[0].ts < cutoff:
            expired = window.popleft()
            expired_path = base_path(expired.path)
            path_counts[expired_path] -= 1
            if path_counts[expired_path] <= 0:
                del path_counts[expired_path]
            referer_counts[expired.referer] -= 1
            if referer_counts[expired.referer] <= 0:
                del referer_counts[expired.referer]
            second_counts = second_path_counts[int(expired.ts)]
            second_counts[expired_path] -= 1
            if second_counts[expired_path] <= 0:
                del second_counts[expired_path]
            if not second_counts:
                del second_path_counts[int(expired.ts)]

        window_len = len(window)
        unique_paths = len(path_counts)
        repeated_paths = sum(1 for count in path_counts.values() if count >= 2)
        same_second_unique = max(
            (len(counts) for counts in second_path_counts.values()), default=0
        )
        referer_ratio = max(referer_counts.values()) / window_len if window_len else 0.0
        candidate = (
            window_len,
            unique_paths,
            repeated_paths,
            same_second_unique,
            referer_ratio,
        )
        if best is None or candidate > best:
            best = candidate
    if best is None:
        return None
    window_len, unique_paths, repeated_paths, same_second_unique, referer_ratio = best
    fires = (
        window_len >= args.multi_fetch_count
        and unique_paths >= args.multi_fetch_unique_paths
        and referer_ratio >= args.multi_fetch_dominant_referer_ratio
        and (
            repeated_paths >= args.multi_fetch_repeat_paths
            or same_second_unique >= args.multi_fetch_same_second_unique_paths
        )
    )
    if fires:
        return None
    return (
        "tight-multifetch near miss: "
        f"reqs={window_len}/{args.multi_fetch_count} "
        f"unique={unique_paths}/{args.multi_fetch_unique_paths} "
        f"repeated={repeated_paths}/{args.multi_fetch_repeat_paths} "
        f"same-second={same_second_unique}/{args.multi_fetch_same_second_unique_paths} "
        f"ref-dom={referer_ratio:.0%}/{args.multi_fetch_dominant_referer_ratio:.0%}"
    )


def payload_marker_diagnostic(rows: list[RequestRow], args, runtime) -> str | None:
    if runtime.payload_marker_patterns:
        return None
    interesting = [
        request
        for request in rows
        if "synthetic_marker=" in request.path or "render=full" in request.path
    ]
    if not interesting:
        return None
    return "payload detectors inert: no payload_marker_patterns configured"


def cross_ip_near_misses(rows: list[RequestRow], args, runtime) -> list[str]:
    messages = []
    by_ua: dict[str, list[RequestRow]] = defaultdict(list)
    by_target: dict[tuple[str, str], list[RequestRow]] = defaultdict(list)
    by_exact_target: dict[tuple[str, str], list[RequestRow]] = defaultdict(list)
    payload_candidates = []
    for request in rows:
        by_ua[request.ua].append(request)
        by_target[(ua_family(request.ua), base_path(request.path))].append(request)
        by_exact_target[(request.ua, base_path(request.path))].append(request)
        if payload_campaign_key(
            request.path, request.referer, runtime.payload_marker_patterns
        ):
            payload_candidates.append(request)

    for ua, ua_rows in by_ua.items():
        if len(ua_rows) < args.coord_count:
            continue
        path_count = len({request.path for request in ua_rows})
        ip_count = len({request.ip for request in ua_rows})
        if path_count < args.coord_unique_paths or ip_count < args.coord_unique_ips:
            messages.append(
                "coordinated-ua near miss: "
                f"ua={resolve_ua_label(ua)} reqs={len(ua_rows)}/{args.coord_count} "
                f"paths={path_count}/{args.coord_unique_paths} ips={ip_count}/{args.coord_unique_ips}"
            )
            break

    for (family, path), target_rows in by_target.items():
        if len(target_rows) < args.target_fanout_count:
            continue
        ip_count = len({request.ip for request in target_rows})
        if ip_count < args.target_fanout_unique_ips:
            messages.append(
                "target-fanout near miss: "
                f"family={family} path={path} reqs={len(target_rows)}/{args.target_fanout_count} "
                f"ips={ip_count}/{args.target_fanout_unique_ips}"
            )
            break

    for (ua, path), target_rows in by_exact_target.items():
        if len(target_rows) < args.target_fanout_same_ua_count:
            continue
        ip_count = len({request.ip for request in target_rows})
        if ip_count < args.target_fanout_same_ua_unique_ips:
            messages.append(
                "same-ua target-fanout near miss: "
                f"ua={resolve_ua_label(ua)} path={path} "
                f"reqs={len(target_rows)}/{args.target_fanout_same_ua_count} "
                f"ips={ip_count}/{args.target_fanout_same_ua_unique_ips}"
            )
            break

    if payload_candidates and len(payload_candidates) < args.payload_campaign_count:
        messages.append(
            "payload-campaign near miss: "
            f"candidates={len(payload_candidates)}/{args.payload_campaign_count}"
        )
    return messages


def resolve_ua_label(ua: str) -> str:
    for label, value in UA_ALIASES.items():
        if value == ua:
            return label
    return ua[:40]


def assert_batch_expectations(case: ScenarioCase) -> None:
    expect = case.data.get("expect", {}).get("batch")
    if not expect:
        return
    _, actor_ips = build_rows(case)
    outcome = run_batch(case)

    for actor in expected_actors(expect.get("bots", []), actor_ips):
        ip = actor_ips[actor]
        assert ip in outcome.bot_ips, batch_failure(case, outcome, f"{actor} bot")
    for actor in expected_actors(expect.get("clean", []), actor_ips):
        ip = actor_ips[actor]
        assert ip not in outcome.bot_ips, batch_failure(case, outcome, f"{actor} clean")
    for actor, expected_proofs in expand_actor_mapping(
        expect.get("proofs", {}), actor_ips
    ).items():
        actual = {
            proof.kind for proof in outcome.proofs_by_ip.get(actor_ips[actor], [])
        }
        missing = set(expected_proofs) - actual
        assert not missing, batch_failure(
            case, outcome, f"{actor} missing proofs {sorted(missing)}"
        )
    for actor, forbidden_proofs in expand_actor_mapping(
        expect.get("absent_proofs", {}), actor_ips
    ).items():
        actual = {
            proof.kind for proof in outcome.proofs_by_ip.get(actor_ips[actor], [])
        }
        forbidden = set(forbidden_proofs) & actual
        assert not forbidden, batch_failure(
            case, outcome, f"{actor} forbidden proofs {sorted(forbidden)}"
        )
    for actor, expected_reasons in expand_actor_mapping(
        expect.get("reasons", {}), actor_ips
    ).items():
        actual = reason_kinds(batch_actor_reasons(outcome, actor_ips, actor))
        missing = set(expected_reasons) - actual
        assert not missing, batch_failure(
            case, outcome, f"{actor} missing reasons {sorted(missing)}"
        )
    for actor, forbidden_reasons in expand_actor_mapping(
        expect.get("absent_reasons", {}), actor_ips
    ).items():
        actual = reason_kinds(batch_actor_reasons(outcome, actor_ips, actor))
        forbidden = {reason_kind(reason) for reason in forbidden_reasons} & actual
        assert not forbidden, batch_failure(
            case, outcome, f"{actor} forbidden reasons {sorted(forbidden)}"
        )
    for actor, expected_action in expand_actor_value_mapping(
        expect.get("actions", {}), actor_ips
    ).items():
        actual = batch_actor_action(outcome, actor_ips, actor)
        assert actual == str(expected_action), batch_failure(
            case, outcome, f"{actor} action {actual} != {expected_action}"
        )
    for actor, max_action in expand_actor_value_mapping(
        expect.get("max_action", {}), actor_ips
    ).items():
        actual = batch_actor_action(outcome, actor_ips, actor)
        assert action_priority(actual) <= action_priority(str(max_action)), (
            batch_failure(
                case,
                outcome,
                f"{actor} action {actual} exceeds max {max_action}",
            )
        )
    for actor, max_score in expand_actor_value_mapping(
        expect.get("max_score", {}), actor_ips
    ).items():
        actual = batch_actor_score(outcome, actor_ips, actor)
        limit = float(max_score)
        assert actual <= limit, batch_failure(
            case,
            outcome,
            f"{actor} score {actual:.2f} exceeds max {limit:.2f}",
        )


def assert_live_expectations(case: ScenarioCase) -> None:
    expect = case.data.get("expect", {}).get("live")
    if not expect:
        return
    outcome = run_live(case)
    actor_ips = build_rows(case)[1]
    for expected in expect.get("emissions", []):
        matches = [
            emission
            for emission in outcome.emissions
            if emission.actor == expected["actor"]
            and emission.decision.action == expected["action"]
            and {
                reason_kind(reason) for reason in expected.get("reasons", ())
            }.issubset(reason_kinds(emission.decision.reasons))
        ]
        assert matches, live_failure(case, outcome, f"missing emission {expected}")
    for actor in expected_actors(expect.get("no_emissions", []), actor_ips):
        unexpected = [
            emission for emission in outcome.emissions if emission.actor == actor
        ]
        assert not unexpected, live_failure(case, outcome, f"{actor} emitted")
    if "emission_count" in expect:
        assert len(outcome.emissions) == int(expect["emission_count"]), live_failure(
            case, outcome, f"expected {expect['emission_count']} emissions"
        )
    for actor, forbidden_actions in expand_actor_mapping(
        expect.get("forbidden_actions", {}), actor_ips
    ).items():
        forbidden = set(forbidden_actions)
        unexpected = [
            emission
            for emission in live_actor_emissions(outcome, actor)
            if emission.decision.action in forbidden
        ]
        assert not unexpected, live_failure(
            case,
            outcome,
            f"{actor} emitted forbidden actions {sorted(forbidden)}",
        )
    for actor, max_action in expand_actor_value_mapping(
        expect.get("max_action", {}), actor_ips
    ).items():
        allowed = str(max_action)
        excessive = [
            emission
            for emission in live_actor_emissions(outcome, actor)
            if action_priority(emission.decision.action) > action_priority(allowed)
        ]
        assert not excessive, live_failure(
            case, outcome, f"{actor} emitted action above max {allowed}"
        )
    for actor, max_score in expand_actor_value_mapping(
        expect.get("max_score", {}), actor_ips
    ).items():
        limit = float(max_score)
        excessive = [
            emission
            for emission in live_actor_emissions(outcome, actor)
            if emission.decision.score > limit
        ]
        assert not excessive, live_failure(
            case, outcome, f"{actor} emitted score above max {limit:.2f}"
        )
    for actor, forbidden_reasons in expand_actor_mapping(
        expect.get("absent_reasons", {}), actor_ips
    ).items():
        forbidden = set(forbidden_reasons)
        actual = {
            reason_kind(reason)
            for emission in live_actor_emissions(outcome, actor)
            for reason in emission.decision.reasons
        }
        present = {reason_kind(reason) for reason in forbidden} & actual
        assert not present, live_failure(
            case, outcome, f"{actor} emitted forbidden reasons {sorted(present)}"
        )


def assert_no_unexpected_drift(case: ScenarioCase) -> None:
    _, actor_ips = build_rows(case)
    batch_expect = case.data.get("expect", {}).get("batch", {})
    if batch_expect:
        batch_outcome = run_batch(case)
        assert_no_unexpected_batch_proofs(case, actor_ips, batch_expect, batch_outcome)
        assert_no_unexpected_batch_reasons(case, actor_ips, batch_expect, batch_outcome)

    live_expect = case.data.get("expect", {}).get("live", {})
    if live_expect:
        live_outcome = run_live(case)
        assert_no_unexpected_live_reasons(case, live_expect, live_outcome)


def assert_no_unexpected_batch_proofs(
    case: ScenarioCase,
    actor_ips: dict[str, str],
    expect: dict[str, Any],
    outcome: BatchOutcome,
) -> None:
    allowed_extra = expand_actor_mapping(
        expect.get("allowed_extra_proofs", {}), actor_ips
    )
    for actor, expected_proofs in expand_actor_mapping(
        expect.get("proofs", {}), actor_ips
    ).items():
        actual = {
            proof.kind for proof in outcome.proofs_by_ip.get(actor_ips[actor], [])
        }
        allowed = set(expected_proofs) | set(allowed_extra.get(actor, ()))
        unexpected = actual - allowed
        assert not unexpected, batch_failure(
            case, outcome, f"{actor} unexpected proofs {sorted(unexpected)}"
        )


def assert_no_unexpected_batch_reasons(
    case: ScenarioCase,
    actor_ips: dict[str, str],
    expect: dict[str, Any],
    outcome: BatchOutcome,
) -> None:
    allowed_extra = expand_actor_mapping(
        expect.get("allowed_extra_reasons", {}), actor_ips
    )
    for actor, expected_reasons in expand_actor_mapping(
        expect.get("reasons", {}), actor_ips
    ).items():
        actual = reason_kinds(batch_actor_reasons(outcome, actor_ips, actor))
        allowed = {reason_kind(reason) for reason in expected_reasons} | {
            reason_kind(reason) for reason in allowed_extra.get(actor, ())
        }
        unexpected = actual - allowed
        assert not unexpected, batch_failure(
            case, outcome, f"{actor} unexpected reasons {sorted(unexpected)}"
        )


def assert_no_unexpected_live_reasons(
    case: ScenarioCase,
    expect: dict[str, Any],
    outcome: LiveOutcome,
) -> None:
    actor_ips = build_rows(case)[1]
    allowed_extra = expand_actor_mapping(
        expect.get("allowed_extra_reasons", {}), actor_ips
    )
    for expected in expect.get("emissions", []):
        expected_kinds = {reason_kind(reason) for reason in expected.get("reasons", ())}
        actor = str(expected["actor"])
        allowed = expected_kinds | {
            reason_kind(reason) for reason in allowed_extra.get(actor, ())
        }
        matching = [
            emission
            for emission in outcome.emissions
            if emission.actor == actor
            and emission.decision.action == expected["action"]
            and expected_kinds.issubset(reason_kinds(emission.decision.reasons))
        ]
        for emission in matching:
            unexpected = reason_kinds(emission.decision.reasons) - allowed
            assert not unexpected, live_failure(
                case,
                outcome,
                f"{actor} emitted unexpected reasons {sorted(unexpected)}",
            )


def batch_failure(case: ScenarioCase, outcome: BatchOutcome, message: str) -> str:
    proof_summary = {
        ip: [proof.kind for proof in proofs]
        for ip, proofs in sorted(outcome.proofs_by_ip.items())
    }
    action_summary = dict(sorted(outcome.actions_by_ip.items()))
    score_summary = {
        ip: round(score, 2) for ip, score in sorted(outcome.scores_by_ip.items())
    }
    reason_summary = {
        ip: list(reasons) for ip, reasons in sorted(outcome.reasons_by_ip.items())
    }
    return (
        f"{case.id}: {message}; bot_ips={sorted(outcome.bot_ips)} "
        f"actions={action_summary} scores={score_summary} "
        f"reasons={reason_summary} proofs={proof_summary}"
    )


def expected_actors(raw: list[str], actor_ips: dict[str, str]) -> list[str]:
    if "*" in raw:
        return sorted(actor_ips)
    return raw


def expand_actor_mapping(
    raw: dict[str, list[str]], actor_ips: dict[str, str]
) -> dict[str, list[str]]:
    expanded: dict[str, list[str]] = {}
    for actor, values in raw.items():
        if actor == "*":
            for target_actor in actor_ips:
                expanded.setdefault(target_actor, []).extend(values)
            continue
        expanded.setdefault(actor, []).extend(values)
    return expanded


def expand_actor_value_mapping(
    raw: dict[str, Any], actor_ips: dict[str, str]
) -> dict[str, Any]:
    expanded: dict[str, Any] = {}
    for actor, value in raw.items():
        if actor == "*":
            for target_actor in actor_ips:
                expanded[target_actor] = value
            continue
        expanded[actor] = value
    return expanded


def action_priority(action: str) -> int:
    try:
        return ACTION_PRIORITY[action]
    except KeyError as exc:
        allowed = ", ".join(sorted(ACTION_PRIORITY))
        raise ValueError(
            f"unknown action {action!r}; expected one of {allowed}"
        ) from exc


def reason_kind(reason: str) -> str:
    return reason.split("=", 1)[0]


def reason_kinds(reasons: Iterable[str]) -> set[str]:
    return {reason_kind(reason) for reason in reasons}


def batch_actor_action(
    outcome: BatchOutcome, actor_ips: dict[str, str], actor: str
) -> str:
    return outcome.actions_by_ip.get(actor_ips[actor], "clean")


def batch_actor_score(
    outcome: BatchOutcome, actor_ips: dict[str, str], actor: str
) -> float:
    return outcome.scores_by_ip.get(actor_ips[actor], 0.0)


def batch_actor_reasons(
    outcome: BatchOutcome, actor_ips: dict[str, str], actor: str
) -> tuple[str, ...]:
    return outcome.reasons_by_ip.get(actor_ips[actor], ())


def live_actor_emissions(outcome: LiveOutcome, actor: str) -> list[LiveEmission]:
    return [emission for emission in outcome.emissions if emission.actor == actor]


def live_failure(case: ScenarioCase, outcome: LiveOutcome, message: str) -> str:
    emissions = [
        {
            "actor": emission.actor,
            "action": emission.decision.action,
            "score": round(emission.decision.score, 2),
            "reasons": list(emission.decision.reasons),
            "proof": emission.decision.proof_detail,
            "path": emission.decision.path,
        }
        for emission in outcome.emissions
    ]
    return f"{case.id}: {message}; emissions={emissions}"
