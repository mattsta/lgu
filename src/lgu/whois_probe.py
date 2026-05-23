"""Evidence-based validation of RDAP registry pacing (`lgu-whois-probe`).

The whois resolver makes pacing decisions (wait, defer, back off) that are only
as good as the assumptions behind them. This tool replaces assumptions with
recorded registry behavior. Every request it makes goes through the same
`fetch_exchange` / `classify_exchange` path `log-audit --whois` uses, and each
exchange (status, headers, final URL after redirects, timing, and how the
resolver classified it) is appended to a JSONL evidence log, by default next to
the whois cache, so behavior can be compared across runs, hosts, and releases.

Subcommands:

  burst    paced queries to one registry until it refuses or N are sent; the
           direct measurement of what a registry tolerates
  replay   run the real WhoisResolver over addresses on a scratch copy of a
           cache; every deferral is checked against what registries actually
           sent, and `--check` exits non-zero when one is unjustified
  ask      send addresses to one named registry, ignoring bootstrap routing,
           and show whether log-audit would use the answer or reject it as a
           placeholder
  explain  offline: what pacing a cache file imposes on the next query to each
           registry, and why (copy a remote cache here, or run it there); also
           lists records the cache holds but lookups no longer use
  verify-cache
           live: ask registries again for addresses the cache answers and
           report divergences; `--fix` replaces diverged answers
  evict    offline: drop cached answers for IPs or ranges so the next run
           asks again, keeping pacing state and recorded blocks
  summary  aggregate the evidence log per registry over time
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import time
import uuid
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import quote, unquote

try:
    from .whois_data import DATASETS, default_data_dir, load_datasets
    from .whois_lookup import (
        BOOTSTRAP_BASENAME,
        BOOTSTRAP_TTL_SECONDS,
        CACHE_BASENAME,
        DEFAULT_INTERVAL_SECONDS,
        DEFAULT_MAX_LOOKUPS,
        DEFAULT_TIMEOUT_SECONDS,
        DEFER_BACKOFF,
        DEFER_BUDGET,
        DEFER_DENIED,
        DEFER_PUBLISHED_LIMIT,
        DEFER_REFUSED,
        DEFER_SPACING,
        DEFER_STOPPED,
        FALLBACK_BASE_URL,
        FETCH_DENIED,
        FETCH_FORBIDDEN,
        FETCH_OK,
        FETCH_REFUSED,
        PUBLISHED_LIMITS,
        REGISTRY_BY_HOST,
        FetchResult,
        HttpExchange,
        LocalSource,
        RdapBootstrap,
        WhoisRecord,
        WhoisResolver,
        classify_exchange,
        clear_denial,
        default_cache_path,
        denial_until,
        describe_denial,
        describe_pause,
        evict_cache,
        fetch_exchange,
        format_whois_line,
        is_queryable,
        load_bootstrap,
        normalize_ip,
        parse_rdap_network,
        placeholder_reason,
        rdap_error,
        read_cache_file,
        read_cache_ignored,
        registrant_candidates,
        registry_for_url,
    )
except ImportError:  # pragma: no cover - direct script execution
    from whois_data import DATASETS, default_data_dir, load_datasets  # type: ignore[no-redef]
    from whois_lookup import (  # type: ignore[no-redef]
        BOOTSTRAP_BASENAME,
        BOOTSTRAP_TTL_SECONDS,
        CACHE_BASENAME,
        DEFAULT_INTERVAL_SECONDS,
        DEFAULT_MAX_LOOKUPS,
        DEFAULT_TIMEOUT_SECONDS,
        DEFER_BACKOFF,
        DEFER_BUDGET,
        DEFER_DENIED,
        DEFER_PUBLISHED_LIMIT,
        DEFER_REFUSED,
        DEFER_SPACING,
        DEFER_STOPPED,
        FALLBACK_BASE_URL,
        FETCH_DENIED,
        FETCH_FORBIDDEN,
        FETCH_OK,
        FETCH_REFUSED,
        PUBLISHED_LIMITS,
        REGISTRY_BY_HOST,
        FetchResult,
        HttpExchange,
        LocalSource,
        RdapBootstrap,
        WhoisRecord,
        WhoisResolver,
        classify_exchange,
        clear_denial,
        default_cache_path,
        denial_until,
        describe_denial,
        describe_pause,
        evict_cache,
        fetch_exchange,
        format_whois_line,
        is_queryable,
        load_bootstrap,
        normalize_ip,
        parse_rdap_network,
        placeholder_reason,
        rdap_error,
        read_cache_file,
        read_cache_ignored,
        registrant_candidates,
        registry_for_url,
    )

EVIDENCE_SCHEMA = 1
EVIDENCE_BASENAME = "whois-probe.jsonl"
MIN_BURST_INTERVAL = 0.1
MAX_BURST_COUNT = 1000
MAX_CROSSCHECK = 100
# Header names that would carry a server's own statement about limits.
RATE_HEADER_HINTS = ("ratelimit", "rate-limit", "retry-after", "quota", "throttl")
REGISTRY_ALIASES = {
    "arin": "ARIN",
    "ripe": "RIPE NCC",
    "ripe ncc": "RIPE NCC",
    "ripencc": "RIPE NCC",
    "apnic": "APNIC",
    "lacnic": "LACNIC",
    "afrinic": "AFRINIC",
}
KNOWN_REGISTRIES = tuple(dict.fromkeys(REGISTRY_BY_HOST.values()))

# Deferral kinds a registry response (this run, or a persisted pause) backs.
REGISTRY_BACKED = {DEFER_REFUSED, DEFER_BACKOFF, DEFER_DENIED}
# Deferral kinds that are this client's own published-policy or config limits.
POLICY_BACKED = {DEFER_BUDGET, DEFER_PUBLISHED_LIMIT, DEFER_STOPPED}

ExchangeFn = Callable[[str, float], HttpExchange]


def default_evidence_path() -> Path:
    return default_cache_path().with_name(EVIDENCE_BASENAME)


def default_bootstrap_path() -> Path:
    return default_cache_path().with_name(BOOTSTRAP_BASENAME)


def canonical_registry(name: str) -> str:
    text = name.strip()
    return REGISTRY_ALIASES.get(text.lower(), text)


def _printable(text: str) -> str:
    """Terminal-safe rendering of registry text: control characters removed."""
    cleaned = " ".join("".join(ch if ch.isprintable() else " " for ch in text).split())
    return cleaned


def _ip_from_url(url: str) -> str | None:
    if "/ip/" not in url:
        return None
    return unquote(url.rsplit("/ip/", 1)[1])


def rate_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        name: value
        for name, value in headers.items()
        if any(hint in name for hint in RATE_HEADER_HINTS)
    }


# --- evidence ---------------------------------------------------------------


def exchange_record(
    exchange: HttpExchange,
    result: FetchResult,
    *,
    run_id: str,
    mode: str,
) -> dict[str, object]:
    """One JSONL evidence row: what was sent, what came back, how it was read."""
    final = exchange.final_url or exchange.url
    headers = {name.lower(): value for name, value in exchange.headers}
    return {
        "schema": EVIDENCE_SCHEMA,
        "run_id": run_id,
        "mode": mode,
        "ts": exchange.started,
        "elapsed_ms": round(exchange.elapsed * 1000.0, 1),
        "registry": registry_for_url(exchange.url),
        "answered_by": registry_for_url(final),
        "ip": _ip_from_url(exchange.url),
        "url": exchange.url,
        "final_url": final,
        "redirected": final != exchange.url,
        "http_status": exchange.status,
        "error": exchange.error,
        "classified": result.status,
        "retry_after": result.retry_after,
        "headers": headers,
        "rate_headers": rate_headers(headers),
        "body_bytes": len(exchange.body),
        "truncated": exchange.truncated,
        # The complete body, every exchange: this is a debug record.
        "body": exchange.body.decode("utf-8", "replace"),
        "rdap_error": rdap_error(exchange.body),
    }


def format_rdap_error(error: object) -> str | None:
    if not isinstance(error, dict):
        return None
    parts = [
        str(error[key]) for key in ("errorCode", "title") if error.get(key) is not None
    ]
    description = error.get("description")
    if isinstance(description, list) and description:
        parts.append(" / ".join(str(line) for line in description))
    return _printable(": ".join(parts)) or None


class EvidenceLog:
    """Append-only JSONL evidence; `path=None` keeps rows in memory only."""

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self.records: list[dict[str, object]] = []

    def append(self, record: dict[str, object]) -> None:
        self.records.append(record)
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")

    @staticmethod
    def read(path: Path) -> list[dict[str, object]]:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        records = []
        for line in lines:
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict) and record.get("schema") == EVIDENCE_SCHEMA:
                records.append(record)
        return records


class RecordingFetch:
    """A resolver `fetch_fn` that records every exchange before classifying it."""

    def __init__(
        self, exchange_fn: ExchangeFn, log: EvidenceLog, run_id: str, mode: str
    ) -> None:
        self.exchange_fn = exchange_fn
        self.log = log
        self.run_id = run_id
        self.mode = mode
        self.records: list[dict[str, object]] = []

    def __call__(self, url: str, timeout: float) -> FetchResult:
        exchange = self.exchange_fn(url, timeout)
        result = classify_exchange(exchange)
        record = exchange_record(exchange, result, run_id=self.run_id, mode=self.mode)
        self.records.append(record)
        self.log.append(record)
        return result


def new_run_id() -> str:
    return time.strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:6]


# --- address sampling -------------------------------------------------------


def _fractions(max_depth: int = 10) -> Iterator[float]:
    for depth in range(1, max_depth + 1):
        denominator = 1 << depth
        for numerator in range(1, denominator, 2):
            yield numerator / denominator


def registry_base_url(bootstrap: RdapBootstrap, registry: str) -> str | None:
    for _network, base in bootstrap.entries:
        if registry_for_url(base) == registry:
            return base
    return None


def sample_addresses(
    bootstrap: RdapBootstrap,
    registry: str,
    count: int,
    queryable_fn: Callable[[str], bool] = is_queryable,
) -> list[str]:
    """Deterministic, distinct, globally routable addresses the bootstrap routes
    to `registry`, spread across its delegated prefixes so each likely lands in
    a different network (no answer is served from another's cache)."""
    prefixes = sorted(
        (net for net, base in bootstrap.entries if registry_for_url(base) == registry),
        key=lambda net: (net.version, int(net.network_address)),
    )
    picked: list[str] = []
    seen: set[str] = set()
    for fraction in _fractions():
        for network in prefixes:
            if len(picked) >= count:
                return picked
            offset = int((network.num_addresses - 1) * fraction)
            candidate = str(network.network_address + offset)
            base = bootstrap.base_url(candidate)
            if (
                candidate in seen
                or not queryable_fn(candidate)
                or base is None
                or registry_for_url(base) != registry
            ):
                continue
            seen.add(candidate)
            picked.append(candidate)
    return picked


def probe_bootstrap(
    path: Path | None, fetch: RecordingFetch, timeout: float
) -> RdapBootstrap | None:
    return load_bootstrap(path, fetch, timeout, time.time())


# --- burst ------------------------------------------------------------------


@dataclass
class RegistryEvidence:
    """Per-registry digest of a set of evidence rows."""

    registry: str
    requests: int = 0
    classified: Counter[str] = field(default_factory=Counter)
    http_status: Counter[str] = field(default_factory=Counter)
    answered_by: Counter[str] = field(default_factory=Counter)
    header_names: set[str] = field(default_factory=set)
    rate_headers: dict[str, set[str]] = field(default_factory=dict)
    refusals: list[dict[str, object]] = field(default_factory=list)
    elapsed_ms: list[float] = field(default_factory=list)
    first_ts: float | None = None
    last_ts: float | None = None

    def to_json(self) -> dict[str, object]:
        latencies = sorted(self.elapsed_ms)
        return {
            "registry": self.registry,
            "requests": self.requests,
            "classified": dict(self.classified),
            "http_status": dict(self.http_status),
            "answered_by": dict(self.answered_by),
            "header_names": sorted(self.header_names),
            "rate_headers": {k: sorted(v) for k, v in self.rate_headers.items()},
            "refusals": self.refusals,
            "median_ms": latencies[len(latencies) // 2] if latencies else None,
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
        }


def digest(records: Iterable[dict[str, object]]) -> dict[str, RegistryEvidence]:
    """Group evidence rows by registry, annotating each refusal with the load
    that preceded it (gap since the previous request, requests in 60s/3600s)."""
    by_registry: dict[str, RegistryEvidence] = {}
    history: dict[str, list[float]] = {}
    ordered = sorted(records, key=lambda rec: float(rec.get("ts") or 0.0))
    for record in ordered:
        registry = str(record.get("registry"))
        ts = float(record.get("ts") or 0.0)
        evidence = by_registry.setdefault(registry, RegistryEvidence(registry))
        seen = history.setdefault(registry, [])
        evidence.requests += 1
        evidence.classified[str(record.get("classified"))] += 1
        evidence.http_status[str(record.get("http_status"))] += 1
        evidence.answered_by[str(record.get("answered_by"))] += 1
        headers = record.get("headers")
        if isinstance(headers, dict):
            evidence.header_names.update(headers)
        rates = record.get("rate_headers")
        if isinstance(rates, dict):
            for name, value in rates.items():
                evidence.rate_headers.setdefault(name, set()).add(str(value))
        elapsed = record.get("elapsed_ms")
        if isinstance(elapsed, (int, float)):
            evidence.elapsed_ms.append(float(elapsed))
        evidence.first_ts = ts if evidence.first_ts is None else evidence.first_ts
        evidence.last_ts = ts
        if record.get("classified") in (FETCH_REFUSED, FETCH_FORBIDDEN, FETCH_DENIED):
            evidence.refusals.append(
                {
                    "ts": ts,
                    "run_id": record.get("run_id"),
                    "ip": record.get("ip"),
                    "http_status": record.get("http_status"),
                    "answered_by": record.get("answered_by"),
                    "retry_after": record.get("retry_after"),
                    "rate_headers": rates,
                    "body": record.get("body"),
                    "rdap_error": record.get("rdap_error"),
                    "gap_since_previous_s": round(ts - seen[-1], 3) if seen else None,
                    "requests_prev_60s": sum(1 for t in seen if t > ts - 60.0),
                    "requests_prev_3600s": sum(1 for t in seen if t > ts - 3600.0),
                }
            )
        seen.append(ts)
    return by_registry


@dataclass
class BurstReport:
    registry: str
    base_url: str
    interval: float
    planned: int
    sent: int
    duration_s: float
    first_refusal_index: int | None
    first_refusal_after_s: float | None
    evidence: RegistryEvidence

    @property
    def per_minute(self) -> float | None:
        if self.sent < 2 or self.duration_s <= 0:
            return None
        return (self.sent - 1) * 60.0 / self.duration_s

    def to_json(self) -> dict[str, object]:
        return {
            "registry": self.registry,
            "base_url": self.base_url,
            "interval": self.interval,
            "planned": self.planned,
            "sent": self.sent,
            "duration_s": round(self.duration_s, 3),
            "per_minute": self.per_minute,
            "first_refusal_index": self.first_refusal_index,
            "first_refusal_after_s": self.first_refusal_after_s,
            "evidence": self.evidence.to_json(),
        }


def run_burst(
    *,
    registry: str,
    bootstrap: RdapBootstrap,
    fetch: RecordingFetch,
    count: int,
    interval: float,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    stop_after_refusals: int = 1,
    time_fn: Callable[[], float] = time.time,
    sleep_fn: Callable[[float], None] = time.sleep,
    queryable_fn: Callable[[str], bool] = is_queryable,
) -> BurstReport:
    base = registry_base_url(bootstrap, registry)
    if base is None:
        raise ValueError(f"bootstrap routes no prefixes to {registry!r}")
    ips = sample_addresses(bootstrap, registry, count, queryable_fn)
    already = len(fetch.records)
    started = time_fn()
    last: float | None = None
    refusals = 0
    sent = 0
    first_index: int | None = None
    first_after: float | None = None
    for ip in ips:
        if last is not None:
            wait = last + interval - time_fn()
            if wait > 0:
                sleep_fn(wait)
        result = fetch(base + "ip/" + quote(ip, safe=":."), timeout)
        last = time_fn()
        sent += 1
        if result.status in (FETCH_REFUSED, FETCH_FORBIDDEN, FETCH_DENIED):
            refusals += 1
            if first_index is None:
                first_index, first_after = sent, round(last - started, 3)
            if refusals >= stop_after_refusals:
                break
    rows = fetch.records[already:]
    evidence = digest(rows).get(registry, RegistryEvidence(registry))
    return BurstReport(
        registry=registry,
        base_url=base,
        interval=interval,
        planned=len(ips),
        sent=sent,
        duration_s=(last or started) - started,
        first_refusal_index=first_index,
        first_refusal_after_s=first_after,
        evidence=evidence,
    )


# --- replay -----------------------------------------------------------------


@dataclass
class Finding:
    severity: str  # "unjustified" | "inherited" | "refused" | "info"
    registry: str | None
    message: str

    def to_json(self) -> dict[str, object]:
        return {
            "severity": self.severity,
            "registry": self.registry,
            "message": self.message,
        }


@dataclass
class ReplayReport:
    run_id: str
    asked: int
    lookups_made: int
    resolved: int
    deferred_by_kind: dict[str, Counter[str]]
    failed: int
    inherited_backoff: dict[str, float]
    evidence: dict[str, RegistryEvidence]
    findings: list[Finding]
    status_note: str | None
    outcomes: dict[str, str]
    inherited_cause: dict[str, str] = field(default_factory=dict)

    @property
    def unjustified(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "unjustified"]

    def to_json(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "asked": self.asked,
            "lookups_made": self.lookups_made,
            "resolved": self.resolved,
            "deferred_by_kind": {
                registry: dict(kinds)
                for registry, kinds in self.deferred_by_kind.items()
            },
            "failed": self.failed,
            # None for a block with no end (a permanent denial).
            "inherited_backoff": {
                name: None if left == float("inf") else left
                for name, left in self.inherited_backoff.items()
            },
            "inherited_cause": self.inherited_cause,
            "evidence": {k: v.to_json() for k, v in self.evidence.items()},
            "findings": [f.to_json() for f in self.findings],
            "status_note": self.status_note,
            "outcomes": self.outcomes,
        }


def _registry_of_reason(reason: str) -> str | None:
    for name in sorted(KNOWN_REGISTRIES, key=len, reverse=True):
        if reason.startswith(name + " "):
            return name
    head = reason.split(" ", 1)[0]
    return head if "." in head else None


def assess_replay(
    *,
    deferred: dict[str, str],
    kinds: dict[str, str],
    evidence: dict[str, RegistryEvidence],
    inherited_backoff: dict[str, float],
    inherited_cause: dict[str, str] | None = None,
    bootstrap_loaded: bool,
) -> tuple[dict[str, Counter[str]], list[Finding]]:
    """Check every deferral against registry evidence; return findings."""
    by_kind: dict[str, Counter[str]] = {}
    causes = inherited_cause or {}
    # Refusals are charged to the registry that sent them, which after a
    # redirect is not the one the request was routed to.
    refused_by = {
        str(refusal.get("answered_by"))
        for seen in evidence.values()
        for refusal in seen.refusals
    }
    findings: list[Finding] = []
    for ip, reason in deferred.items():
        kind = kinds.get(ip, "unknown")
        registry = _registry_of_reason(reason) or "(this client)"
        by_kind.setdefault(registry, Counter())[kind] += 1
    for registry, counter in sorted(by_kind.items()):
        refused_now = registry in refused_by
        if counter.get(DEFER_SPACING):
            findings.append(
                Finding(
                    "unjustified",
                    registry,
                    f"{counter[DEFER_SPACING]} deferred for this client's own "
                    "spacing; spacing should be slept, never deferred",
                )
            )
        backed = sum(counter.get(kind, 0) for kind in REGISTRY_BACKED)
        if backed and not refused_now and registry in inherited_backoff:
            findings.append(
                Finding(
                    "inherited",
                    registry,
                    f"{backed} deferred by a back-off loaded from the cache "
                    f"({_left(inherited_backoff[registry])}); no response this "
                    f"run asked for it; recorded cause: {causes.get(registry, 'unknown')}",
                )
            )
        elif backed and not refused_now:
            findings.append(
                Finding(
                    "unjustified",
                    registry,
                    f"{backed} deferred as throttled with no refusal on record",
                )
            )
        unknown = counter.get("unknown", 0)
        if unknown:
            findings.append(
                Finding("unjustified", registry, f"{unknown} deferred, kind unknown")
            )
    for registry, seen in sorted(evidence.items()):
        for refusal in seen.refusals:
            retry = refusal.get("retry_after")
            findings.append(
                Finding(
                    "refused",
                    registry,
                    f"HTTP {refusal.get('http_status')} from "
                    f"{refusal.get('answered_by')} after "
                    f"{refusal.get('requests_prev_60s')} requests in 60s "
                    f"(gap {_seconds(refusal.get('gap_since_previous_s'))}); "
                    f"error {format_rdap_error(refusal.get('rdap_error')) or 'none'}; "
                    "Retry-After "
                    f"{'absent' if retry is None else f'{retry:.0f}s'}; rate headers "
                    f"{refusal.get('rate_headers') or 'none'}",
                )
            )
        if seen.answered_by and set(seen.answered_by) - {registry}:
            others = ", ".join(sorted(set(seen.answered_by) - {registry}))
            findings.append(
                Finding(
                    "info",
                    registry,
                    f"requests sent to {registry} were answered by {others} "
                    "after redirects; each answering registry is paced and "
                    "charged for its own refusals",
                )
            )
    if not bootstrap_loaded:
        findings.append(
            Finding(
                "info",
                None,
                "IANA bootstrap unavailable; every query used the ARIN fallback",
            )
        )
    return by_kind, findings


def run_replay(
    *,
    ips: Sequence[str],
    fetch: RecordingFetch,
    cache_path: Path | None,
    bootstrap_path: Path | None,
    interval: float = DEFAULT_INTERVAL_SECONDS,
    max_lookups: int = DEFAULT_MAX_LOOKUPS,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    time_fn: Callable[[], float] = time.time,
    sleep_fn: Callable[[float], None] = time.sleep,
    queryable_fn: Callable[[str], bool] = is_queryable,
) -> ReplayReport:
    """Drive the production resolver over `ips` on a scratch copy of the cache.

    The given cache (and bootstrap) are copied, never written, so a replay can
    reproduce a remote host's state without changing it.
    """
    with tempfile.TemporaryDirectory(prefix="lgu-whois-replay-") as scratch:
        work = Path(scratch) / CACHE_BASENAME
        if cache_path is not None and cache_path.exists():
            shutil.copy2(cache_path, work)
        if bootstrap_path is not None and bootstrap_path.exists():
            shutil.copy2(bootstrap_path, work.with_name(BOOTSTRAP_BASENAME))
        resolver = WhoisResolver(
            cache_path=work,
            interval=interval,
            max_lookups=max_lookups,
            timeout=timeout,
            fetch_fn=fetch,
            time_fn=time_fn,
            sleep_fn=sleep_fn,
            queryable_fn=queryable_fn,
        )
        started = time_fn()
        states = resolver.registry_states()
        inherited: dict[str, float] = {}
        causes: dict[str, str] = {}
        for name, state in states.items():
            until = denial_until(state, started)
            if until is not None:
                inherited[name] = until - started
                causes[name] = describe_denial(state)
            elif state.blocked_until > started:
                inherited[name] = state.blocked_until - started
                causes[name] = describe_pause(state)
        already = len(fetch.records)
        resolver.resolve_many(ips)
        rows = fetch.records[already:]
        evidence = digest(row for row in rows if row.get("ip") is not None)
        bootstrap_loaded = resolver.bootstrap_available
        by_kind, findings = assess_replay(
            deferred=resolver.deferred,
            kinds=resolver.deferred_kinds,
            evidence=evidence,
            inherited_backoff=inherited,
            inherited_cause=causes,
            bootstrap_loaded=bootstrap_loaded,
        )
        outcomes = {ip: resolver.describe(ip) for ip in dict.fromkeys(ips)}
        return ReplayReport(
            run_id=fetch.run_id,
            asked=len(outcomes),
            lookups_made=resolver.lookups_made,
            resolved=sum(1 for ip in outcomes if resolver.lookup(ip) is not None),
            deferred_by_kind=by_kind,
            failed=len(resolver.failed),
            inherited_backoff=inherited,
            evidence=evidence,
            findings=findings,
            status_note=resolver.status_note(),
            outcomes=outcomes,
            inherited_cause=causes,
        )


# --- crosscheck ---------------------------------------------------------------

CROSSCHECK_FIELDS = ("start", "end", "org", "net")


def _record_fields(record: WhoisRecord | None) -> dict[str, object] | None:
    if record is None:
        return None
    return {name: getattr(record, name) for name in (*CROSSCHECK_FIELDS, "registry")}


def compare_answers(
    ip: str,
    local: WhoisRecord | None,
    remote: WhoisRecord | None,
    *,
    refused: bool = False,
    http_status: int | None = None,
) -> dict[str, object]:
    """One crosscheck row: local dataset answer vs RDAP answer for `ip`."""
    differences: list[str] = []
    if refused:
        verdict = "refused"
    elif local is None and remote is None:
        verdict = "both-empty"
    elif local is None:
        verdict = "local-missing"
    elif remote is None:
        verdict = "remote-missing"
    else:
        differences = [
            name
            for name in CROSSCHECK_FIELDS
            if getattr(local, name) != getattr(remote, name)
        ]
        verdict = "mismatch" if differences else "match"
    return {
        "ip": ip,
        "verdict": verdict,
        "differences": differences,
        "local": _record_fields(local),
        "remote": _record_fields(remote),
        "http_status": http_status,
    }


def recorded_answers(
    records: Iterable[dict[str, object]], ips: Sequence[str] = ()
) -> dict[str, dict[str, object]]:
    """Latest recorded successful RDAP answer per IP, from the evidence log."""
    wanted = set(ips)
    latest: dict[str, dict[str, object]] = {}
    for record in records:
        ip = record.get("ip")
        if not isinstance(ip, str) or (wanted and ip not in wanted):
            continue
        if record.get("http_status") != 200 or not isinstance(record.get("body"), str):
            continue
        previous = latest.get(ip)
        if previous is None or float(record.get("ts") or 0) >= float(
            previous.get("ts") or 0
        ):
            latest[ip] = record
    return latest


def recorded_payload(record: dict[str, object]) -> dict[str, object] | None:
    try:
        payload = json.loads(str(record.get("body")))
    except ValueError:
        return None
    return payload if isinstance(payload, dict) else None


def crosscheck_evidence(
    records: Iterable[dict[str, object]],
    dataset: LocalSource,
    ips: Sequence[str] = (),
) -> list[dict[str, object]]:
    """Offline crosscheck: re-parse recorded RDAP answers with the current
    parser and compare them with the local dataset. No network, so parser and
    dataset changes can be re-validated without spending registry quota."""
    rows = []
    for ip, record in sorted(recorded_answers(records, ips).items()):
        payload = recorded_payload(record)
        remote = (
            parse_rdap_network(
                payload,
                ip,
                float(record.get("ts") or 0),
                str(record.get("answered_by")),
            )
            if payload is not None
            else None
        )
        if record.get("answered_by") != dataset.registry:
            continue  # answered by another registry: not this dataset's to judge
        rows.append(compare_answers(ip, dataset.lookup(ip), remote, http_status=200))
    return rows


def inspect_entities(
    records: Iterable[dict[str, object]], ips: Sequence[str] = ()
) -> list[dict[str, object]]:
    """How the ownership parser reads each recorded answer's registrants."""
    rows = []
    for ip, record in sorted(recorded_answers(records, ips).items()):
        payload = recorded_payload(record)
        if payload is None:
            continue
        parsed = parse_rdap_network(payload, ip, 0.0, str(record.get("answered_by")))
        rows.append(
            {
                "ip": ip,
                "answered_by": record.get("answered_by"),
                "recorded": record.get("ts"),
                "registrants": registrant_candidates(payload),
                "org": parsed.org if parsed else None,
                "net": parsed.net if parsed else None,
                "range": parsed.key if parsed else None,
                "kind": parsed.kind if parsed else None,
                "placeholder": placeholder_reason(parsed) if parsed else None,
            }
        )
    return rows


def render_entities(rows: Sequence[dict[str, object]]) -> str:
    lines = []
    for row in rows:
        lines.append(
            f"{row['ip']:<39} {row['answered_by']}: org {row['org']!r}  net {row['net']!r}"
        )
        lines.append(f"    range {row.get('range')}  type {row.get('kind')!r}")
        if row.get("placeholder"):
            lines.append(f"    REJECTED, not an owner: {row['placeholder']}")
        registrants = row["registrants"]
        assert isinstance(registrants, list)
        for candidate in registrants:
            lines.append(
                f"    registrant {candidate['handle']!s:<22} kind {candidate['kind']!s:<10} "
                f"name {candidate['name']!r}: {candidate['verdict']}"
            )
    lines.append(f"entities: {len(rows)} recorded answers")
    kinds = Counter((str(row["answered_by"]), str(row.get("kind"))) for row in rows)
    for (registry, kind), count in sorted(kinds.items()):
        lines.append(f"  {registry:<22} type {kind!r}: {count}")
    return "\n".join(lines)


def run_ask(
    *,
    registry: str,
    ips: Sequence[str],
    fetch: RecordingFetch,
    bootstrap: RdapBootstrap,
    interval: float = DEFAULT_INTERVAL_SECONDS,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    time_fn: Callable[[], float] = time.time,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> list[dict[str, object]]:
    """Send each IP to `registry` directly, ignoring the bootstrap's routing.

    For seeing what a registry answers for space routed elsewhere (where a
    redirect or a stale route sends it). Each row holds the parsed record, the
    placeholder verdict, and the org line log-audit would print. Stops at the
    first refusal or block.
    """
    base = registry_base_url(bootstrap, registry)
    if base is None:
        raise ValueError(f"bootstrap routes no prefixes to {registry!r}")
    rows: list[dict[str, object]] = []
    last: float | None = None
    for ip in ips:
        if last is not None:
            wait = last + interval - time_fn()
            if wait > 0:
                sleep_fn(wait)
        result = fetch(base + "ip/" + quote(ip, safe=":."), timeout)
        last = time_fn()
        answered = registry_for_url(result.final_url or base)
        record = (
            parse_rdap_network(result.payload, ip, last, answered)
            if result.status == FETCH_OK and isinstance(result.payload, dict)
            else None
        )
        placeholder = placeholder_reason(record) if record else None
        rows.append(
            {
                "ip": ip,
                "asked": registry,
                "answered_by": answered,
                "redirected": answered != registry,
                "http_status": result.http_status,
                "classified": result.status,
                "message": result.message,
                "record": _record_fields(record),
                "placeholder": placeholder,
                "shown": format_whois_line(None if placeholder else record, ip),
            }
        )
        if result.status in (FETCH_REFUSED, FETCH_DENIED, FETCH_FORBIDDEN):
            break
    return rows


def render_ask(rows: Sequence[dict[str, object]]) -> str:
    lines = []
    for row in rows:
        via = f" (redirected to {row['answered_by']})" if row["redirected"] else ""
        lines.append(
            f"{row['ip']:<39} asked {row['asked']}{via}: HTTP {row['http_status']} "
            f"{row['classified']}"
            + (f": {row['message']}" if row.get("message") else "")
        )
        record = row["record"]
        if isinstance(record, dict):
            lines.append(
                f"    range {record['start']} - {record['end']}  net {record['net']!r}  "
                f"org {record['org']!r}  registry {record['registry']!r}"
            )
        if row["placeholder"]:
            lines.append(f"    REJECTED, not an owner: {row['placeholder']}")
        lines.append(f"    org line: {row['shown']}")
    lines.append(f"ask: {len(rows)} answers")
    return "\n".join(lines)


VERIFY_FIELDS = ("start", "end", "org", "net")
MAX_VERIFY = 100


def verify_targets(cache_path: Path, sample: int) -> list[str]:
    """One address per cached answer, oldest first: what verification asks
    when given no IPs. Ranges are asked at their first address."""
    records, _misses, _registries, answers = read_cache_file(cache_path)
    entries = sorted(
        [(record.ts, ip) for ip, record in answers.items()]
        + [(record.ts, record.start) for record in records.values()]
    )
    picked = [ip for _ts, ip in entries if is_queryable(ip)]
    return list(dict.fromkeys(picked))[:sample]


def run_verify_cache(
    *,
    cache_path: Path,
    ips: Sequence[str],
    fetch: RecordingFetch,
    bootstrap: RdapBootstrap | None,
    fix: bool = False,
    interval: float = DEFAULT_INTERVAL_SECONDS,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    time_fn: Callable[[], float] = time.time,
    sleep_fn: Callable[[float], None] = time.sleep,
    queryable_fn: Callable[[str], bool] = is_queryable,
) -> dict[str, object]:
    """Ask registries again for IPs the cache answers, and compare.

    Runs the production resolver on the real cache, so pacing, published
    limits, recorded blocks, and request history all apply and are updated:
    registries saw these queries whatever is done with the answers. Answers
    are written only with `fix`, which first evicts every record that
    diverged (they would keep answering otherwise), then stores what the
    registries said.
    """

    def no_network(url: str, timeout: float) -> FetchResult:
        raise AssertionError("reading the cache must not touch the network")

    cached = WhoisResolver(
        cache_path=cache_path,
        fetch_fn=no_network,
        time_fn=time_fn,
        queryable_fn=queryable_fn,
    )
    before = {ip: cached.lookup(ip) for ip in ips}
    live = WhoisResolver(
        cache_path=cache_path,
        fetch_fn=fetch,
        bootstrap=bootstrap,
        interval=interval,
        timeout=timeout,
        max_lookups=len(ips),
        time_fn=time_fn,
        sleep_fn=sleep_fn,
        queryable_fn=queryable_fn,
    )
    after = live.requery(ips)
    rows: list[dict[str, object]] = []
    for ip in ips:
        old = before[ip]
        row: dict[str, object] = {"ip": ip, "cached": _verify_fields(old)}
        if ip not in after:
            row["verdict"] = "not-asked"
            row["reason"] = (
                live.deferred.get(ip) or live.failed.get(ip) or "not globally routable"
            )
        else:
            new = after[ip]
            row["live"] = _verify_fields(new)
            if live.placeholders.get(ip):
                row["reason"] = live.placeholders[ip]
            if old is None:
                row["verdict"] = "match" if new is None else "uncached"
            elif row["cached"] == row["live"]:
                row["verdict"] = "match"
            else:
                row["verdict"] = "diverged"
        rows.append(row)
    diverged = [str(row["ip"]) for row in rows if row["verdict"] == "diverged"]
    evicted = evict_cache(cache_path, diverged) if fix and diverged else None
    saved = live.save(store_answers=fix)
    return {
        "cache": str(cache_path),
        "rows": rows,
        "lookups": live.lookups_made,
        "fixed": fix,
        "evicted": evicted,
        "saved": saved,
    }


def _verify_fields(record: WhoisRecord | None) -> dict[str, object] | None:
    if record is None:
        return None
    return {name: getattr(record, name) for name in VERIFY_FIELDS}


def _verify_text(fields: object, empty: str) -> str:
    if not isinstance(fields, dict):
        return empty
    return f"{fields['start']} - {fields['end']}  {fields['org']!r}  {fields['net']!r}"


def render_verify(report: dict[str, object]) -> str:
    rows = report["rows"]
    assert isinstance(rows, list)
    tally = Counter(str(row["verdict"]) for row in rows)
    lines = []
    for row in rows:
        lines.append(f"{row['ip']:<39} {row['verdict']}")
        if row["verdict"] in ("diverged", "uncached"):
            lines.append(f"    cache: {_verify_text(row['cached'], 'nothing cached')}")
            lines.append(f"    live:  {_verify_text(row.get('live'), 'no owner')}")
        if row.get("reason"):
            lines.append(f"    {row['reason']}")
    evicted = report.get("evicted")
    if report.get("fixed"):
        removed = (
            f"evicted {len(evicted['networks'])} ranges, "
            f"{len(evicted['answers'])} answers, {len(evicted['misses'])} misses"
            if isinstance(evicted, dict)
            else "nothing diverged to evict"
        )
        lines.append(f"fixed: {removed}; stored the registries' answers")
    elif tally.get("diverged"):
        lines.append(
            "diverged answers left in place; rerun with --fix to replace them, "
            "or `lgu-whois-probe evict IP...` to have the next run ask again"
        )
    if not report.get("saved"):
        lines.append(f"WARNING: could not write {report['cache']}")
    summary = ", ".join(f"{name} {count}" for name, count in sorted(tally.items()))
    lines.append(f"verify-cache: {report['lookups']} lookups; {summary or 'nothing'}")
    return "\n".join(lines)


def render_evict(removed: dict[str, list[str]]) -> str:
    lines = [f"  range {key}" for key in removed["networks"]]
    lines += [f"  answer {ip}" for ip in removed["answers"]]
    lines += [f"  miss {ip}" for ip in removed["misses"]]
    total = sum(len(items) for items in removed.values())
    lines.append(
        f"evict: removed {total} entries; pacing state and recorded blocks kept"
        if total
        else "evict: nothing cached for those targets"
    )
    return "\n".join(lines)


def run_crosscheck(
    *,
    ips: Sequence[str],
    dataset: LocalSource,
    fetch: RecordingFetch,
    bootstrap: RdapBootstrap | None,
    interval: float = DEFAULT_INTERVAL_SECONDS,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    time_fn: Callable[[], float] = time.time,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> list[dict[str, object]]:
    """Compare a local dataset's answer with live RDAP, field by field.

    Live answers go through the production parser, so a match means log-audit
    prints the same thing from either source. Stops at the first refusal or
    block: those mean the registry wants fewer queries, not more.
    """
    rows: list[dict[str, object]] = []
    last: float | None = None
    for ip in ips:
        local = dataset.lookup(ip)
        base = (bootstrap.base_url(ip) if bootstrap else None) or FALLBACK_BASE_URL
        if last is not None:
            wait = last + interval - time_fn()
            if wait > 0:
                sleep_fn(wait)
        result = fetch(base + "ip/" + quote(ip, safe=":."), timeout)
        last = time_fn()
        remote = None
        if result.status == FETCH_OK and isinstance(result.payload, dict):
            answered = registry_for_url(result.final_url or base)
            remote = parse_rdap_network(result.payload, ip, last, answered)
        row = compare_answers(
            ip,
            local,
            remote,
            refused=result.status in (FETCH_REFUSED, FETCH_DENIED, FETCH_FORBIDDEN),
            http_status=result.http_status,
        )
        rows.append(row)
        if row["verdict"] == "refused":
            break
    return rows


def render_crosscheck(rows: Sequence[dict[str, object]]) -> str:
    tally = Counter(str(row["verdict"]) for row in rows)
    lines = []
    for row in rows:
        lines.append(f"{row['ip']:<39} {row['verdict']}")
        if row["verdict"] in {"mismatch", "local-missing", "remote-missing"}:
            for side in ("local", "remote"):
                fields = row[side]
                shown = (
                    {k: v for k, v in fields.items() if k in CROSSCHECK_FIELDS}
                    if isinstance(fields, dict)
                    else fields
                )
                lines.append(f"    {side:<6} {shown}")
            if row["differences"]:
                lines.append(f"    differs: {', '.join(row['differences'])}")
    lines.append(f"crosscheck: {dict(tally)}")
    return "\n".join(lines)


# --- explain ----------------------------------------------------------------


def explain_cache(
    cache_path: Path,
    *,
    bootstrap_path: Path | None = None,
    now: float | None = None,
    data_dir: Path | None = None,
) -> dict[str, object]:
    """Offline: what the cache file makes the resolver do next, per registry."""
    now = time.time() if now is None else now

    def no_network(url: str, timeout: float) -> FetchResult:
        raise AssertionError("explain must not touch the network")

    records, misses, _registries, answers = read_cache_file(cache_path)
    ignored = read_cache_ignored(cache_path)
    resolver = WhoisResolver(
        cache_path=cache_path, fetch_fn=no_network, time_fn=lambda: now
    )
    states = resolver.registry_states()
    names = list(dict.fromkeys([*KNOWN_REGISTRIES, *states]))
    registries = []
    for name in names:
        state = states.get(name)
        wait, kind, reason = resolver.next_query_wait(name)
        requests = state.requests if state else []
        registries.append(
            {
                "registry": name,
                "cached_networks": sum(
                    1 for record in records.values() if record.registry == name
                ),
                "cached_answers": sum(
                    1 for record in answers.values() if record.registry == name
                ),
                "requests_last_60s": sum(1 for ts in requests if ts > now - 60.0),
                "requests_last_3600s": sum(1 for ts in requests if ts > now - 3600.0),
                "requests_last_86400s": sum(1 for ts in requests if ts > now - 86400.0),
                "last_request_ago_s": round(now - max(requests), 1)
                if requests
                else None,
                "blocked_for_s": round(state.blocked_until - now, 1)
                if state and state.blocked_until > now
                else 0.0,
                "published_limits": [
                    {"window_s": window, "max": limit}
                    for window, limit in PUBLISHED_LIMITS.get(name, ())
                ],
                # None when blocked indefinitely (a permanent denial).
                "next_query_wait_s": round(wait, 1) if wait != float("inf") else None,
                "denied": state.denied if state else None,
                "next_query_kind": kind or None,
                "next_query_reason": reason or None,
                "refusal_streak": state.refusal_streak if state else 0,
                "last_refusal": state.last_refusal if state else None,
            }
        )
    bootstrap: dict[str, object] = {"path": None, "present": False}
    candidate = bootstrap_path or cache_path.with_name(BOOTSTRAP_BASENAME)
    try:
        stored = json.loads(candidate.read_text(encoding="utf-8"))
        ts = float(stored.get("ts", 0.0))
        bootstrap = {
            "path": str(candidate),
            "present": True,
            "age_s": round(now - ts, 1),
            "stale": not 0 <= now - ts <= BOOTSTRAP_TTL_SECONDS,
        }
    except (OSError, ValueError, AttributeError, TypeError):
        bootstrap = {"path": str(candidate), "present": False}
    return {
        "cache": str(cache_path),
        "now": now,
        "networks": len(records),
        "answers": len(answers),
        "misses": len(misses),
        # Records the file holds but lookups do not use (placeholders, and
        # ranges older releases cached without a registration type). Their
        # IPs are asked again when next shown; the next save drops them.
        "ignored": [
            {
                "key": key,
                "range": record.key,
                "net": record.net,
                "org": record.org,
                "registry": record.registry,
                "cached": record.ts,
                "placeholder": placeholder_reason(record) is not None,
                "reason": reason,
            }
            for key, record, reason in ignored
        ],
        "bootstrap": bootstrap,
        "registries": registries,
        "datasets": [
            {
                "registry": dataset.registry,
                "path": str(dataset.path),
                "published": dataset.as_of,
                "age_s": round(now - dataset.as_of, 1),
            }
            for dataset in load_datasets(data_dir)
        ],
    }


# --- summary ----------------------------------------------------------------


def summarize(
    records: Sequence[dict[str, object]], since: float | None = None
) -> dict[str, object]:
    chosen = [
        rec
        for rec in records
        if rec.get("ip") is not None
        and (since is None or float(rec.get("ts") or 0.0) >= since)
    ]
    evidence = digest(chosen)
    return {
        "records": len(chosen),
        "runs": len({rec.get("run_id") for rec in chosen}),
        "registries": {name: ev.to_json() for name, ev in sorted(evidence.items())},
    }


# --- text rendering -----------------------------------------------------------


def _left(seconds: float) -> str:
    return "no end: permanent" if seconds == float("inf") else f"{seconds:.0f}s left"


def _seconds(value: object) -> str:
    return f"{value}s" if isinstance(value, (int, float)) else "-"


def _when(ts: float | None) -> str:
    if ts is None:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def render_evidence(evidence: RegistryEvidence, indent: str = "  ") -> list[str]:
    data = evidence.to_json()
    lines = [
        f"{indent}requests {data['requests']}  classified {data['classified']}  "
        f"http {data['http_status']}  median {data['median_ms']}ms",
        f"{indent}answered by {data['answered_by']}",
        f"{indent}rate-limit headers seen: {data['rate_headers'] or 'none'}",
        f"{indent}all header names: {', '.join(data['header_names']) or '-'}",
    ]
    for refusal in evidence.refusals:
        lines.append(
            f"{indent}REFUSED {_when(refusal['ts'])} ip {refusal['ip']} "
            f"HTTP {refusal['http_status']} by {refusal['answered_by']}  "
            f"gap {_seconds(refusal['gap_since_previous_s'])}  "
            f"prev60s {refusal['requests_prev_60s']}  "
            f"prev1h {refusal['requests_prev_3600s']}  "
            f"retry-after {refusal['retry_after']}"
        )
        error_text = format_rdap_error(refusal.get("rdap_error"))
        if error_text:
            lines.append(f"{indent}  rdap error: {error_text}")
        elif refusal.get("body"):
            lines.append(f"{indent}  body: {_printable(str(refusal['body']))}")
    return lines


def render_burst(report: BurstReport) -> str:
    rate = report.per_minute
    lines = [
        f"burst {report.registry} via {report.base_url}",
        f"  sent {report.sent}/{report.planned} at {report.interval}s spacing "
        f"over {report.duration_s:.1f}s"
        + (f" (~{rate:.0f}/min)" if rate is not None else ""),
        "  first refusal: "
        + (
            f"request #{report.first_refusal_index} after "
            f"{report.first_refusal_after_s}s"
            if report.first_refusal_index is not None
            else "none"
        ),
        *render_evidence(report.evidence),
    ]
    return "\n".join(lines)


def render_replay(report: ReplayReport) -> str:
    lines = [
        f"replay {report.run_id}: {report.asked} addresses, "
        f"{report.lookups_made} lookups, {report.resolved} resolved, "
        f"{sum(sum(c.values()) for c in report.deferred_by_kind.values())} "
        f"deferred, {report.failed} failed",
    ]
    for registry, kinds in sorted(report.deferred_by_kind.items()):
        lines.append(f"  deferred {registry}: {dict(kinds)}")
    for registry, left in sorted(report.inherited_backoff.items()):
        lines.append(f"  inherited pause {registry}: {_left(left)} at start")
    for registry, evidence in sorted(report.evidence.items()):
        lines.append(f"  {registry}:")
        lines.extend(render_evidence(evidence, indent="    "))
    if report.findings:
        lines.append("findings:")
        lines.extend(
            f"  [{f.severity}] {f.registry or '-'}: {f.message}"
            for f in report.findings
        )
    else:
        lines.append("findings: none; every deferral is backed by evidence or policy")
    if report.status_note:
        lines.append(f"resolver note: {report.status_note}")
    return "\n".join(lines)


def render_explain(data: dict[str, object]) -> str:
    bootstrap = data["bootstrap"]
    assert isinstance(bootstrap, dict)
    lines = [
        f"cache {data['cache']}: {data['networks']} assignment ranges, "
        f"{data.get('answers', 0)} per-IP answers, {data['misses']} misses",
        "bootstrap: "
        + (
            f"{bootstrap['path']} age {bootstrap['age_s']}s"
            + (" (STALE)" if bootstrap.get("stale") else "")
            if bootstrap.get("present")
            else f"MISSING at {bootstrap['path']}; lookups route via the "
            "ARIN fallback until it loads"
        ),
    ]
    ignored = data.get("ignored") or []
    for entry in ignored:
        if entry["placeholder"]:
            lines.append(
                f"IGNORED {entry['key']} from {entry['registry']}, cached "
                f"{_when(entry['cached'])}: {entry['reason']}. It answered for "
                "every address in that range; dropped at the next save"
            )
    others = Counter(
        str(entry["reason"]) for entry in ignored if not entry["placeholder"]
    )
    for reason, count in sorted(others.items()):
        lines.append(
            f"IGNORED {count} cached records: {reason}; their IPs are asked "
            "again when next shown, and the next save drops them"
        )
    for dataset in data.get("datasets") or []:
        lines.append(
            f"local dataset {dataset['registry']}: published "
            f"{_when(dataset['published'])} (age {dataset['age_s'] / 86400:.1f} days, "
            f"in use) {dataset['path']}"
        )
    if not data.get("datasets"):
        lines.append("local datasets: none; run `lgu-whois-data sync`")
    registries = data["registries"]
    assert isinstance(registries, list)
    for entry in registries:
        wait = entry["next_query_wait_s"]
        if entry["next_query_kind"] == DEFER_DENIED:
            verdict = f"NO QUERIES: {entry['next_query_reason']}"
        elif not wait:
            verdict = "next query goes now"
        else:
            verdict = (
                f"next query waits {wait}s ({entry['next_query_kind']}: "
                f"{entry['next_query_reason']})"
            )
        lines.append(
            f"  {entry['registry']:<9} ranges {entry['cached_networks']:>5}  "
            f"answers {entry.get('cached_answers', 0):>5}  "
            f"req/60s {entry['requests_last_60s']:>3}  "
            f"req/1h {entry['requests_last_3600s']:>4}  "
            f"req/24h {entry.get('requests_last_86400s', 0):>4}  "
            f"blocked {entry['blocked_for_s']}s  {verdict}"
        )
        denied = entry.get("denied")
        if isinstance(denied, dict):
            lines.append(
                f"            blocked {_when(denied.get('ts'))}: HTTP "
                f"{denied.get('http_status')} from {denied.get('url')}: "
                f"{denied.get('message')}"
            )
        refusal = entry.get("last_refusal")
        if isinstance(refusal, dict):
            lines.append(
                f"            last refusal {_when(refusal.get('ts'))}: "
                f"HTTP {refusal.get('http_status')} from {refusal.get('url')}  "
                f"Retry-After {refusal.get('retry_after')}  "
                f"backoff {refusal.get('backoff')}s  streak {refusal.get('streak')}"
            )
    return "\n".join(lines)


def render_summary(data: dict[str, object]) -> str:
    lines = [f"evidence: {data['records']} lookups across {data['runs']} runs"]
    registries = data["registries"]
    assert isinstance(registries, dict)
    for name, entry in registries.items():
        evidence = RegistryEvidence(name)
        evidence.requests = int(entry["requests"])
        evidence.classified = Counter(entry["classified"])
        evidence.http_status = Counter(entry["http_status"])
        evidence.answered_by = Counter(entry["answered_by"])
        evidence.header_names = set(entry["header_names"])
        evidence.rate_headers = {k: set(v) for k, v in entry["rate_headers"].items()}
        evidence.refusals = list(entry["refusals"])
        if entry["median_ms"] is not None:
            evidence.elapsed_ms = [float(entry["median_ms"])]
        lines.append(f"{name}: {_when(entry['first_ts'])} .. {_when(entry['last_ts'])}")
        lines.extend(render_evidence(evidence))
    return "\n".join(lines)


# --- CLI ----------------------------------------------------------------------


def _optional_path(raw: str | None, default: Path) -> Path | None:
    if raw is None:
        return default
    if raw.strip().lower() in {"none", "off", ""}:
        return None
    return Path(raw).expanduser()


def _read_ips(args: argparse.Namespace, bootstrap: RdapBootstrap | None) -> list[str]:
    ips: list[str] = list(args.ips)
    if args.ips_file:
        # stdin is read, never closed; a named file is read whole.
        lines = (
            sys.stdin.read().splitlines()
            if args.ips_file == "-"
            else Path(args.ips_file).read_text(encoding="utf-8").splitlines()
        )
        for line in lines:
            text = line.split("#", 1)[0].strip()
            if text:
                ips.append(text.split()[0])
    for spec in args.sample:
        name, _, raw_count = spec.rpartition("=")
        if not name:
            raise SystemExit(f"--sample expects REGISTRY=N, got {spec!r}")
        if bootstrap is None:
            raise SystemExit("--sample needs the IANA bootstrap, which did not load")
        ips.extend(
            sample_addresses(bootstrap, canonical_registry(name), int(raw_count))
        )
    return _valid_ips(ips)


def _valid_ips(ips: Sequence[str]) -> list[str]:
    for ip in ips:
        try:
            ip_address(ip)
        except ValueError:
            raise SystemExit(f"not an IP address: {ip!r}") from None
    return list(ips)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lgu-whois-probe",
        description=(
            "Measure and validate RDAP registry pacing from recorded evidence. "
            "Network subcommands append every exchange to a JSONL evidence log."
        ),
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON.")
    sub = parser.add_subparsers(dest="command", required=True)

    def network_flags(cmd: argparse.ArgumentParser) -> None:
        cmd.add_argument(
            "--evidence",
            default=None,
            metavar="PATH",
            help=f"JSONL evidence log, or 'none'. Default: {default_evidence_path()}",
        )
        cmd.add_argument(
            "--bootstrap",
            default=None,
            metavar="PATH",
            help=(
                "IANA bootstrap cache to use, or 'none' to fetch fresh. "
                f"Default: {default_bootstrap_path()}"
            ),
        )
        cmd.add_argument(
            "--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS, metavar="S"
        )

    burst = sub.add_parser("burst", help="Paced queries to one registry.")
    burst.add_argument("registry", help="ARIN, RIPE, APNIC, LACNIC, AFRINIC")
    burst.add_argument("--count", type=int, default=30)
    burst.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL_SECONDS,
        help="Seconds between request completions (default: production spacing).",
    )
    burst.add_argument(
        "--stop-after-refusals",
        type=int,
        default=1,
        metavar="N",
        help="Stop once the registry has refused N requests.",
    )
    network_flags(burst)

    replay = sub.add_parser(
        "replay", help="Run the real resolver and audit its deferrals."
    )
    replay.add_argument("ips", nargs="*", help="Addresses, in priority order.")
    replay.add_argument(
        "--ips-file", metavar="PATH", help="One IP per line; '-' = stdin."
    )
    replay.add_argument(
        "--sample",
        action="append",
        default=[],
        metavar="REGISTRY=N",
        help="Add N sampled addresses routed to REGISTRY (repeatable).",
    )
    replay.add_argument(
        "--cache",
        default="none",
        metavar="PATH",
        help=(
            "Whois cache to start from (copied, never modified), e.g. one "
            "copied from a remote host. Default: start empty."
        ),
    )
    replay.add_argument("--interval", type=float, default=DEFAULT_INTERVAL_SECONDS)
    replay.add_argument("--max-lookups", type=int, default=DEFAULT_MAX_LOOKUPS)
    replay.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if any deferral is not backed by evidence or policy.",
    )
    network_flags(replay)

    cross = sub.add_parser(
        "crosscheck",
        help="Compare a local dataset's answers with live RDAP, field by field.",
        description=(
            "Each RIPE RDAP answer spends about six of this host's 1,000 daily "
            "personal-data objects (RIPE AUP); keep samples small."
        ),
    )
    cross.add_argument("ips", nargs="*", help="Addresses to compare.")
    cross.add_argument(
        "--from-evidence",
        action="store_true",
        help=(
            "Offline: re-parse RDAP answers recorded in the evidence log (all, or "
            "the given IPs) and compare them with the dataset. No network."
        ),
    )
    cross.add_argument("--dataset", default="ripe", help=f"One of {sorted(DATASETS)}")
    cross.add_argument("--sample", type=int, default=20, metavar="N")
    cross.add_argument("--seed", type=int, default=0)
    cross.add_argument("--data-dir", type=Path, default=None)
    cross.add_argument("--interval", type=float, default=DEFAULT_INTERVAL_SECONDS)
    cross.add_argument("--cache", default=None, metavar="PATH")
    cross.add_argument(
        "--force", action="store_true", help="Query even if the cache records a block."
    )
    network_flags(cross)

    ask = sub.add_parser(
        "ask",
        help="Query one registry directly for addresses, ignoring bootstrap routing.",
        description=(
            "Shows what a registry answers, and whether log-audit would use it "
            "or reject it as a placeholder. RIPE answers spend personal-data "
            "quota (RIPE AUP); keep lists short."
        ),
    )
    ask.add_argument("registry", help="ARIN, RIPE, APNIC, LACNIC, AFRINIC")
    ask.add_argument("ips", nargs="+")
    ask.add_argument("--interval", type=float, default=DEFAULT_INTERVAL_SECONDS)
    ask.add_argument("--cache", default=None, metavar="PATH")
    ask.add_argument(
        "--force", action="store_true", help="Query even if the cache records a block."
    )
    network_flags(ask)

    verify = sub.add_parser(
        "verify-cache",
        help="Live: ask registries again for cached answers; report divergences.",
        description=(
            "Runs the production resolver on the real cache: pacing, limits, "
            "and recorded blocks apply, and the queries are recorded in the "
            "cache's request history. Answers are only written with --fix."
        ),
    )
    verify.add_argument("ips", nargs="*", help="IPs to verify (default: --sample).")
    verify.add_argument(
        "--sample",
        type=int,
        default=10,
        metavar="N",
        help="Without IPs: the N oldest cached answers.",
    )
    verify.add_argument(
        "--fix",
        action="store_true",
        help="Evict diverged records and store the registries' answers.",
    )
    verify.add_argument("--interval", type=float, default=DEFAULT_INTERVAL_SECONDS)
    verify.add_argument(
        "--cache", default=None, metavar="PATH", help=f"Default: {default_cache_path()}"
    )
    network_flags(verify)

    evict = sub.add_parser(
        "evict",
        help="Offline: drop cached answers for IPs or ranges; the next run asks again.",
        description=(
            "Removes range records overlapping each target and per-IP answers "
            "and misses inside it. Pacing state and recorded blocks are kept, "
            "which deleting the cache file would lose."
        ),
    )
    evict.add_argument("targets", nargs="+", help="IP, CIDR, or start-end range.")
    evict.add_argument(
        "--cache", default=None, metavar="PATH", help=f"Default: {default_cache_path()}"
    )

    entities = sub.add_parser(
        "entities",
        help="Offline: how ownership parsing reads recorded RDAP registrants.",
    )
    entities.add_argument("ips", nargs="*", help="Only these IPs.")
    entities.add_argument("--evidence", default=None, metavar="PATH")

    explain = sub.add_parser("explain", help="Offline: why a cache defers queries.")
    explain.add_argument(
        "--cache", default=None, metavar="PATH", help=f"Default: {default_cache_path()}"
    )
    explain.add_argument("--bootstrap", default=None, metavar="PATH")
    explain.add_argument("--data-dir", type=Path, default=None)

    summary = sub.add_parser("summary", help="Aggregate the evidence log.")
    summary.add_argument("--evidence", default=None, metavar="PATH")
    summary.add_argument(
        "--since-hours", type=float, default=None, metavar="H", help="Recent rows only."
    )

    clear = sub.add_parser(
        "clear-denial",
        help="Forget a recorded block once the registry has lifted it.",
    )
    clear.add_argument("registry", help="e.g. RIPE")
    clear.add_argument(
        "--cache", default=None, metavar="PATH", help=f"Default: {default_cache_path()}"
    )

    burst.add_argument(
        "--cache",
        default=None,
        metavar="PATH",
        help="Cache whose recorded blocks burst honors. Default: the whois cache.",
    )
    burst.add_argument(
        "--force",
        action="store_true",
        help=(
            "Query a registry the cache records as having blocked this host. "
            "Querying while blocked can make a temporary RIPE block permanent."
        ),
    )
    return parser


def main(
    argv: Sequence[str] | None = None, exchange_fn: ExchangeFn = fetch_exchange
) -> int:
    args = build_parser().parse_args(argv)
    emit_json = args.json

    def emit(text: str, payload: dict[str, object]) -> None:
        print(json.dumps(payload, indent=2, sort_keys=True) if emit_json else text)

    if args.command == "explain":
        cache = _optional_path(args.cache, default_cache_path())
        if cache is None:
            raise SystemExit("explain needs a cache path")
        bootstrap = _optional_path(args.bootstrap, cache.with_name(BOOTSTRAP_BASENAME))
        data = explain_cache(
            cache,
            bootstrap_path=bootstrap,
            data_dir=args.data_dir or default_data_dir(),
        )
        emit(render_explain(data), data)
        return 0

    if args.command == "summary":
        path = _optional_path(args.evidence, default_evidence_path())
        if path is None:
            raise SystemExit("summary needs an evidence path")
        since = time.time() - args.since_hours * 3600.0 if args.since_hours else None
        data = summarize(EvidenceLog.read(path), since=since)
        emit(render_summary(data), data)
        return 0

    if args.command == "clear-denial":
        cache = _optional_path(args.cache, default_cache_path())
        if cache is None:
            raise SystemExit("clear-denial needs a cache path")
        name = canonical_registry(args.registry)
        cleared = clear_denial(cache, name)
        if cleared is None:
            print(f"no recorded block for {name} in {cache}")
            return 1
        print(f"cleared {name} block recorded {_when(cleared.get('ts'))}")
        return 0

    if args.command == "evict":
        cache = _optional_path(args.cache, default_cache_path())
        if cache is None:
            raise SystemExit("evict needs a cache path")
        try:
            removed = evict_cache(cache, args.targets)
        except ValueError as error:
            raise SystemExit(str(error)) from None
        if removed is None:
            raise SystemExit(f"could not read or write {cache}")
        emit(render_evict(removed), removed)
        return 0 if any(removed.values()) else 1

    if args.command == "entities":
        path = _optional_path(args.evidence, default_evidence_path())
        rows = inspect_entities(EvidenceLog.read(path) if path else [], args.ips)
        emit(render_entities(rows), {"rows": rows})
        return 0

    dataset = None
    if args.command == "crosscheck":
        data_dir = args.data_dir or default_data_dir()
        spec = DATASETS.get(args.dataset)
        if spec is None:
            raise SystemExit(
                f"unknown dataset {args.dataset!r}; known {sorted(DATASETS)}"
            )
        dataset = next(
            (d for d in load_datasets(data_dir) if d.registry == spec.registry), None
        )
        if dataset is None:
            raise SystemExit(f"no built {args.dataset} index under {data_dir}")
        if args.from_evidence:
            path = _optional_path(args.evidence, default_evidence_path())
            records = EvidenceLog.read(path) if path is not None else []
            rows = crosscheck_evidence(records, dataset, args.ips)
            emit(render_crosscheck(rows), {"rows": rows})
            bad = {"mismatch", "local-missing", "remote-missing"}
            return 1 if any(row["verdict"] in bad for row in rows) else 0
        if not 1 <= args.sample + len(args.ips) <= MAX_CROSSCHECK:
            raise SystemExit(f"crosscheck 1..{MAX_CROSSCHECK} addresses")

    if args.command in ("burst", "crosscheck", "ask") and not args.force:
        cache = _optional_path(args.cache, default_cache_path())
        name = (
            dataset.registry
            if dataset is not None
            else canonical_registry(args.registry)
        )
        states = read_cache_file(cache)[2] if cache is not None else {}
        state = states.get(name)
        if state is not None and denial_until(state, time.time()) is not None:
            raise SystemExit(
                f"{name} {describe_denial(state)}. Not querying; pass --force to "
                "send anyway."
            )

    log = EvidenceLog(_optional_path(args.evidence, default_evidence_path()))
    fetch = RecordingFetch(exchange_fn, log, new_run_id(), args.command)
    bootstrap_path = _optional_path(args.bootstrap, default_bootstrap_path())

    if args.command == "burst":
        if not 1 <= args.count <= MAX_BURST_COUNT:
            raise SystemExit(f"--count must be 1..{MAX_BURST_COUNT}")
        if args.interval < MIN_BURST_INTERVAL:
            raise SystemExit(f"--interval must be >= {MIN_BURST_INTERVAL}")
        bootstrap = probe_bootstrap(bootstrap_path, fetch, args.timeout)
        if bootstrap is None:
            raise SystemExit("IANA bootstrap did not load; see the evidence log")
        report = run_burst(
            registry=canonical_registry(args.registry),
            bootstrap=bootstrap,
            fetch=fetch,
            count=args.count,
            interval=args.interval,
            timeout=args.timeout,
            stop_after_refusals=max(1, args.stop_after_refusals),
        )
        emit(render_burst(report), report.to_json())
        return 0

    if args.command == "verify-cache":
        cache = _optional_path(args.cache, default_cache_path())
        if cache is None:
            raise SystemExit("verify-cache needs a cache path")
        ips = (
            [normalize_ip(ip) for ip in _valid_ips(args.ips)]
            if args.ips
            else verify_targets(cache, max(0, args.sample))
        )
        if not 1 <= len(ips) <= MAX_VERIFY:
            raise SystemExit(f"verify-cache checks 1..{MAX_VERIFY} addresses")
        report = run_verify_cache(
            cache_path=cache,
            ips=ips,
            fetch=fetch,
            bootstrap=probe_bootstrap(bootstrap_path, fetch, args.timeout),
            fix=args.fix,
            interval=max(MIN_BURST_INTERVAL, args.interval),
            timeout=args.timeout,
        )
        emit(render_verify(report), report)
        rows = report["rows"]
        assert isinstance(rows, list)
        diverged = any(row["verdict"] == "diverged" for row in rows)
        return 1 if diverged and not args.fix else 0

    if args.command == "ask":
        ips = [normalize_ip(ip) for ip in _valid_ips(args.ips)]
        private = [ip for ip in ips if not is_queryable(ip)]
        if private:
            raise SystemExit(f"not globally routable, never sent: {private}")
        bootstrap = probe_bootstrap(bootstrap_path, fetch, args.timeout)
        if bootstrap is None:
            raise SystemExit("IANA bootstrap did not load; see the evidence log")
        try:
            rows = run_ask(
                registry=canonical_registry(args.registry),
                ips=ips,
                fetch=fetch,
                bootstrap=bootstrap,
                interval=max(MIN_BURST_INTERVAL, args.interval),
                timeout=args.timeout,
            )
        except ValueError as error:
            raise SystemExit(str(error)) from None
        emit(render_ask(rows), {"rows": rows})
        return 0

    if args.command == "crosscheck":
        assert dataset is not None
        bootstrap = probe_bootstrap(bootstrap_path, fetch, args.timeout)
        ips = [*args.ips, *dataset.sample_addresses(args.sample, seed=args.seed)]
        rows = run_crosscheck(
            ips=ips,
            dataset=dataset,
            fetch=fetch,
            bootstrap=bootstrap,
            interval=args.interval,
            timeout=args.timeout,
        )
        emit(render_crosscheck(rows), {"rows": rows})
        bad = {"mismatch", "local-missing", "remote-missing", "refused"}
        return 1 if any(row["verdict"] in bad for row in rows) else 0

    # replay
    bootstrap = (
        probe_bootstrap(bootstrap_path, fetch, args.timeout) if args.sample else None
    )
    ips = _read_ips(args, bootstrap)
    if not ips:
        raise SystemExit("replay needs addresses (positional, --ips-file, or --sample)")
    report = run_replay(
        ips=ips,
        fetch=fetch,
        cache_path=_optional_path(args.cache, default_cache_path()),
        bootstrap_path=bootstrap_path,
        interval=args.interval,
        max_lookups=args.max_lookups,
        timeout=args.timeout,
    )
    emit(render_replay(report), report.to_json())
    return 1 if args.check and report.unjustified else 0


if __name__ == "__main__":
    raise SystemExit(main())
