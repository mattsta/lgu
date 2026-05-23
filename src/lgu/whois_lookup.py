"""Registry ownership (RDAP "whois") lookups for the grouped recent view.

RDAP is the JSON successor to port-43 whois, so nothing here parses free-form
text. Each address is routed with IANA's RDAP bootstrap table directly to the
authoritative registry (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC), so each can
be paced on its own. Registries still redirect some transferred space to each
other; a redirected answer or refusal is charged to the registry that sent it.

Pacing follows what the registries publish and what they actually send
(validate it with `lgu-whois-probe`, which records every exchange):

- LACNIC documents per-IP limits of 10 queries per minute and 1000 per hour,
  whichever is hit first; we stay just under both, and the request history is
  persisted so back-to-back runs share one budget.
- ARIN, RIPE NCC, APNIC, and AFRINIC publish no numeric RDAP query rate, so
  they get a modest default spacing per registry. Spacing is always slept,
  never deferred.
- RIPE NCC's Acceptable Use Policy caps personal data at 1,000 person/role
  objects per IP per 24 hours, and its RDAP ip answers embed those contacts
  (admin-c/tech-c, nested under abuse; only e-mail is redacted). Exceeding the
  cap blocks the client until the end of the UTC day; repeated blocks, or
  querying while blocked, make the block permanent. RIPE sends the block as a
  429 carrying "%ERROR:201: access denied"; that is classified as a denial,
  never retried, and persisted (temporary: until UTC midnight; permanent:
  until an operator runs `lgu-whois-probe clear-denial` after RIPE lifts it).
- RDAP servers signal throttling with HTTP 429 and an optional Retry-After
  (RFC 7480). A throttle pauses only the registry that sent it: Retry-After
  when given, else 2s doubling per consecutive refusal. Pauses within
  MAX_INLINE_BACKOFF_SECONDS are slept and the IP retried; longer ones defer.
  The pause, streak, and the refusal behind it are persisted for later runs.
- A 403 without Retry-After is an access decision, not pacing: it is reported
  as denied and counts toward the per-run failure stop, never a pause.

RDAP answers with the most specific registration holding the queried address.
An end-user assignment is the answer for its whole range, so it is cached by
range and one query covers every address in it. An allocation is not: other
addresses in it may sit inside a customer's sub-block, so it is cached for the
queried address only (`reusable_range`). Registry placeholders (APNIC's
all-of-IPv4 IANA-BLOCK, or any range wider than a real registration) are never
cached or shown (`placeholder_reason`). `evict_cache` removes answers an
operator has found wrong without touching pacing state or recorded blocks.
Non-global addresses are never sent.
"""

from __future__ import annotations

import http.client
import json
import os
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from ipaddress import (
    IPv4Network,
    IPv6Network,
    ip_address,
    ip_network,
    summarize_address_range,
)
from pathlib import Path
from typing import Protocol
from urllib.parse import quote, urlparse

CACHE_VERSION = 1
CACHE_ENV_VAR = "LGU_WHOIS_CACHE"
CACHE_BASENAME = "whois-cache.json"
BOOTSTRAP_BASENAME = "whois-bootstrap.json"
BOOTSTRAP_URLS = {
    4: "https://data.iana.org/rdap/ipv4.json",
    6: "https://data.iana.org/rdap/ipv6.json",
}
BOOTSTRAP_TTL_SECONDS = 7 * 24 * 3600.0
FALLBACK_BASE_URL = "https://rdap.arin.net/registry/"
USER_AGENT = "lgu-log-audit/1 (rdap ownership lookup; cached, rate limited)"
DEFAULT_TTL_SECONDS = 30 * 24 * 3600.0
NEGATIVE_TTL_CAP_SECONDS = 24 * 3600.0
DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_INTERVAL_SECONDS = 0.5
DEFAULT_MAX_LOOKUPS = 100
# A throttle (429) without Retry-After gets a short pause that doubles with
# each consecutive refusal (2s, 4s, 8s, ...), instead of one long guess.
INITIAL_BACKOFF_SECONDS = 2.0
MAX_BACKOFF_SECONDS = 3600.0
# Waits up to this long are slept inside a run; longer ones defer the IP to a
# later run. Our own spacing is always slept, whatever its length.
MAX_INLINE_WAIT_SECONDS = 60.0
# Registry-imposed pauses get a shorter inline allowance: a burst limiter
# clears within a few doublings (2s, 4s, 8s; LACNIC did in recorded probes),
# while a registry blocking this client (RIPE's daily personal-data block)
# never clears inside a run, so waiting longer only stalls the report.
MAX_INLINE_BACKOFF_SECONDS = 10.0
MAX_ATTEMPTS_PER_IP = 4
MAX_CONSECUTIVE_FAILURES = 3
MAX_RESPONSE_BYTES = 1 << 20
MAX_LABEL_CHARS = 80
HISTORY_SECONDS = 3600.0

# Objects a registry keeps to stand for space it holds no record of; never an
# owner. APNIC's IANA-BLOCK spans 0.0.0.0-255.255.255.255; RIPE keeps IANA-BLK
# and NON-RIPE-NCC-MANAGED-ADDRESS-BLOCK.
PLACEHOLDER_NETNAMES = frozenset(
    {"IANA-BLOCK", "IANA-BLK", "NON-RIPE-NCC-MANAGED-ADDRESS-BLOCK"}
)
# IANA delegates to registries in IPv4 /8s and IPv6 /12s at most, so no real
# registration is wider; a wider answer is a placeholder whatever its name.
WIDEST_PREFIX = {4: 8, 6: 12}
# End-user assignments are leaves: nothing smaller is registered inside them.
# Every registry's assignment types contain this marker (ASSIGNED PA/PI,
# ASSIGNED, ASSIGNED [NON-]PORTABLE, ALLOCATED-ASSIGNED PA, DIRECT
# ASSIGNMENT, REASSIGNMENT, REASSIGNED); no allocation type does. Measured
# on RIPE's whole database (`lgu-whois-data statuses`): 233 of 5.4M
# assignments (0.004%) hold another registration, against 2-72% for each
# allocation status.
LEAF_KIND_MARKER = "ASSIGN"

# Published per-client limits, as (window seconds, max requests) pairs. Values
# sit one step under the documented ceiling so clock skew never tips us over.
DAY_SECONDS = 86400.0
PUBLISHED_LIMITS: dict[str, tuple[tuple[float, int], ...]] = {
    # LACNIC RDAP: 10 per minute and 1000 per hour, per IP, whichever first.
    "LACNIC": ((60.0, 9), (3600.0, 900)),
    # RIPE's AUP caps personal data at 1,000 person/role objects per IP per
    # 24h, and each RDAP ip answer embeds about six. Going over blocks the
    # host until UTC midnight, and repeat blocks are permanent.
    "RIPE NCC": ((DAY_SECONDS, 150),),
}
# How a limit is described when it holds a query back, where the cap is not
# a plain query count.
LIMIT_REASONS: dict[tuple[str, float], str] = {
    ("RIPE NCC", DAY_SECONDS): (
        "RIPE AUP: 1,000 personal-data objects/24h, about 6 per answer; "
        "held to 150 answers/24h"
    ),
}

REGISTRY_BY_HOST = {
    "rdap.arin.net": "ARIN",
    "rdap.db.ripe.net": "RIPE NCC",
    "rdap.apnic.net": "APNIC",
    "rdap.lacnic.net": "LACNIC",
    "rdap.afrinic.net": "AFRINIC",
}
REGISTRY_BY_PORT43 = {
    "whois.arin.net": "ARIN",
    "whois.ripe.net": "RIPE NCC",
    "whois.apnic.net": "APNIC",
    "whois.lacnic.net": "LACNIC",
    "whois.afrinic.net": "AFRINIC",
    "whois.registro.br": "NIC.br",
    "whois.nic.ad.jp": "JPNIC",
    "whois.nic.or.kr": "KRNIC",
    "whois.kisa.or.kr": "KRNIC",
    "whois.twnic.net": "TWNIC",
    "whois.twnic.net.tw": "TWNIC",
    "whois.cnnic.cn": "CNNIC",
    "whois.cnnic.net.cn": "CNNIC",
    "whois.idnic.net": "IDNIC",
    "whois.nic.mx": "NIC Mexico",
}

FETCH_OK = "ok"
FETCH_NOT_FOUND = "not-found"
FETCH_REFUSED = "refused"  # throttled: 429, or 403 carrying Retry-After
FETCH_FORBIDDEN = "forbidden"  # 403 without Retry-After: access denied, not pacing
# The registry has blocked this client (RIPE "%ERROR:201: access denied").
# Only time (temporary) or the registry's staff (permanent) lifts it, and
# querying while blocked is what turns a temporary block permanent.
FETCH_DENIED = "denied"
ACCESS_DENIED_MARKER = "%ERROR:201"
FETCH_ERROR = "error"

# Why an IP was not queried this run. Only DEFER_REFUSED and DEFER_BACKOFF are
# claims about a registry; the rest are limits this client imposes on itself.
DEFER_BUDGET = "budget"
DEFER_STOPPED = "stopped"
DEFER_SPACING = "spacing"
DEFER_PUBLISHED_LIMIT = "published-limit"
DEFER_BACKOFF = "backoff"
DEFER_REFUSED = "refused"
DEFER_DENIED = "denied"


@dataclass(frozen=True)
class FetchResult:
    status: str
    payload: object = None
    retry_after: float | None = None
    http_status: int | None = None
    # Where the answer came from after redirects; None when nothing answered.
    final_url: str | None = None
    # The registry's own explanation (RDAP error description), if it sent one.
    message: str | None = None


@dataclass(frozen=True)
class WhoisRecord:
    start: str
    end: str
    org: str | None
    net: str | None
    ts: float
    registry: str | None = None
    # The registry's classification of the network (RDAP "type", RPSL
    # "status"): ALLOCATED PA, ASSIGNED PA, REASSIGNMENT, ...
    kind: str | None = None

    @property
    def key(self) -> str:
        return f"{self.start}-{self.end}"


@dataclass(frozen=True)
class _Range:
    version: int
    first: int
    last: int
    record: WhoisRecord


@dataclass
class RegistryState:
    name: str
    requests: list[float] = field(default_factory=list)
    blocked_until: float = 0.0
    failures: int = 0
    stopped: str | None = None
    dirty: bool = False
    # Consecutive throttle responses, and when that count last changed; drives
    # the doubling backoff and survives runs so a still-throttling registry is
    # not hammered back at the shortest pause every run.
    refusal_streak: int = 0
    streak_ts: float = 0.0
    # The response behind the current pause: what the registry actually sent.
    last_refusal: dict[str, object] | None = None
    # Set when the registry blocked this client: {ts, permanent, until,
    # http_status, message, url}. `until` is None for a permanent block, which
    # holds until an operator clears it once the registry has lifted it.
    denied: dict[str, object] | None = None
    # IPs this registry answered after another registry redirected them, so a
    # retry honors this registry's pause before the request is sent at all.
    redirected_ips: dict[str, float] = field(default_factory=dict)


Network = IPv4Network | IPv6Network


class LocalSource(Protocol):
    """A local ownership dataset the resolver consults before the network."""

    registry: str

    def lookup(self, raw: str) -> WhoisRecord | None: ...


def default_cache_path() -> Path:
    override = os.environ.get(CACHE_ENV_VAR)
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".cache"
    return base / "lgu" / CACHE_BASENAME


def normalize_ip(raw: str) -> str:
    """Canonical text form; IPv4-mapped IPv6 (::ffff:a.b.c.d) becomes IPv4.

    Dual-stack listeners log IPv4 clients in mapped form. Registries answer
    those with IANA's reserved ::ffff:0:0/96 block, which would then shadow
    every mapped client, so they are looked up and cached as plain IPv4.
    """
    try:
        address = ip_address(raw.strip())
    except ValueError:
        return raw.strip()
    mapped = getattr(address, "ipv4_mapped", None)
    return str(mapped or address)


def is_queryable(ip: str) -> bool:
    try:
        address = ip_address(ip)
    except ValueError:
        return False
    return address.is_global and not address.is_multicast


def clean_label(value: object) -> str | None:
    """Make registry-supplied text safe to print on an operator terminal."""
    if not isinstance(value, str):
        return None
    # Fast path for already-clean text (nearly all registry labels; matters
    # when building local datasets over millions of objects).
    if (
        value
        and len(value) <= MAX_LABEL_CHARS
        and value.isprintable()
        and "  " not in value
        and value[0] != " "
        and value[-1] != " "
    ):
        return value
    printable = "".join(ch if ch.isprintable() else " " for ch in value)
    collapsed = " ".join(printable.split())
    if not collapsed:
        return None
    if len(collapsed) > MAX_LABEL_CHARS:
        collapsed = collapsed[: MAX_LABEL_CHARS - 3] + "..."
    return collapsed


def registry_for_url(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    return REGISTRY_BY_HOST.get(host) or clean_label(host) or "?"


def registry_for_port43(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    host = value.strip().lower().rstrip(".")
    return REGISTRY_BY_PORT43.get(host) or clean_label(host)


# --- RDAP payload parsing -------------------------------------------------


def _vcard_value(entity: dict[str, object], name: str) -> str | None:
    vcard = entity.get("vcardArray")
    if not (isinstance(vcard, list) and len(vcard) == 2):
        return None
    properties = vcard[1]
    if not isinstance(properties, list):
        return None
    for prop in properties:
        if isinstance(prop, list) and len(prop) >= 4 and prop[0] == name:
            return clean_label(prop[3])
    return None


def _vcard_fn(entity: dict[str, object]) -> str | None:
    return _vcard_value(entity, "fn")


def registrant_candidates(payload: dict[str, object]) -> list[dict[str, object]]:
    """Every registrant entity with how ownership parsing judges it.

    RIPE lists the network's maintainer accounts as registrants beside the
    real organisation. A maintainer's vCard name is its own handle (STEMNT-1,
    DTAG-NIC, PALTEL-MNTNER, ...), and its kind is "individual"; the
    organisation has kind "org" and an ORG- handle. Accounts are never owners.
    """
    entities = payload.get("entities")
    if not isinstance(entities, list):
        return []
    judged: list[dict[str, object]] = []
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles")
        if not isinstance(roles, list) or "registrant" not in roles:
            continue
        raw_handle = entity.get("handle")
        handle = raw_handle.upper() if isinstance(raw_handle, str) else ""
        name = _vcard_fn(entity)
        kind = (_vcard_value(entity, "kind") or "").lower()
        if name is None:
            verdict, rank = "no name", None
        elif handle.endswith("-MNT") or name.upper() == handle:
            verdict, rank = "account (maintainer), not an owner", None
        elif kind == "org" or handle.startswith("ORG-"):
            verdict, rank = "organisation", 0
        else:
            verdict, rank = "other registrant", 1
        judged.append(
            {
                "handle": raw_handle,
                "name": name,
                "kind": kind or None,
                "verdict": verdict,
                "rank": rank,
            }
        )
    return judged


def _registrant_org(payload: dict[str, object]) -> str | None:
    ranked = [
        (int(c["rank"]), str(c["name"]))
        for c in registrant_candidates(payload)
        if c["rank"] is not None
    ]
    if not ranked:
        return None  # the network name is the better fallback
    return min(ranked, key=lambda item: item[0])[1]


def _remark_org(payload: dict[str, object]) -> str | None:
    remarks = payload.get("remarks")
    if not isinstance(remarks, list):
        return None
    for remark in remarks:
        if not isinstance(remark, dict):
            continue
        lines = remark.get("description")
        if not isinstance(lines, list):
            continue
        for line in lines:
            if isinstance(line, str) and line.lower().startswith("orgname:"):
                return clean_label(line.split(":", 1)[1])
    return None


def parse_rdap_network(
    payload: dict[str, object], ip: str, ts: float, registry: str | None = None
) -> WhoisRecord | None:
    """Extract the owning network for `ip`, or None if the answer is unusable."""
    start_raw = payload.get("startAddress")
    end_raw = payload.get("endAddress")
    if not isinstance(start_raw, str) or not isinstance(end_raw, str):
        return None
    try:
        start = ip_address(start_raw.strip())
        end = ip_address(end_raw.strip())
        address = ip_address(ip)
    except ValueError:
        return None
    if not (start.version == end.version == address.version):
        return None
    if not (int(start) <= int(address) <= int(end)):
        return None
    org = _registrant_org(payload) or _remark_org(payload)
    net = clean_label(payload.get("name"))
    answered_by = registry_for_port43(payload.get("port43")) or registry
    return WhoisRecord(
        start=str(start),
        end=str(end),
        org=org,
        net=net,
        ts=ts,
        registry=answered_by,
        kind=clean_label(payload.get("type")),
    )


def placeholder_reason(record: WhoisRecord) -> str | None:
    """Why `record` is a registry placeholder rather than an owner, else None.

    Records are cached and matched by range, so a placeholder would answer for
    every address it spans: one 0.0.0.0/0 answer labels every IPv4 visitor
    with it and, being a cache hit, stops any of them being queried until it
    expires. Every source (live answers, the cache file, local datasets) is
    checked with this before a record is used.
    """
    try:
        start = ip_address(record.start)
        end = ip_address(record.end)
        networks = list(summarize_address_range(start, end))  # type: ignore[type-var]
    except (ValueError, TypeError):
        return f"unusable range {record.key}"
    span = str(networks[0]) if len(networks) == 1 else record.key
    label = f"placeholder {record.net} {span}" if record.net else f"placeholder {span}"
    widest = WIDEST_PREFIX[start.version]
    if int(end) - int(start) >= 1 << (start.max_prefixlen - widest):
        return f"{label}: wider than any registration (/{widest})"
    if record.net and record.net.upper() in PLACEHOLDER_NETNAMES:
        return label
    return None


def reusable_range(record: WhoisRecord) -> bool:
    """Whether `record` answers for every address in its range.

    RDAP returns the most specific registration holding the queried address.
    For an end-user assignment that is the answer for its whole range. For an
    allocation it is not: another address in it may sit inside a customer's
    sub-allocation or assignment that the queried one is outside of, so the
    answer holds only for the address asked. A missing type is treated the
    same way.
    """
    return record.kind is not None and LEAF_KIND_MARKER in record.kind.upper()


# --- display ----------------------------------------------------------------


def block_label(record: WhoisRecord, ip: str) -> str:
    """Return the CIDR inside the record's range that contains `ip`."""
    try:
        start = ip_address(record.start)
        end = ip_address(record.end)
        address = ip_address(ip)
        for network in summarize_address_range(start, end):  # type: ignore[type-var]
            if address in network:
                return str(network)
    except (ValueError, TypeError):
        pass
    return record.key


def meaningful_net_name(net: str | None) -> bool:
    """Network names that carry information, not numbering-plan noise."""
    if not net:
        return False
    if net.isdigit() or " - " in net or "/" in net:
        return False
    try:
        ip_address(net)
    except ValueError:
        return True
    return False


def format_whois_line(record: WhoisRecord | None, ip: str) -> str:
    if record is None:
        return "-"
    net = record.net if meaningful_net_name(record.net) else None
    owner = record.org or net
    if owner is None:
        # No assignee on record: the block is held directly by the registry.
        return f"{record.registry or 'registry'} (no assignee listed)  " + (
            block_label(record, ip)
        )
    parts = [owner, block_label(record, ip)]
    if net and net != owner:
        parts.append(net)
    if record.registry:
        parts.append(f"[{record.registry}]")
    return "  ".join(parts)


# --- network ----------------------------------------------------------------


class _HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        if urlparse(newurl).scheme != "https":
            raise urllib.error.HTTPError(
                newurl, code, "refusing non-https redirect", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def parse_retry_after(value: str | None, now: float | None = None) -> float | None:
    """Seconds to wait from a Retry-After header (delta-seconds or HTTP date)."""
    if not value:
        return None
    text = value.strip()
    if text.isdigit():
        seconds = float(text)
    else:
        try:
            when = parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError):
            return None
        if when is None:
            return None
        seconds = when.timestamp() - (time.time() if now is None else now)
    return min(max(seconds, 1.0), MAX_BACKOFF_SECONDS)


@dataclass(frozen=True)
class HttpExchange:
    """Everything observable about one registry request, before classification.

    Kept separate from `FetchResult` so the probe tooling can record exactly
    what a registry sent (status, headers, final URL after redirects) through
    the same code path the resolver uses.
    """

    url: str
    started: float
    elapsed: float
    status: int | None = None
    final_url: str | None = None
    headers: tuple[tuple[str, str], ...] = ()
    body: bytes = b""
    truncated: bool = False
    error: str | None = None

    def header(self, name: str) -> str | None:
        lowered = name.lower()
        for key, value in self.headers:
            if key.lower() == lowered:
                return value
        return None


def fetch_exchange(url: str, timeout: float) -> HttpExchange:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/rdap+json, application/json",
            "User-Agent": USER_AGENT,
        },
    )
    opener = urllib.request.build_opener(_HttpsOnlyRedirectHandler)
    started = time.time()
    clock = time.monotonic()
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
            return HttpExchange(
                url=url,
                started=started,
                elapsed=time.monotonic() - clock,
                status=response.status,
                final_url=response.geturl(),
                headers=tuple(response.headers.items()),
                body=body[:MAX_RESPONSE_BYTES],
                truncated=len(body) > MAX_RESPONSE_BYTES,
            )
    except urllib.error.HTTPError as error:
        try:
            body = error.read(MAX_RESPONSE_BYTES) if error.fp is not None else b""
        except (OSError, http.client.HTTPException):
            body = b""
        headers = error.headers
        return HttpExchange(
            url=url,
            started=started,
            elapsed=time.monotonic() - clock,
            status=error.code,
            final_url=error.geturl() or error.filename,
            headers=tuple(headers.items()) if headers is not None else (),
            body=body,
            error=f"HTTP {error.code} {error.reason}",
        )
    except (OSError, ValueError, http.client.HTTPException) as error:
        return HttpExchange(
            url=url,
            started=started,
            elapsed=time.monotonic() - clock,
            error=f"{type(error).__name__}: {error}",
        )


def rdap_error(body: bytes) -> dict[str, object] | None:
    """The RFC 9083 error fields of a response body, wherever they sit.

    Registries put long terms-of-service notices ahead of the error fields, so
    the error is pulled out by field rather than read off the front.
    """
    try:
        payload = json.loads(body)
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    error: dict[str, object] = {}
    code = payload.get("errorCode")
    if isinstance(code, (int, str)):
        error["errorCode"] = code
    title = payload.get("title")
    if isinstance(title, str):
        error["title"] = title
    description = payload.get("description")
    if isinstance(description, list):
        error["description"] = [
            line for line in description if isinstance(line, str) and line
        ]
    elif isinstance(description, str):
        error["description"] = [description]
    return error or None


def error_text(error: dict[str, object] | None) -> str | None:
    """An RDAP error description as one terminal-safe line, whois '%' dropped."""
    if not error:
        return None
    lines = error.get("description")
    if not isinstance(lines, list) or not lines:
        return None
    text = " ".join(str(line) for line in lines)
    printable = "".join(ch if ch.isprintable() else " " for ch in text)
    words = [word for word in printable.split() if word != "%"]
    return " ".join(words) or None


def classify_exchange(exchange: HttpExchange) -> FetchResult:
    """The resolver's reading of one exchange; the only place status is judged."""
    status = exchange.status
    if status is None:
        return FetchResult(FETCH_ERROR)
    final = exchange.final_url or exchange.url

    def result(
        kind: str,
        payload: object = None,
        retry: float | None = None,
        message: str | None = None,
    ) -> FetchResult:
        return FetchResult(
            kind,
            payload,
            retry_after=retry,
            http_status=status,
            final_url=final,
            message=message,
        )

    if status == 404:
        return result(FETCH_NOT_FOUND)
    explanation = None
    if not 200 <= status < 300:
        explanation = error_text(rdap_error(exchange.body))
        # Checked before the status: RIPE sends its access block as a 429.
        if explanation and ACCESS_DENIED_MARKER in explanation:
            return result(FETCH_DENIED, message=explanation)
    retry = parse_retry_after(exchange.header("Retry-After"))
    # RFC 7480 throttling is 429. A 403 or 503 that names a retry time is the
    # server pacing us too; a bare 403 is an access decision, not a rate.
    if status == 429 or (status in (403, 503) and retry is not None):
        return result(FETCH_REFUSED, retry=retry, message=explanation)
    if status == 403:
        return result(FETCH_FORBIDDEN, message=explanation)
    if not 200 <= status < 300 or exchange.truncated:
        return result(FETCH_ERROR, message=explanation)
    try:
        payload = json.loads(exchange.body)
    except ValueError:
        return result(FETCH_ERROR)
    if not isinstance(payload, dict):
        return result(FETCH_ERROR)
    return result(FETCH_OK, payload)


def fetch_json(url: str, timeout: float) -> FetchResult:
    return classify_exchange(fetch_exchange(url, timeout))


# --- IANA bootstrap -----------------------------------------------------------


def parse_bootstrap(payload: object) -> list[tuple[Network, str]]:
    """Map networks to RDAP base URLs from an IANA bootstrap document."""
    if not isinstance(payload, dict):
        return []
    services = payload.get("services")
    if not isinstance(services, list):
        return []
    entries: list[tuple[Network, str]] = []
    for service in services:
        if not (isinstance(service, list) and len(service) == 2):
            continue
        prefixes, urls = service
        if not isinstance(prefixes, list) or not isinstance(urls, list):
            continue
        base = next(
            (
                url
                for url in urls
                if isinstance(url, str) and url.startswith("https://")
            ),
            None,
        )
        if base is None:
            continue
        if not base.endswith("/"):
            base += "/"
        for prefix in prefixes:
            if not isinstance(prefix, str):
                continue
            try:
                entries.append((ip_network(prefix, strict=False), base))
            except ValueError:
                continue
    return entries


class RdapBootstrap:
    def __init__(self, entries: Iterable[tuple[Network, str]]) -> None:
        self.entries = sorted(entries, key=lambda item: -item[0].prefixlen)

    def base_url(self, ip: str) -> str | None:
        try:
            address = ip_address(ip)
        except ValueError:
            return None
        for network, base in self.entries:
            if network.version == address.version and address in network:
                return base
        return None


def load_bootstrap(
    cache_path: Path | None,
    fetch_fn: Callable[[str, float], FetchResult],
    timeout: float,
    now: float,
) -> RdapBootstrap | None:
    """Return the IANA bootstrap, refreshing the on-disk copy weekly."""
    cached: dict[str, list[list[str]]] | None = None
    cached_ts = 0.0
    if cache_path is not None:
        try:
            stored = json.loads(cache_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            stored = None
        if isinstance(stored, dict) and isinstance(stored.get("services"), dict):
            cached = stored["services"]
            raw_ts = stored.get("ts")
            cached_ts = float(raw_ts) if isinstance(raw_ts, (int, float)) else 0.0

    def entries_from(services: dict[str, list[list[str]]]) -> list[tuple[Network, str]]:
        entries: list[tuple[Network, str]] = []
        for rows in services.values():
            for item in rows if isinstance(rows, list) else []:
                if isinstance(item, list) and len(item) == 2:
                    try:
                        entries.append((ip_network(item[0], strict=False), item[1]))
                    except (TypeError, ValueError):
                        continue
        return entries

    if cached is not None and 0 <= now - cached_ts <= BOOTSTRAP_TTL_SECONDS:
        return RdapBootstrap(entries_from(cached))

    fresh: dict[str, list[list[str]]] = {}
    for version, url in BOOTSTRAP_URLS.items():
        result = fetch_fn(url, timeout)
        if result.status != FETCH_OK:
            fresh = {}
            break
        fresh[str(version)] = [
            [str(network), base] for network, base in parse_bootstrap(result.payload)
        ]
    if fresh and all(fresh.values()):
        if cache_path is not None:
            _atomic_write_json(cache_path, {"ts": now, "services": fresh})
        return RdapBootstrap(entries_from(fresh))
    if cached is not None:
        return RdapBootstrap(entries_from(cached))  # stale beats nothing
    return None


# --- resolver -----------------------------------------------------------------


def next_utc_midnight(ts: float) -> float:
    return (ts // 86400.0 + 1.0) * 86400.0


def denial_until(state: RegistryState, now: float) -> float | None:
    """When an active block on this client ends (inf if permanent), else None."""
    denied = state.denied
    if not denied:
        return None
    if denied.get("permanent"):
        return float("inf")
    until = denied.get("until")
    if isinstance(until, (int, float)) and until > now:
        return float(until)
    return None


def describe_denial(state: RegistryState) -> str:
    denied = state.denied or {}
    status = denied.get("http_status")
    sent = f"HTTP {status}" if status else "a block"
    if denied.get("permanent"):
        span = (
            "permanently; no queries are sent until it is lifted by the registry "
            f"and cleared with `lgu-whois-probe clear-denial '{state.name}'`"
        )
    else:
        until = denied.get("until")
        when = (
            time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(until))
            if isinstance(until, (int, float))
            else "?"
        )
        span = f"until {when}; no queries are sent before then"
    return f"blocked this host ({sent}, access denied) {span}"


def describe_pause(state: RegistryState) -> str:
    """Why `state` is paused, in terms of what the registry actually sent."""
    refusal = state.last_refusal
    if not refusal:
        # A pause loaded from a cache written before refusals were recorded.
        return "paused by an earlier refusal (details not recorded)"
    status = refusal.get("http_status")
    retry = refusal.get("retry_after")
    backoff = refusal.get("backoff")
    sent = f"HTTP {status}" if status else "a refusal"
    if isinstance(retry, (int, float)):
        detail = f"Retry-After {retry:.0f}s"
    else:
        streak = refusal.get("streak")
        pause = f"{backoff:.0f}s" if isinstance(backoff, (int, float)) else "?"
        detail = f"no Retry-After; refusal {streak} in a row, backing off {pause}"
    return f"returned {sent} ({detail})"


class WhoisResolver:
    def __init__(
        self,
        *,
        cache_path: Path | None = None,
        ttl: float = DEFAULT_TTL_SECONDS,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        interval: float = DEFAULT_INTERVAL_SECONDS,
        max_lookups: int = DEFAULT_MAX_LOOKUPS,
        fetch_fn: Callable[[str, float], FetchResult] | None = None,
        bootstrap: RdapBootstrap | None = None,
        time_fn: Callable[[], float] = time.time,
        sleep_fn: Callable[[float], None] = time.sleep,
        queryable_fn: Callable[[str], bool] = is_queryable,
        published_limits: dict[str, tuple[tuple[float, int], ...]] | None = None,
        local_sources: Sequence[LocalSource] = (),
    ) -> None:
        self._limits = (
            PUBLISHED_LIMITS if published_limits is None else published_limits
        )
        self.cache_path = cache_path
        self.ttl = max(0.0, ttl)
        self.timeout = max(0.1, timeout)
        self.interval = max(0.0, interval)
        self.max_lookups = max(0, max_lookups)
        self._fetch_fn = fetch_fn or fetch_json
        self._bootstrap = bootstrap
        self._bootstrap_loaded = bootstrap is not None
        self._time_fn = time_fn
        self._sleep_fn = sleep_fn
        self._queryable_fn = queryable_fn
        self._ranges: dict[str, _Range] = {}
        self._misses: dict[str, float] = {}
        self._registries: dict[str, RegistryState] = {}
        self._fresh_records: set[str] = set()
        self._fresh_misses: set[str] = set()
        # Answers that hold only for the IP asked (allocations, untyped).
        self._answers: dict[str, WhoisRecord] = {}
        self._fresh_answers: set[str] = set()
        # What the registry said for each IP queried this run (None: no
        # owner), whatever the cache held before; read by verification.
        self._latest: dict[str, WhoisRecord | None] = {}
        self._deferred: dict[str, str] = {}
        self._deferred_kind: dict[str, str] = {}
        self._failed: dict[str, str] = {}
        # IPs answered this run with a placeholder, and what was sent.
        self._placeholders: dict[str, str] = {}
        self._last_request: dict[str, float] = {}
        self._loaded = False
        self.lookups_made = 0
        # Local registry datasets (whois_data.LocalDataset), consulted first.
        self._local_sources = list(local_sources)
        self._local_records: dict[str, WhoisRecord | None] = {}
        self.local_hits = 0

    # cache state -------------------------------------------------------------

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if self.cache_path is None:
            return
        records, misses, registries, answers = read_cache_file(self.cache_path)
        for record in records.values():
            self._remember(record)
        self._misses.update(misses)
        self._registries.update(registries)
        self._answers.update(answers)

    def _remember(self, record: WhoisRecord) -> None:
        try:
            start = ip_address(record.start)
            end = ip_address(record.end)
        except ValueError:
            return
        if start.version != end.version or int(start) > int(end):
            return
        self._ranges[record.key] = _Range(
            version=start.version, first=int(start), last=int(end), record=record
        )

    @staticmethod
    def _fresh(ts: float, now: float, ttl: float) -> bool:
        return -ttl <= now - ts <= ttl

    def _cached(self, ip: str, now: float) -> WhoisRecord | None:
        """The most specific fresh answer for `ip`: its own answer, or an
        assignment range holding it."""
        try:
            address = ip_address(ip)
        except ValueError:
            return None
        value = int(address)
        best: WhoisRecord | None = None
        best_span = 0
        answer = self._answers.get(ip)
        if answer is not None and self._fresh(answer.ts, now, self.ttl):
            best = answer
            best_span = int(ip_address(answer.end)) - int(ip_address(answer.start))
        for candidate in self._ranges.values():
            span = candidate.last - candidate.first
            if (
                candidate.version == address.version
                and candidate.first <= value <= candidate.last
                and self._fresh(candidate.record.ts, now, self.ttl)
                and (best is None or span < best_span)
            ):
                best, best_span = candidate.record, span
        return best

    def _recent_miss(self, ip: str, now: float) -> bool:
        ts = self._misses.get(ip)
        if ts is None:
            return False
        return self._fresh(ts, now, min(self.ttl, NEGATIVE_TTL_CAP_SECONDS))

    # routing and pacing ------------------------------------------------------

    def _route(self, ip: str) -> tuple[str, str]:
        if not self._bootstrap_loaded:
            self._bootstrap_loaded = True
            bootstrap_path = (
                self.cache_path.with_name(BOOTSTRAP_BASENAME)
                if self.cache_path is not None
                else None
            )
            self._bootstrap = load_bootstrap(
                bootstrap_path, self._fetch_fn, self.timeout, self._time_fn()
            )
        base = self._bootstrap.base_url(ip) if self._bootstrap else None
        base = base or FALLBACK_BASE_URL
        return base + "ip/" + quote(ip, safe=":."), registry_for_url(base)

    def _state(self, registry: str) -> RegistryState:
        state = self._registries.get(registry)
        if state is None:
            state = self._registries[registry] = RegistryState(name=registry)
        return state

    def _wait_for(self, state: RegistryState, now: float) -> tuple[float, str, str]:
        """Seconds until `state` may be queried again, the DEFER_* kind, and why."""
        until = denial_until(state, now)
        if until is not None:
            return until - now, DEFER_DENIED, describe_denial(state)
        wait, kind, reason = 0.0, "", ""
        if state.blocked_until > now:
            wait, kind = state.blocked_until - now, DEFER_BACKOFF
            reason = describe_pause(state)
        last = self._last_request.get(state.name)
        if last is not None and last + self.interval - now > wait:
            wait, kind = last + self.interval - now, DEFER_SPACING
            reason = "spacing"
        for window, limit in self._limits.get(state.name, ()):
            recent = [ts for ts in state.requests if ts > now - window]
            if len(recent) >= limit:
                until = sorted(recent)[-limit] + window - now
                if until > wait:
                    per = "min" if window == 60.0 else f"{window / 3600:.0f}h"
                    wait, kind = until, DEFER_PUBLISHED_LIMIT
                    reason = LIMIT_REASONS.get(
                        (state.name, window), f"published limit {limit + 1}/{per}"
                    )
        return max(0.0, wait), kind, reason

    def _defer(self, ip: str, kind: str, reason: str) -> None:
        self._deferred_kind.setdefault(ip, kind)
        self._deferred.setdefault(ip, reason)

    def _note_request(self, registry: str, done: float) -> RegistryState:
        # Completion time, not send time: windows then free a slot one
        # response-latency later than the registry would, never earlier.
        state = self._state(registry)
        state.requests.append(done)
        state.dirty = True
        self._last_request[registry] = done
        return state

    @staticmethod
    def _record_refusal(
        state: RegistryState, result: FetchResult, done: float
    ) -> float:
        """Pause `state` for what the server asked, else a doubling backoff."""
        if done - state.streak_ts > HISTORY_SECONDS:
            state.refusal_streak = 0  # an old streak says nothing about now
        state.refusal_streak += 1
        state.streak_ts = done
        if result.retry_after is not None:
            backoff = result.retry_after
        else:
            backoff = min(
                INITIAL_BACKOFF_SECONDS * 2 ** (state.refusal_streak - 1),
                MAX_BACKOFF_SECONDS,
            )
        state.blocked_until = max(state.blocked_until, done + backoff)
        state.last_refusal = {
            "ts": done,
            "http_status": result.http_status,
            "retry_after": result.retry_after,
            "backoff": backoff,
            "streak": state.refusal_streak,
            "url": result.final_url,
        }
        state.dirty = True
        return backoff

    @staticmethod
    def _record_denial(state: RegistryState, result: FetchResult, done: float) -> None:
        message = result.message or ""
        permanent = "permanent" in message.lower()
        state.denied = {
            "ts": done,
            "permanent": permanent,
            # RIPE lifts temporary blocks at the end of the calendar day (UTC).
            "until": None if permanent else next_utc_midnight(done),
            "http_status": result.http_status,
            "message": message,
            "url": result.final_url,
        }
        state.dirty = True

    @staticmethod
    def _record_answer(state: RegistryState, done: float) -> None:
        state.failures = 0
        if state.refusal_streak:
            state.refusal_streak = 0
            state.streak_ts = done
            state.dirty = True

    def resolve_many(self, ips: Iterable[str]) -> None:
        """Look up uncached IPs in the given priority order, within limits."""
        self._load()
        seen: set[str] = set()
        for raw in ips:
            ip = normalize_ip(raw)
            if ip in seen or not self._queryable_fn(ip):
                continue
            seen.add(ip)
            now = self._time_fn()
            if self._local(ip) is not None:
                continue
            if self._cached(ip, now) is not None or self._recent_miss(ip, now):
                continue
            self._resolve_one(ip)

    def requery(self, ips: Iterable[str]) -> dict[str, WhoisRecord | None]:
        """Ask again for `ips` whatever the cache holds, to verify it.

        Pacing, published limits, blocks, and the run budget apply exactly as
        for any lookup. Returns the registry's answer for each IP answered
        (None: no owner); deferred and failed IPs are absent.
        """
        self._load()
        for raw in ips:
            ip = normalize_ip(raw)
            if ip not in self._latest and self._queryable_fn(ip):
                self._resolve_one(ip)
        return dict(self._latest)

    def _resolve_one(self, ip: str) -> None:
        url, routed = self._route(ip)
        # Registries this IP's query touches: where the bootstrap routes it,
        # plus wherever an earlier attempt was redirected. Every one of them
        # must be clear before the request is (re)sent.
        involved = [routed] + [
            name
            for name, state in self._registries.items()
            if ip in state.redirected_ips and name != routed
        ]
        last_refusal = ""
        for _attempt in range(MAX_ATTEMPTS_PER_IP):
            if self.lookups_made >= self.max_lookups:
                self._defer(
                    ip, DEFER_BUDGET, f"run budget of {self.max_lookups} lookups used"
                )
                return
            stopped = next(
                (s for s in map(self._state, involved) if s.stopped is not None), None
            )
            if stopped is not None:
                self._defer(ip, DEFER_STOPPED, f"{stopped.name} {stopped.stopped}")
                return
            now = self._time_fn()
            wait, kind, reason, name = 0.0, "", "", routed
            for state in map(self._state, involved):
                candidate = self._wait_for(state, now)
                if candidate[0] > wait:
                    (wait, kind, reason), name = candidate, state.name
            # Our own spacing is always slept: it is bounded by the interval
            # and deferring on it would cap a run at one lookup per registry.
            cap = (
                MAX_INLINE_BACKOFF_SECONDS
                if kind == DEFER_BACKOFF
                else MAX_INLINE_WAIT_SECONDS
            )
            if kind == DEFER_DENIED:
                self._defer(ip, kind, f"{name} {reason}")
                return
            if wait > cap and kind != DEFER_SPACING:
                if last_refusal and kind == DEFER_BACKOFF:
                    kind = DEFER_REFUSED
                self._defer(ip, kind, f"{name} {reason}; retry in ~{wait:.0f}s")
                return
            if wait > 0:
                self._sleep_fn(wait)

            result = self._fetch_fn(url, self.timeout)
            done = self._time_fn()
            self.lookups_made += 1
            answered = (
                registry_for_url(result.final_url) if result.final_url else routed
            )
            self._note_request(routed, done)
            target = self._note_request(answered, done) if answered != routed else None
            target = target or self._state(routed)
            if answered not in involved:
                involved.append(answered)
            if answered != routed:
                # Remembered until answered, so a later run checks this
                # registry's pause before re-sending through `routed`.
                target.redirected_ips[ip] = done
                target.dirty = True

            if result.status in (FETCH_OK, FETCH_NOT_FOUND):
                self._record_answer(self._state(routed), done)
                self._record_answer(target, done)
                record = (
                    parse_rdap_network(result.payload, ip, done, answered)
                    if result.status == FETCH_OK and isinstance(result.payload, dict)
                    else None
                )
                placeholder = placeholder_reason(record) if record else None
                if placeholder:
                    # An answer, so not a failure; but never cached by range.
                    # Kept as this IP's miss, so it is asked again tomorrow.
                    self._placeholders[ip] = f"{answered} answered with {placeholder}"
                    record = None
                self._latest[ip] = record
                if record is None:
                    self._misses[ip] = done
                    self._fresh_misses.add(ip)
                elif reusable_range(record):
                    self._remember(record)
                    self._fresh_records.add(record.key)
                else:
                    self._answers[ip] = record
                    self._fresh_answers.add(ip)
                return
            if result.status == FETCH_REFUSED:
                backoff = self._record_refusal(target, result, done)
                last_refusal = (
                    f"{target.name} {describe_pause(target)}; retry in ~{backoff:.0f}s"
                )
                continue  # re-evaluate: short pauses are slept, then retried
            if result.status == FETCH_DENIED:
                self._record_denial(target, result, done)
                self._defer(
                    ip, DEFER_DENIED, f"{target.name} {describe_denial(target)}"
                )
                return
            if result.status == FETCH_FORBIDDEN:
                failure = f"{answered} denied access (HTTP 403, no Retry-After)"
            else:
                status = (
                    f"HTTP {result.http_status}" if result.http_status else "no answer"
                )
                failure = f"{answered} lookup failed ({status})"
            target.failures += 1
            self._failed[ip] = failure
            if target.failures >= MAX_CONSECUTIVE_FAILURES:
                target.stopped = (
                    f"paused for this run after {MAX_CONSECUTIVE_FAILURES} "
                    f"failures in a row (last: {failure})"
                )
            return
        self._defer(
            ip,
            DEFER_REFUSED,
            f"{last_refusal} (refused all {MAX_ATTEMPTS_PER_IP} attempts this run)",
        )

    # output ------------------------------------------------------------------

    def _local(self, ip: str) -> WhoisRecord | None:
        """First source: a local registry dataset, used whatever its age.

        Network ownership changes slowly, so an old dump still beats a query.
        Answers are kept per IP in memory, apart from the cache's TTL-checked
        ranges, and are never persisted.
        """
        if ip in self._local_records:
            return self._local_records[ip]
        record = None
        for source in self._local_sources:
            record = source.lookup(ip)
            if record is not None and placeholder_reason(record) is not None:
                record = None
            if record is not None:
                self.local_hits += 1
                break
        self._local_records[ip] = record
        return record

    def lookup(self, raw: str) -> WhoisRecord | None:
        self._load()
        ip = normalize_ip(raw)
        return self._local(ip) or self._cached(ip, self._time_fn())

    def describe(self, raw: str) -> str:
        """The `org` line text for one IP, including why it is blank."""
        ip = normalize_ip(raw)
        record = self.lookup(ip)
        if record is not None:
            return format_whois_line(record, ip)
        if ip in self._deferred:
            return f"? deferred: {self._deferred[ip]}"
        if ip in self._failed:
            return f"? {self._failed[ip]}"
        if ip in self._placeholders:
            return f"? no owner: {self._placeholders[ip]}"
        return "-"

    @property
    def pending(self) -> int:
        return len(self._deferred)

    @property
    def placeholders(self) -> dict[str, str]:
        """IPs answered with a placeholder this run, and what was sent."""
        return dict(self._placeholders)

    # introspection, for the probe/audit tooling ------------------------------

    @property
    def deferred(self) -> dict[str, str]:
        return dict(self._deferred)

    @property
    def deferred_kinds(self) -> dict[str, str]:
        """DEFER_* kind for each deferred IP."""
        return dict(self._deferred_kind)

    @property
    def failed(self) -> dict[str, str]:
        return dict(self._failed)

    @property
    def bootstrap_available(self) -> bool:
        """False when routing fell back to ARIN for every query this run."""
        return self._bootstrap is not None

    def registry_states(self) -> dict[str, RegistryState]:
        self._load()
        return dict(self._registries)

    def next_query_wait(self, registry: str) -> tuple[float, str, str]:
        """(seconds, DEFER_* kind, reason) pacing imposes on `registry` now."""
        self._load()
        state = self._registries.get(registry) or RegistryState(name=registry)
        if state.stopped is not None:
            return float("inf"), DEFER_STOPPED, state.stopped
        return self._wait_for(state, self._time_fn())

    def status_note(self) -> str | None:
        if not self._deferred and not self._failed:
            return None
        parts = []
        if self._deferred:
            parts.append(f"{len(self._deferred)} deferred")
        if self._failed:
            parts.append(f"{len(self._failed)} failed")
        reasons = sorted(set(self._deferred.values()) | set(self._failed.values()))
        return (
            f"whois: {self.lookups_made} lookups this run; {', '.join(parts)} "
            f"({'; '.join(reasons[:3])}); rerun to fill the rest"
        )

    def save(self, *, store_answers: bool = True) -> bool:
        """Persist new answers and pacing state; False only when a write failed.

        `store_answers=False` persists pacing state only: what registries saw
        is always recorded, whether or not the answers are kept.
        """
        if self.cache_path is None:
            return True
        dirty_registries = {
            name: state for name, state in self._registries.items() if state.dirty
        }
        fresh = store_answers and bool(
            self._fresh_records or self._fresh_misses or self._fresh_answers
        )
        if not (fresh or dirty_registries):
            return True
        records = {
            key: self._ranges[key].record
            for key in self._fresh_records
            if key in self._ranges and store_answers
        }
        misses = {ip: self._misses[ip] for ip in self._fresh_misses if store_answers}
        answers = {ip: self._answers[ip] for ip in self._fresh_answers if store_answers}
        if not write_cache_file(
            self.cache_path,
            records,
            misses,
            dirty_registries,
            self._time_fn(),
            answers=answers,
            keep_seconds=max(self.ttl, DEFAULT_TTL_SECONDS),
        ):
            return False
        if store_answers:
            self._fresh_records.clear()
            self._fresh_misses.clear()
            self._fresh_answers.clear()
        for state in dirty_registries.values():
            state.dirty = False
        return True


# --- cache file -------------------------------------------------------------


def _read_cache_payload(path: Path) -> dict[str, object] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict) or payload.get("version") != CACHE_VERSION:
        return None
    return payload


def _record_entry(entry: object) -> WhoisRecord | None:
    if not isinstance(entry, dict):
        return None
    start, end, ts = entry.get("start"), entry.get("end"), entry.get("ts")
    if not isinstance(start, str) or not isinstance(end, str):
        return None
    if not isinstance(ts, (int, float)):
        return None
    return WhoisRecord(
        start=start,
        end=end,
        org=clean_label(entry.get("org")),
        net=clean_label(entry.get("net")),
        ts=float(ts),
        registry=clean_label(entry.get("registry")),
        kind=clean_label(entry.get("kind")),
    )


def _record_json(record: WhoisRecord) -> dict[str, object]:
    return {
        "start": record.start,
        "end": record.end,
        "org": record.org,
        "net": record.net,
        "registry": record.registry,
        "kind": record.kind,
        "ts": record.ts,
    }


def _contains(record: WhoisRecord, ip: str) -> bool:
    try:
        address = ip_address(ip)
        start, end = ip_address(record.start), ip_address(record.end)
    except ValueError:
        return False
    return start.version == end.version == address.version and int(start) <= int(
        address
    ) <= int(end)


def _range_problem(record: WhoisRecord) -> str | None:
    """Why a cached range record must not answer for its range, else None."""
    reason = placeholder_reason(record)
    if reason is not None:
        return reason
    if record.kind is None:
        return (
            "no registration type (cached by an older release), so not known "
            "to answer for its whole range"
        )
    if not reusable_range(record):
        return f"type {record.kind!r} is not an assignment; answers only the IP asked"
    return None


def _answer_problem(ip: str, record: WhoisRecord) -> str | None:
    """Why a cached per-IP answer must not be used, else None."""
    reason = placeholder_reason(record)
    if reason is not None:
        return reason
    if not _contains(record, ip):
        return f"range {record.key} does not hold {ip}"
    return None


def _cache_entries(
    payload: dict[str, object],
) -> tuple[list[WhoisRecord], list[tuple[str, WhoisRecord]]]:
    """Every well-formed range record and per-IP answer, unusable ones too."""
    ranges: list[WhoisRecord] = []
    raw_networks = payload.get("networks")
    for entry in raw_networks.values() if isinstance(raw_networks, dict) else ():
        record = _record_entry(entry)
        if record is not None:
            ranges.append(record)
    answers: list[tuple[str, WhoisRecord]] = []
    raw_answers = payload.get("answers")
    for ip, entry in raw_answers.items() if isinstance(raw_answers, dict) else ():
        record = _record_entry(entry)
        if isinstance(ip, str) and record is not None:
            answers.append((normalize_ip(ip), record))
    return ranges, answers


def read_cache_ignored(path: Path) -> list[tuple[str, WhoisRecord, str]]:
    """Records a cache file holds that `read_cache_file` will not use.

    Each is (the range key or the IP it answered, record, why). Placeholders,
    and ranges without a registration type, come from older releases; the
    next save rewrites the file without them.
    """
    payload = _read_cache_payload(path)
    if payload is None:
        return []
    ranges, answers = _cache_entries(payload)
    found = []
    for record in ranges:
        reason = _range_problem(record)
        if reason is not None:
            found.append((record.key, record, reason))
    for ip, record in answers:
        reason = _answer_problem(ip, record)
        if reason is not None:
            found.append((ip, record, reason))
    return found


def read_cache_file(
    path: Path,
) -> tuple[
    dict[str, WhoisRecord],
    dict[str, float],
    dict[str, RegistryState],
    dict[str, WhoisRecord],
]:
    """(assignment ranges by key, misses, registry states, per-IP answers)."""
    payload = _read_cache_payload(path)
    if payload is None:
        return {}, {}, {}, {}
    ranges, raw_answers = _cache_entries(payload)
    records = {
        record.key: record for record in ranges if _range_problem(record) is None
    }
    answers = {
        ip: record for ip, record in raw_answers if _answer_problem(ip, record) is None
    }
    misses: dict[str, float] = {}
    raw_misses = payload.get("misses")
    if isinstance(raw_misses, dict):
        for ip, ts in raw_misses.items():
            if isinstance(ip, str) and isinstance(ts, (int, float)):
                misses[normalize_ip(ip)] = float(ts)
    registries: dict[str, RegistryState] = {}
    raw_registries = payload.get("registries")
    if isinstance(raw_registries, dict):
        for name, entry in raw_registries.items():
            if not isinstance(name, str) or not isinstance(entry, dict):
                continue
            requests = entry.get("requests")
            blocked = entry.get("blocked_until")
            streak = entry.get("refusal_streak")
            streak_ts = entry.get("streak_ts")
            last_refusal = entry.get("last_refusal")
            denied = entry.get("denied")
            redirected = entry.get("redirected_ips")
            registries[name] = RegistryState(
                name=name,
                requests=[
                    float(ts)
                    for ts in (requests if isinstance(requests, list) else [])
                    if isinstance(ts, (int, float))
                ],
                blocked_until=float(blocked)
                if isinstance(blocked, (int, float))
                else 0.0,
                refusal_streak=streak if isinstance(streak, int) and streak > 0 else 0,
                streak_ts=float(streak_ts)
                if isinstance(streak_ts, (int, float))
                else 0.0,
                last_refusal=last_refusal if isinstance(last_refusal, dict) else None,
                denied=denied if isinstance(denied, dict) else None,
                redirected_ips={
                    normalize_ip(ip): float(ts)
                    for ip, ts in (
                        redirected.items() if isinstance(redirected, dict) else ()
                    )
                    if isinstance(ip, str) and isinstance(ts, (int, float))
                },
            )
    return records, misses, registries, answers


def _newer_denial(
    state: RegistryState, existing: RegistryState | None
) -> dict[str, object] | None:
    denials = [d for d in (state.denied, existing and existing.denied) if d]
    return max(denials, key=lambda d: float(d.get("ts") or 0.0), default=None)


def clear_denial(path: Path, registry: str) -> dict[str, object] | None:
    """Remove a recorded block from the cache file; returns what was cleared.

    For after the registry has lifted the block (RIPE: on request to
    ripe-dbm@ripe.net). Edits the file directly, since the merge in
    `write_cache_file` deliberately keeps any block it finds.
    """
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    registries = payload.get("registries") if isinstance(payload, dict) else None
    entry = registries.get(registry) if isinstance(registries, dict) else None
    if not isinstance(entry, dict) or not entry.get("denied"):
        return None
    cleared = entry["denied"]
    entry["denied"] = None
    entry["blocked_until"] = 0.0
    entry["refusal_streak"] = 0
    if not _atomic_write_json(path, payload):
        return None
    return cleared if isinstance(cleared, dict) else {"denied": cleared}


def _as_span(target: str) -> tuple[int, int, int] | None:
    """(version, first, last) of an IP, a CIDR, or a `start-end` range key."""
    text = target.strip()
    try:
        if "/" in text:
            network = ip_network(text, strict=False)
            return network.version, int(network[0]), int(network[-1])
        if "-" in text:  # a range key; no IP spelling contains '-'
            first_raw, last_raw = text.split("-", 1)
            first, last = ip_address(first_raw.strip()), ip_address(last_raw.strip())
            if first.version != last.version or int(first) > int(last):
                return None
            return first.version, int(first), int(last)
        address = ip_address(normalize_ip(text))
    except ValueError:
        return None
    return address.version, int(address), int(address)


def evict_cache(path: Path, targets: Sequence[str]) -> dict[str, list[str]] | None:
    """Remove every cached answer touching `targets` (IPs, CIDRs, or range
    keys), so the next run asks the registry again. Returns what was removed,
    or None when the file could not be read or written.

    Range records overlapping a target go, since they would keep answering for
    it; so do per-IP answers and misses inside a target. Pacing state, refusal
    history, and recorded blocks are untouched: deleting the cache file to
    "start clean" would lose them, and querying a registry that has blocked
    this host is what makes a temporary RIPE block permanent.
    """
    spans = []
    for target in targets:
        span = _as_span(target)
        if span is None:
            raise ValueError(f"not an IP, CIDR, or start-end range: {target!r}")
        spans.append(span)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None

    def hit(first: int, last: int, version: int) -> bool:
        return any(v == version and first <= hi and lo <= last for v, lo, hi in spans)

    removed: dict[str, list[str]] = {"networks": [], "answers": [], "misses": []}
    networks = payload.get("networks")
    for key in list(networks) if isinstance(networks, dict) else []:
        span = _as_span(key)
        record = _record_entry(networks[key])
        if record is not None:
            span = _as_span(f"{record.start}-{record.end}") or span
        if span is not None and hit(span[1], span[2], span[0]):
            del networks[key]
            removed["networks"].append(key)
    for section in ("answers", "misses"):
        entries = payload.get(section)
        for ip in list(entries) if isinstance(entries, dict) else []:
            span = _as_span(ip)
            if span is not None and hit(span[1], span[2], span[0]):
                del entries[ip]
                removed[section].append(ip)
    if any(removed.values()) and not _atomic_write_json(path, payload):
        return None
    return removed


def _newer_streak(
    state: RegistryState, existing: RegistryState | None
) -> dict[str, object]:
    newest = state
    if existing is not None and existing.streak_ts > state.streak_ts:
        newest = existing
    refusals = [
        r for r in (state.last_refusal, existing and existing.last_refusal) if r
    ]
    last = max(refusals, key=lambda r: float(r.get("ts") or 0.0), default=None)
    return {
        "refusal_streak": newest.refusal_streak,
        "streak_ts": newest.streak_ts,
        "last_refusal": last,
    }


def history_seconds(registry: str) -> float:
    """How long request times are kept: the registry's longest limit window."""
    windows = [window for window, _limit in PUBLISHED_LIMITS.get(registry, ())]
    return max([HISTORY_SECONDS, *windows])


def write_cache_file(
    path: Path,
    records: dict[str, WhoisRecord],
    misses: dict[str, float],
    registries: dict[str, RegistryState] | None = None,
    now: float | None = None,
    *,
    answers: dict[str, WhoisRecord] | None = None,
    keep_seconds: float = DEFAULT_TTL_SECONDS,
) -> bool:
    """Merge into the cache file. Per-IP answers older than `keep_seconds`
    are dropped: they grow with every visitor and are never used once
    expired."""
    now = time.time() if now is None else now
    merged_records, merged_misses, merged_registries, merged_answers = read_cache_file(
        path
    )
    for key, record in records.items():
        existing = merged_records.get(key)
        if existing is None or record.ts >= existing.ts:
            merged_records[key] = record
    for ip, ts in misses.items():
        if ts >= merged_misses.get(ip, float("-inf")):
            merged_misses[ip] = ts
    for ip, record in (answers or {}).items():
        existing = merged_answers.get(ip)
        if existing is None or record.ts >= existing.ts:
            merged_answers[ip] = record
    for name, state in (registries or {}).items():
        existing = merged_registries.get(name)
        combined = set(state.requests) | set(existing.requests if existing else [])
        merged_registries[name] = RegistryState(
            name=name,
            requests=sorted(combined),
            blocked_until=max(
                state.blocked_until, existing.blocked_until if existing else 0.0
            ),
            # The newer observation of the streak wins, so a success that
            # reset it is not undone by an older on-disk count.
            **_newer_streak(state, existing),
            # A recorded block outlives any run that did not see it; clearing
            # one is an explicit operator step (clear_denial).
            denied=_newer_denial(state, existing),
            redirected_ips={
                **(existing.redirected_ips if existing else {}),
                **state.redirected_ips,
            },
        )
    payload = {
        "version": CACHE_VERSION,
        # Assignment ranges: each answers for every address it holds.
        "networks": {
            key: _record_json(record) for key, record in sorted(merged_records.items())
        },
        # Answers that hold only for the IP asked (allocations, untyped).
        "answers": {
            ip: _record_json(record)
            for ip, record in sorted(merged_answers.items())
            if record.ts > now - keep_seconds
        },
        "misses": dict(sorted(merged_misses.items())),
        "registries": {
            name: {
                # As far back as the registry's longest published window.
                "requests": [
                    ts for ts in state.requests if ts > now - history_seconds(name)
                ],
                "blocked_until": state.blocked_until,
                "refusal_streak": state.refusal_streak,
                "streak_ts": state.streak_ts,
                "last_refusal": state.last_refusal,
                "denied": state.denied,
                "redirected_ips": {
                    ip: ts
                    for ip, ts in sorted(state.redirected_ips.items())
                    if ts > now - DEFAULT_TTL_SECONDS
                },
            }
            for name, state in sorted(merged_registries.items())
        },
    }
    return _atomic_write_json(path, payload)


def _atomic_write_json(path: Path, payload: object) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            json.dump(payload, handle)
            handle.write("\n")
            tmp_path = Path(handle.name)
        tmp_path.replace(path)
    except OSError:
        return False
    return True
