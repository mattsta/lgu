from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path

CACHE_VERSION = 1
CACHE_ENV_VAR = "LGU_PTR_CACHE"
CACHE_BASENAME = "ptr-cache.json"
DEFAULT_TTL_SECONDS = 7 * 24 * 3600.0
NEGATIVE_TTL_CAP_SECONDS = 24 * 3600.0
DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_WORKERS = 16
DIG_CHUNK_SIZE = 8
DIG_STALL_BUDGET = 3
RESOLVER_METHODS = ("auto", "dig", "socket")

_QUESTION_RE = re.compile(r"^;(?P<name>\S+\.arpa\.?)\s")
_ANSWER_RE = re.compile(
    r"^(?P<name>\S+\.arpa\.?)\s+\d+\s+IN\s+PTR\s+(?P<target>\S+)\s*$",
    re.IGNORECASE,
)
_HEX_DIGITS = frozenset("0123456789abcdef")


@dataclass(frozen=True)
class PtrEntry:
    ptr: str | None
    ts: float


def default_cache_path() -> Path:
    override = os.environ.get(CACHE_ENV_VAR)
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".cache"
    return base / "lgu" / CACHE_BASENAME


def normalize_ip(raw: str) -> str:
    try:
        return str(ip_address(raw.strip()))
    except ValueError:
        return raw.strip()


def arpa_to_ip(name: str) -> str | None:
    label = name.rstrip(".").lower()
    if label.endswith(".in-addr.arpa"):
        octets = label[: -len(".in-addr.arpa")].split(".")
        if len(octets) != 4:
            return None
        candidate = ".".join(reversed(octets))
    elif label.endswith(".ip6.arpa"):
        nibbles = label[: -len(".ip6.arpa")].split(".")
        if len(nibbles) != 32 or any(
            len(nibble) != 1 or nibble not in _HEX_DIGITS for nibble in nibbles
        ):
            return None
        packed = "".join(reversed(nibbles))
        candidate = ":".join(packed[index : index + 4] for index in range(0, 32, 4))
    else:
        return None
    try:
        return str(ip_address(candidate))
    except ValueError:
        return None


def ip_to_arpa(ip: str) -> str | None:
    try:
        return ip_address(ip).reverse_pointer
    except ValueError:
        return None


def _clean_name(target: str) -> str | None:
    name = target.strip().rstrip(".")
    return name or None


def _dig_available() -> bool:
    return shutil.which("dig") is not None


def resolve_with_dig(ips: list[str], timeout: float) -> dict[str, str | None]:
    """Resolve a chunk of IPs with one dig invocation; timeout is per query.

    Only IPs the resolver answered for appear in the result; an IP mapped to
    None answered with no PTR record, and an absent IP means the query never
    completed and should not be cached.
    """
    queries: list[str] = []
    for ip in ips:
        if ip_to_arpa(ip) is not None:
            queries.extend(("-x", ip))
    if not queries:
        return {}

    per_query_timeout = max(1, round(timeout))
    query_count = len(queries) // 2
    command = [
        "dig",
        "+noall",
        "+question",
        "+answer",
        "+tries=1",
        f"+time={per_query_timeout}",
        *queries,
    ]
    # dig runs the chunk sequentially, so a dead resolver would otherwise cost
    # per_query_timeout for every query in it. Cap the chunk at a few stalled
    # queries and keep whatever dig already printed.
    chunk_deadline = per_query_timeout * min(query_count, DIG_STALL_BUDGET) + 1
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=chunk_deadline,
            check=False,
        )
    except subprocess.TimeoutExpired as expired:
        return parse_dig_output(_decode_stream(expired.stdout))
    except (OSError, subprocess.SubprocessError):
        return {}
    return parse_dig_output(completed.stdout)


def _decode_stream(stream: str | bytes | None) -> str:
    if stream is None:
        return ""
    if isinstance(stream, bytes):
        return stream.decode("utf-8", errors="replace")
    return stream


def parse_dig_output(stdout: str) -> dict[str, str | None]:
    """Map queried IPs to PTR names from `dig +noall +question +answer` output.

    Echoed question lines mark the queries the resolver actually answered, so
    an IP absent from the result never got a reply and must not be cached.
    """
    resolved: dict[str, str | None] = {}
    for line in stdout.splitlines():
        question = _QUESTION_RE.match(line)
        if question:
            ip = arpa_to_ip(question.group("name"))
            if ip is not None:
                resolved.setdefault(ip, None)
            continue
        answer = _ANSWER_RE.match(line)
        if not answer:
            continue
        ip = arpa_to_ip(answer.group("name"))
        name = _clean_name(answer.group("target"))
        if ip is not None and name is not None and not resolved.get(ip):
            resolved[ip] = name
    return resolved


def resolve_with_socket(ips: list[str]) -> dict[str, str | None]:
    resolved: dict[str, str | None] = {}
    for ip in ips:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except (OSError, UnicodeError):
            resolved[ip] = None
            continue
        resolved[ip] = _clean_name(hostname)
    return resolved


def _chunks(items: list[str], size: int) -> Iterable[list[str]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


class ReverseDNSResolver:
    def __init__(
        self,
        *,
        cache_path: Path | None = None,
        ttl: float = DEFAULT_TTL_SECONDS,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        workers: int = DEFAULT_WORKERS,
        method: str = "auto",
        resolve_fn: Callable[[list[str]], dict[str, str | None]] | None = None,
        time_fn: Callable[[], float] = time.time,
    ) -> None:
        self.cache_path = cache_path
        self.ttl = max(0.0, ttl)
        self.timeout = max(0.1, timeout)
        self.workers = max(1, workers)
        self.method = method if method in RESOLVER_METHODS else "auto"
        self._resolve_fn = resolve_fn
        self._time_fn = time_fn
        self._entries: dict[str, PtrEntry] = {}
        self._fresh_keys: set[str] = set()
        self._loaded = False

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if self.cache_path is None:
            return
        self._entries.update(read_cache_file(self.cache_path))

    def _is_fresh(self, entry: PtrEntry, now: float) -> bool:
        ttl = self.ttl if entry.ptr else min(self.ttl, NEGATIVE_TTL_CAP_SECONDS)
        age = now - entry.ts
        return -ttl <= age <= ttl

    def resolve_many(self, ips: Iterable[str]) -> None:
        self._load()
        now = self._time_fn()
        pending: list[str] = []
        seen: set[str] = set()
        for raw in ips:
            ip = normalize_ip(raw)
            if not ip or ip in seen:
                continue
            seen.add(ip)
            entry = self._entries.get(ip)
            if entry is not None and self._is_fresh(entry, now):
                continue
            pending.append(ip)
        if not pending:
            return
        for ip, ptr in self._resolve_batch(pending).items():
            self._entries[ip] = PtrEntry(ptr=ptr, ts=now)
            self._fresh_keys.add(ip)

    def _resolve_batch(self, ips: list[str]) -> dict[str, str | None]:
        if self._resolve_fn is not None:
            return self._resolve_fn(ips)
        use_dig = self.method == "dig" or (self.method == "auto" and _dig_available())
        workers = min(self.workers, len(ips))
        resolved: dict[str, str | None] = {}
        if use_dig:
            chunks = list(_chunks(ips, DIG_CHUNK_SIZE))
            workers = min(self.workers, len(chunks))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                for partial in pool.map(
                    lambda chunk: resolve_with_dig(chunk, self.timeout), chunks
                ):
                    resolved.update(partial)
            return resolved
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for partial in pool.map(lambda ip: resolve_with_socket([ip]), ips):
                resolved.update(partial)
        return resolved

    def lookup(self, raw: str) -> str | None:
        self._load()
        entry = self._entries.get(normalize_ip(raw))
        if entry is None or not self._is_fresh(entry, self._time_fn()):
            return None
        return entry.ptr

    def save(self) -> None:
        if self.cache_path is None or not self._fresh_keys:
            return
        updates = {key: self._entries[key] for key in self._fresh_keys}
        if write_cache_file(self.cache_path, updates):
            self._fresh_keys.clear()


def read_cache_file(path: Path) -> dict[str, PtrEntry]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(payload, dict) or payload.get("version") != CACHE_VERSION:
        return {}
    raw_entries = payload.get("entries")
    if not isinstance(raw_entries, dict):
        return {}
    entries: dict[str, PtrEntry] = {}
    for ip, record in raw_entries.items():
        if not isinstance(record, dict):
            continue
        ptr = record.get("ptr")
        ts = record.get("ts")
        if ptr is not None and not isinstance(ptr, str):
            continue
        if not isinstance(ts, (int, float)):
            continue
        entries[normalize_ip(ip)] = PtrEntry(ptr=ptr or None, ts=float(ts))
    return entries


def write_cache_file(path: Path, updates: dict[str, PtrEntry]) -> bool:
    merged = read_cache_file(path)
    for ip, entry in updates.items():
        existing = merged.get(ip)
        if existing is None or entry.ts >= existing.ts:
            merged[ip] = entry
    payload = {
        "version": CACHE_VERSION,
        "entries": {
            ip: {"ptr": entry.ptr, "ts": entry.ts}
            for ip, entry in sorted(merged.items())
        },
    }
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
        os.replace(tmp_path, path)
    except OSError:
        return False
    return True
