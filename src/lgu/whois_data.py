"""Local registry datasets: bulk database dumps as the first whois source.

Registries publish their databases as daily RPSL text dumps with personal data
removed. A local index built from them answers ownership lookups with no
network traffic, no per-query limits, and no personal data retrieved, so the
resolver consults it before its cache and before live RDAP.

Pipeline (`lgu-whois-data sync`):

1. download: conditional (If-Modified-Since) HTTPS fetch of each dump file,
   written to a temporary file and renamed, so a failed transfer never
   replaces a good dump;
2. parse: stream the gzip'd RPSL (blank-line separated objects, `attr: value`
   lines, whitespace or `+` continuation lines, `%`/`#` comment lines, `#`
   end-of-line comments on structured attributes), keeping only the range,
   netname, org handle, country, and status of each network object, and the
   name of each organisation;
3. index: registry ownership is nested (allocation > sub-allocation >
   assignment), so the ranges are flattened in one sorted sweep into disjoint
   segments, each labelled with its most specific owner. A lookup is then one
   primary-key range probe in a read-only SQLite file: the same answer RDAP
   gives (the most specific object), at no load cost per run.

Placeholder objects a registry keeps for space it does not manage (RIPE's
`IANA-BLK` and `NON-RIPE-NCC-MANAGED-ADDRESS-BLOCK`) are dropped, so a dump
only ever answers for addresses its registry actually holds, including space
transferred in from another region. The resolver also rejects any record wider
than a real registration (`whois_lookup.placeholder_reason`) from every source.
"""

from __future__ import annotations

import argparse
import email.utils
import gzip
import json
import os
import random
import resource
import sqlite3
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from pathlib import Path

try:
    from .whois_lookup import (
        PLACEHOLDER_NETNAMES,
        USER_AGENT,
        WhoisRecord,
        _HttpsOnlyRedirectHandler,
        clean_label,
        default_cache_path,
        format_whois_line,
        normalize_ip,
    )
except ImportError:  # pragma: no cover - direct script execution
    from whois_lookup import (  # type: ignore[no-redef]
        PLACEHOLDER_NETNAMES,
        USER_AGENT,
        WhoisRecord,
        _HttpsOnlyRedirectHandler,
        clean_label,
        default_cache_path,
        format_whois_line,
        normalize_ip,
    )

DATA_ENV_VAR = "LGU_WHOIS_DATA"
DATA_DIRNAME = "whois-data"
INDEX_BASENAME = "index.sqlite"
INDEX_SCHEMA = 1
DOWNLOAD_TIMEOUT_SECONDS = 60.0
DOWNLOAD_CHUNK_BYTES = 1 << 20
INSERT_BATCH = 50_000
NETWORK_ROLES = ("inetnum", "inet6num")


@dataclass(frozen=True)
class DatasetSpec:
    """One registry's bulk dump: where its files live and what they hold."""

    key: str
    registry: str
    # (role, URL); roles: "organisation", "inetnum", "inet6num"
    files: tuple[tuple[str, str], ...]
    # netnames of objects that stand for space this registry does not manage
    placeholder_netnames: frozenset[str] = frozenset()


RIPE_SPLIT = "https://ftp.ripe.net/ripe/dbase/split/"
DATASETS: dict[str, DatasetSpec] = {
    "ripe": DatasetSpec(
        key="ripe",
        registry="RIPE NCC",
        files=(
            ("organisation", RIPE_SPLIT + "ripe.db.organisation.utf8.gz"),
            ("inetnum", RIPE_SPLIT + "ripe.db.inetnum.utf8.gz"),
            ("inet6num", RIPE_SPLIT + "ripe.db.inet6num.utf8.gz"),
        ),
        placeholder_netnames=PLACEHOLDER_NETNAMES,
    ),
}


def default_data_dir() -> Path:
    override = os.environ.get(DATA_ENV_VAR)
    if override:
        return Path(override).expanduser()
    return default_cache_path().with_name(DATA_DIRNAME)


def dataset_dir(data_dir: Path, spec: DatasetSpec) -> Path:
    return data_dir / spec.key


def raw_path(data_dir: Path, spec: DatasetSpec, url: str) -> Path:
    return dataset_dir(data_dir, spec) / "raw" / url.rsplit("/", 1)[1]


def index_path(data_dir: Path, spec: DatasetSpec) -> Path:
    return dataset_dir(data_dir, spec) / INDEX_BASENAME


# --- download -----------------------------------------------------------------


@dataclass(frozen=True)
class DownloadResult:
    role: str
    url: str
    path: Path
    status: str  # "downloaded" | "not-modified"
    bytes: int
    last_modified: str | None
    elapsed: float


def _read_json(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _meta_path(dest: Path) -> Path:
    return dest.with_name(dest.name + ".meta.json")


OpenerFn = Callable[[], urllib.request.OpenerDirector]


def download_file(
    url: str,
    dest: Path,
    *,
    role: str,
    timeout: float = DOWNLOAD_TIMEOUT_SECONDS,
    opener_fn: OpenerFn | None = None,
) -> DownloadResult:
    """Fetch `url` to `dest`, skipping the transfer when unchanged upstream."""
    meta = _read_json(_meta_path(dest))
    headers = {"User-Agent": USER_AGENT}
    previous = meta.get("last_modified")
    if dest.exists() and isinstance(previous, str):
        headers["If-Modified-Since"] = previous
    request = urllib.request.Request(url, headers=headers)
    opener = (
        opener_fn()
        if opener_fn
        else urllib.request.build_opener(_HttpsOnlyRedirectHandler)
    )
    started = time.monotonic()
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        if error.code == 304 and dest.exists():
            return DownloadResult(
                role,
                url,
                dest,
                "not-modified",
                dest.stat().st_size,
                previous if isinstance(previous, str) else None,
                time.monotonic() - started,
            )
        raise
    with response:
        last_modified = response.headers.get("Last-Modified")
        total = 0
        partial: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                "wb", dir=dest.parent, prefix=f".{dest.name}.", delete=False
            ) as handle:
                partial = Path(handle.name)
                while chunk := response.read(DOWNLOAD_CHUNK_BYTES):
                    handle.write(chunk)
                    total += len(chunk)
            partial.replace(dest)
        except BaseException:
            if partial is not None:
                partial.unlink(missing_ok=True)
            raise
    _meta_path(dest).write_text(
        json.dumps(
            {
                "url": url,
                "last_modified": last_modified,
                "downloaded": time.time(),
                "bytes": total,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return DownloadResult(
        role, url, dest, "downloaded", total, last_modified, time.monotonic() - started
    )


def published_at(dest: Path) -> float | None:
    """Upstream publication time of a downloaded dump (its Last-Modified)."""
    value = _read_json(_meta_path(dest)).get("last_modified")
    if not isinstance(value, str):
        return None
    try:
        return email.utils.parsedate_to_datetime(value).timestamp()
    except (TypeError, ValueError, IndexError):
        return None


# --- RPSL parsing ---------------------------------------------------------------


def iter_rpsl(lines: Iterable[str], wanted: frozenset[str]) -> Iterator[dict[str, str]]:
    """Yield each object's first value of every `wanted` attribute.

    Continuation lines (leading space, tab, or `+`) extend the attribute they
    follow; `%` and `#` lines are comments; a blank line ends an object.
    Attribute names are matched as registries write them in dumps: lowercase
    at the start of the line.

    Hot loop over ~100M lines per full RIPE dump: wanted attributes are found
    with one C-level `startswith(tuple)`, and every other line costs a single
    first-character check.
    """
    prefixes = tuple(f"{key}:" for key in wanted)
    obj: dict[str, str] = {}
    extending: str | None = None
    for line in lines:
        if line.startswith(prefixes):
            key, _, value = line.partition(":")
            if key in obj:
                extending = None
            else:
                obj[key] = value.strip()
                extending = key
            continue
        head = line[:1]
        if head in (" ", "\t", "+") and extending is not None:
            rest = line[1:].strip()
            if rest or head == "+":
                obj[extending] += " " + rest
                continue
        if head in ("\n", "\r", "") or line.isspace():
            if obj:
                yield obj
                obj = {}
            extending = None
            continue
        if head in (" ", "\t", "+", "%", "#"):
            continue  # continuation of an unwanted attribute, or a comment
        extending = None
    if obj:
        yield obj


def structured(value: str | None) -> str | None:
    """A structured attribute's value without its RPSL end-of-line comment."""
    if value is None:
        return None
    text = value.split("#", 1)[0].strip()
    return text or None


def _ipv4_int(text: str) -> int | None:
    """Dotted-quad to int without `ipaddress` overhead (hot in dataset builds)."""
    parts = text.strip().split(".")
    if len(parts) != 4:
        return None
    value = 0
    for part in parts:
        if not part.isdigit() or len(part) > 3 or (len(part) > 1 and part[0] == "0"):
            return None
        octet = int(part)
        if octet > 255:
            return None
        value = value << 8 | octet
    return value


def parse_range(role: str, value: str) -> tuple[int, int, int] | None:
    """(version, first, last) of an inetnum range or inet6num prefix."""
    text = structured(value)
    if text is None:
        return None
    try:
        if role == "inetnum":
            first_raw, sep, last_raw = text.partition("-")
            if not sep:
                network = ip_network(text, strict=False)
                if network.version != 4:
                    return None
                return 4, int(network[0]), int(network[-1])
            first = _ipv4_int(first_raw)
            last = _ipv4_int(last_raw)
            if first is None or last is None or first > last:
                return None
            return 4, first, last
        network = ip_network(text, strict=False)
    except ValueError:
        return None
    if network.version != 6:
        return None
    return 6, int(network[0]), int(network[-1])


def open_dump(path: Path) -> Iterator[str]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as handle:  # type: ignore[operator]
        yield from handle


def load_organisations(path: Path) -> dict[str, str]:
    names: dict[str, str] = {}
    for obj in iter_rpsl(open_dump(path), frozenset({"organisation", "org-name"})):
        handle = structured(obj.get("organisation"))
        name = clean_label(obj.get("org-name"))
        if handle and name:
            names[handle.upper()] = name
    return names


@dataclass(frozen=True)
class NetworkObject:
    version: int
    first: int
    last: int
    org: str | None
    net: str | None
    country: str | None
    status: str | None


def iter_networks(
    path: Path, role: str, orgs: dict[str, str], placeholders: frozenset[str]
) -> Iterator[NetworkObject]:
    wanted = frozenset({role, "netname", "org", "country", "status"})
    for obj in iter_rpsl(open_dump(path), wanted):
        raw = obj.get(role)
        if raw is None:
            continue
        span = parse_range(role, raw)
        if span is None:
            continue
        net = structured(obj.get("netname"))
        if net is not None and net.upper() in placeholders:
            continue
        handle = structured(obj.get("org"))
        yield NetworkObject(
            version=span[0],
            first=span[1],
            last=span[2],
            org=orgs.get(handle.upper()) if handle else None,
            net=clean_label(net),
            # country and status are stored, never printed: no label cleaning
            country=structured(obj.get("country")),
            status=structured(obj.get("status")),
        )


# --- flattening ---------------------------------------------------------------


def flatten(items: Iterable[tuple[int, int, int]]) -> Iterator[tuple[int, int, int]]:
    """Disjoint (first, last, owner) segments from nested (first, last, owner).

    `items` must be sorted by first ascending, then last descending, so every
    enclosing range precedes the ranges inside it. Each address covered by any
    input is covered by exactly one output segment, labelled with the most
    specific (innermost) input containing it; on identical ranges the later
    input wins. A range that partially overlaps its enclosing range is
    clipped to it (registries forbid such overlaps; this keeps output sane).
    Output is ascending, and memory is proportional to nesting depth.
    """
    stack: list[tuple[int, int]] = []  # (last, owner) of open enclosing ranges
    cursor = 0  # first address not yet emitted while the stack is non-empty
    for first, last, owner in items:
        while stack and stack[-1][0] < first:
            end, enclosing = stack.pop()
            if cursor <= end:
                yield cursor, end, enclosing
                cursor = end + 1
        if stack:
            end, enclosing = stack[-1]
            if cursor < first:
                yield cursor, first - 1, enclosing
            last = min(last, end)
        cursor = first
        stack.append((last, owner))
    while stack:
        end, enclosing = stack.pop()
        if cursor <= end:
            yield cursor, end, enclosing
            cursor = end + 1


# --- index build --------------------------------------------------------------


def _key(value: int) -> bytes:
    return value.to_bytes(16, "big")


SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE objects (
    id INTEGER PRIMARY KEY,
    version INTEGER NOT NULL,
    first BLOB NOT NULL,
    last BLOB NOT NULL,
    org TEXT,
    net TEXT,
    country TEXT,
    status TEXT
);
CREATE TABLE segments (
    version INTEGER NOT NULL,
    first BLOB NOT NULL,
    last BLOB NOT NULL,
    object INTEGER NOT NULL,
    PRIMARY KEY (version, first)
) WITHOUT ROWID;
"""


@dataclass
class BuildStats:
    registry: str
    path: Path
    organisations: int = 0
    objects: dict[int, int] = field(default_factory=dict)
    segments: dict[int, int] = field(default_factory=dict)
    published: float | None = None
    seconds: dict[str, float] = field(default_factory=dict)
    bytes: int = 0
    peak_rss_bytes: int | None = None


def peak_rss_bytes() -> int:
    """Peak resident memory of this process (ru_maxrss is KiB on Linux)."""
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(peak if sys.platform == "darwin" else peak * 1024)


def build_index(
    spec: DatasetSpec,
    files: dict[str, Path],
    out: Path,
    *,
    published: float | None = None,
) -> BuildStats:
    """Build the lookup index for `spec` from its dump files into `out`."""
    stats = BuildStats(spec.registry, out, published=published)
    out.parent.mkdir(parents=True, exist_ok=True)
    work = out.with_name(out.name + ".building")
    work.unlink(missing_ok=True)
    conn = sqlite3.connect(work)
    try:
        conn.executescript(
            "PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; "
            "PRAGMA temp_store=FILE; PRAGMA cache_size=-65536;" + SCHEMA
        )
        clock = time.monotonic()
        orgs = (
            load_organisations(files["organisation"]) if "organisation" in files else {}
        )
        stats.organisations = len(orgs)
        stats.seconds["organisations"] = time.monotonic() - clock

        clock = time.monotonic()
        batch: list[tuple[object, ...]] = []
        insert = (
            "INSERT INTO objects (version, first, last, org, net, country, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        for role in NETWORK_ROLES:
            if role not in files:
                continue
            for item in iter_networks(
                files[role], role, orgs, spec.placeholder_netnames
            ):
                batch.append(
                    (
                        item.version,
                        _key(item.first),
                        _key(item.last),
                        item.org,
                        item.net,
                        item.country,
                        item.status,
                    )
                )
                stats.objects[item.version] = stats.objects.get(item.version, 0) + 1
                if len(batch) >= INSERT_BATCH:
                    conn.executemany(insert, batch)
                    batch.clear()
        conn.executemany(insert, batch)
        stats.seconds["parse"] = time.monotonic() - clock

        clock = time.monotonic()
        conn.execute(
            "CREATE INDEX objects_order ON objects (version, first, last DESC)"
        )
        for version in (4, 6):
            rows = conn.execute(
                "SELECT first, last, id FROM objects WHERE version = ? "
                "ORDER BY first, last DESC, id",
                (version,),
            )
            ranges = (
                (int.from_bytes(first, "big"), int.from_bytes(last, "big"), oid)
                for first, last, oid in rows
            )
            segments: list[tuple[object, ...]] = []
            count = 0
            writer = conn.cursor()
            for first, last, oid in flatten(ranges):
                segments.append((version, _key(first), _key(last), oid))
                count += 1
                if len(segments) >= INSERT_BATCH:
                    writer.executemany(
                        "INSERT INTO segments VALUES (?, ?, ?, ?)", segments
                    )
                    segments.clear()
            writer.executemany("INSERT INTO segments VALUES (?, ?, ?, ?)", segments)
            stats.segments[version] = count
        conn.execute("DROP INDEX objects_order")
        stats.seconds["flatten"] = time.monotonic() - clock

        meta = {
            "schema": INDEX_SCHEMA,
            "registry": spec.registry,
            "dataset": spec.key,
            "built": time.time(),
            "published": published,
            "objects": stats.objects,
            "segments": stats.segments,
            "organisations": stats.organisations,
        }
        conn.executemany(
            "INSERT INTO meta VALUES (?, ?)",
            [(key, json.dumps(value)) for key, value in meta.items()],
        )
        conn.commit()
        clock = time.monotonic()
        conn.execute("VACUUM")
        stats.seconds["vacuum"] = time.monotonic() - clock
    except BaseException:
        conn.close()
        work.unlink(missing_ok=True)
        raise
    conn.close()
    work.replace(out)  # readers holding the old file keep their snapshot
    stats.bytes = out.stat().st_size
    stats.peak_rss_bytes = peak_rss_bytes()
    return stats


def nesting_by_status(
    objects: Iterable[tuple[int, int, int, str | None]],
) -> dict[str, dict[str, int]]:
    """Count, per status, objects and those containing a strictly smaller one.

    `objects` are (version, first, last, status) sorted by version, first
    ascending, then last descending, so each container precedes its contents.
    An object with the same range as its container is a duplicate
    registration, not a sub-registration, and is not counted as one.
    """
    tally: dict[str, dict[str, int]] = {}
    stack: list[_OpenObject] = []  # containers of the current object

    def close(entry: _OpenObject) -> None:
        counts = tally.setdefault(str(entry.status), {"objects": 0, "with_children": 0})
        counts["objects"] += 1
        counts["with_children"] += entry.has_child

    for version, first, last, status in objects:
        while stack and (stack[-1].version != version or stack[-1].last < first):
            close(stack.pop())
        for entry in stack:
            if (entry.first, entry.last) != (first, last):
                entry.has_child = True
        stack.append(_OpenObject(version, first, last, status))
    while stack:
        close(stack.pop())
    return tally


@dataclass
class _OpenObject:
    version: int
    first: int
    last: int
    status: str | None
    has_child: bool = False


# --- runtime lookup -------------------------------------------------------------


class LocalDataset:
    """Read-only lookups against one built index."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._conn = sqlite3.connect(
            f"file:{path}?mode=ro&immutable=1", uri=True, check_same_thread=False
        )
        meta = {
            key: json.loads(value)
            for key, value in self._conn.execute("SELECT key, value FROM meta")
        }
        if meta.get("schema") != INDEX_SCHEMA:
            self._conn.close()
            raise ValueError(f"{path}: index schema {meta.get('schema')!r}")
        self.meta = meta
        self.registry = str(meta.get("registry"))
        published = meta.get("published")
        built = meta.get("built")
        # A record's age is the dump's publication time when known.
        self.as_of = float(published if isinstance(published, (int, float)) else built)

    def close(self) -> None:
        self._conn.close()

    def status_nesting(self) -> dict[str, dict[str, int]]:
        """Per status: objects, and how many contain a smaller registration.

        Evidence for which registration types are leaves (nothing registered
        inside), which decides whether a live answer of that type may answer
        for other addresses in its range.
        """
        rows = self._conn.execute(
            "SELECT version, first, last, status FROM objects "
            "ORDER BY version, first, last DESC"
        )
        return nesting_by_status(
            (version, int.from_bytes(first, "big"), int.from_bytes(last, "big"), status)
            for version, first, last, status in rows
        )

    def sample_addresses(self, count: int, seed: int = 0) -> list[str]:
        """Addresses spread over the indexed space, one per distinct segment.

        Each pick probes the segment at or after a random key, so the cost is
        logarithmic; versions are mixed in proportion to their segment counts.
        """

        rng = random.Random(seed)
        counts = self.meta.get("segments") or {}
        v4 = int(counts.get("4", 0)) if isinstance(counts, dict) else 0
        v6 = int(counts.get("6", 0)) if isinstance(counts, dict) else 0
        picked: dict[bytes, str] = {}
        attempts = 0
        while len(picked) < count and attempts < count * 20 and (v4 or v6):
            attempts += 1
            version = 4 if rng.random() < v4 / (v4 + v6) else 6
            bits = 32 if version == 4 else 128
            probe = _key(rng.getrandbits(bits))
            row = self._conn.execute(
                "SELECT first, last FROM segments WHERE version = ? AND first >= ? "
                "ORDER BY first LIMIT 1",
                (version, probe),
            ).fetchone()
            if row is None or row[0] in picked:
                continue
            first = int.from_bytes(row[0], "big")
            last = int.from_bytes(row[1], "big")
            middle = first + (last - first) // 2
            address = IPv4Address(middle) if version == 4 else IPv6Address(middle)
            picked[row[0]] = str(address)
        return list(picked.values())

    def lookup(self, raw: str) -> WhoisRecord | None:
        try:
            address = ip_address(normalize_ip(raw))
        except ValueError:
            return None
        key = _key(int(address))
        row = self._conn.execute(
            "SELECT last, object FROM segments WHERE version = ? AND first <= ? "
            "ORDER BY first DESC LIMIT 1",
            (address.version, key),
        ).fetchone()
        if row is None or row[0] < key:
            return None
        found = self._conn.execute(
            "SELECT first, last, org, net FROM objects WHERE id = ?", (row[1],)
        ).fetchone()
        if found is None:
            return None
        first, last, org, net = found
        version_type = type(address)
        return WhoisRecord(
            start=str(version_type(int.from_bytes(first, "big"))),
            end=str(version_type(int.from_bytes(last, "big"))),
            org=org,
            net=net,
            ts=self.as_of,
            registry=self.registry,
        )


def load_datasets(data_dir: Path | None) -> list[LocalDataset]:
    """Every built index under `data_dir`, in DATASETS order; unusable ones skipped."""
    if data_dir is None:
        return []
    found = []
    for spec in DATASETS.values():
        path = index_path(data_dir, spec)
        if not path.exists():
            continue
        try:
            found.append(LocalDataset(path))
        except (sqlite3.Error, ValueError):
            continue
    return found


# --- sync -------------------------------------------------------------------------


@dataclass
class SyncReport:
    dataset: str
    downloads: list[DownloadResult]
    built: BuildStats | None
    reason: str


def sync_dataset(
    spec: DatasetSpec,
    data_dir: Path,
    *,
    force_build: bool = False,
    download: bool = True,
    opener_fn: OpenerFn | None = None,
) -> SyncReport:
    """Refresh dumps for `spec` and rebuild its index when they changed."""
    downloads = (
        [
            download_file(
                url, raw_path(data_dir, spec, url), role=role, opener_fn=opener_fn
            )
            for role, url in spec.files
        ]
        if download
        else []
    )
    files = {role: raw_path(data_dir, spec, url) for role, url in spec.files}
    missing = [role for role, path in files.items() if not path.exists()]
    if missing:
        raise FileNotFoundError(f"{spec.key}: missing dump files {missing}")
    out = index_path(data_dir, spec)
    changed = any(result.status == "downloaded" for result in downloads)
    newest_dump = max(path.stat().st_mtime for path in files.values())
    stale = not out.exists() or out.stat().st_mtime < newest_dump
    if not (force_build or changed or stale):
        return SyncReport(spec.key, downloads, None, "index current")
    stamps = [published_at(path) for path in files.values()]
    known = [stamp for stamp in stamps if stamp is not None]
    stats = build_index(spec, files, out, published=min(known) if known else None)
    reason = (
        "forced" if force_build else ("dumps changed" if changed else "index stale")
    )
    return SyncReport(spec.key, downloads, stats, reason)


# --- CLI --------------------------------------------------------------------------


def _when(ts: object) -> str:
    if not isinstance(ts, (int, float)):
        return "-"
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts))


def _size(count: int) -> str:
    return f"{count / (1 << 20):.1f} MiB"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lgu-whois-data",
        description=(
            "Manage local registry datasets that log-audit --whois consults "
            "before the network."
        ),
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help=f"Dataset directory. Default: ${DATA_ENV_VAR} or {default_data_dir()}",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sync = sub.add_parser("sync", help="Download changed dumps and rebuild indexes.")
    sync.add_argument("datasets", nargs="*", default=None, help=f"{sorted(DATASETS)}")
    sync.add_argument("--force-build", action="store_true")
    sync.add_argument(
        "--no-download", action="store_true", help="Build from dumps already on disk."
    )
    sub.add_parser("info", help="Show built indexes.")
    sub.add_parser(
        "statuses",
        help="Per registration status: how many objects have registrations inside.",
    )
    lookup = sub.add_parser("lookup", help="Look addresses up in the local indexes.")
    lookup.add_argument("ips", nargs="+")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    data_dir = args.data_dir or default_data_dir()

    if args.command == "sync":
        keys = args.datasets or list(DATASETS)
        unknown = [key for key in keys if key not in DATASETS]
        if unknown:
            raise SystemExit(f"unknown datasets {unknown}; known: {sorted(DATASETS)}")
        for key in keys:
            report = sync_dataset(
                DATASETS[key],
                data_dir,
                force_build=args.force_build,
                download=not args.no_download,
            )
            for result in report.downloads:
                print(
                    f"{key} {result.role}: {result.status}, {_size(result.bytes)} "
                    f"in {result.elapsed:.1f}s (published {result.last_modified})"
                )
            if report.built is None:
                print(f"{key}: {report.reason}; not rebuilt")
                continue
            built = report.built
            timings = ", ".join(f"{k} {v:.1f}s" for k, v in built.seconds.items())
            print(
                f"{key}: built {built.path} ({report.reason}): "
                f"{built.organisations} organisations, objects {built.objects}, "
                f"segments {built.segments}, {_size(built.bytes)}; {timings}; "
                f"peak memory {_size(built.peak_rss_bytes or 0)}"
            )
        return 0

    datasets = load_datasets(data_dir)
    if args.command == "info":
        if not datasets:
            print(f"no built datasets under {data_dir}; run `lgu-whois-data sync`")
            return 1
        for dataset in datasets:
            meta = dataset.meta
            print(
                f"{meta.get('dataset')} ({dataset.registry}): {dataset.path} "
                f"{_size(dataset.path.stat().st_size)}; published "
                f"{_when(meta.get('published'))}, built {_when(meta.get('built'))}; "
                f"objects {meta.get('objects')}, segments {meta.get('segments')}"
            )
        return 0

    if args.command == "statuses":
        if not datasets:
            print(f"no built datasets under {data_dir}; run `lgu-whois-data sync`")
            return 1
        for dataset in datasets:
            print(f"{dataset.registry} ({dataset.path}):")
            nesting = dataset.status_nesting()
            for status, counts in sorted(
                nesting.items(), key=lambda item: -item[1]["objects"]
            ):
                total, nested = counts["objects"], counts["with_children"]
                print(
                    f"  {status:<24} {total:>9} objects  {nested:>8} with "
                    f"registrations inside ({100.0 * nested / total:.3f}%)"
                )
        return 0

    # lookup
    if not datasets:
        print(f"no built datasets under {data_dir}; run `lgu-whois-data sync`")
        return 1
    for raw in args.ips:
        ip = normalize_ip(raw)
        for dataset in datasets:
            clock = time.perf_counter()
            record = dataset.lookup(ip)
            micros = (time.perf_counter() - clock) * 1e6
            line = format_whois_line(record, ip) if record else "-"
            print(f"{ip:<39} {dataset.registry}: {line}  ({micros:.0f}us)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
