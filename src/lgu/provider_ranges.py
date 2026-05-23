from __future__ import annotations

import csv
import json
from collections.abc import Iterable
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True)
class ProviderRangeRecord:
    cidr: str
    provider: str
    service: str = ""
    region: str = ""
    source: str = ""


@dataclass(frozen=True)
class ProviderMatch:
    provider: str
    network: str
    service: str = ""
    region: str = ""
    source: str = ""


class ProviderRangeSource(Protocol):
    name: str

    def can_load(self, path: Path) -> bool: ...

    def load(self, path: Path) -> Iterable[ProviderRangeRecord]: ...


@dataclass(frozen=True)
class _Interval:
    start: int
    end: int
    prefixlen: int
    match: ProviderMatch


_SOURCE_ADAPTERS: list[ProviderRangeSource] = []


class ProviderRangeLookup:
    def __init__(self, records: Iterable[ProviderRangeRecord]) -> None:
        self._prefixes: dict[int, dict[int, dict[int, tuple[ProviderMatch, ...]]]] = {
            4: {},
            6: {},
        }
        self._count = 0
        self._cache: dict[str, tuple[ProviderMatch, ...]] = {}
        grouped: dict[tuple[int, int, int], dict[ProviderMatch, None]] = {}
        for record in records:
            interval = _interval_from_record(record)
            version = 4 if "." in interval.match.network else 6
            key = (version, interval.prefixlen, interval.start)
            grouped.setdefault(key, {})[interval.match] = None

        for (version, prefixlen, network_int), matches in grouped.items():
            self._prefixes[version].setdefault(prefixlen, {})[network_int] = tuple(
                sorted(
                    matches,
                    key=lambda match: (
                        match.provider,
                        match.service,
                        match.region,
                        match.network,
                    ),
                )
            )
            self._count += len(matches)

    @classmethod
    def from_path(
        cls,
        path: str | Path,
        *,
        source_format: str = "auto",
        provider_include: Iterable[str] = (),
        provider_exclude: Iterable[str] = (),
    ) -> ProviderRangeLookup:
        return cls(
            filter_provider_records(
                load_provider_records(Path(path), source_format=source_format),
                provider_include=provider_include,
                provider_exclude=provider_exclude,
            )
        )

    @classmethod
    def from_paths(
        cls,
        paths: Iterable[str | Path],
        *,
        source_format: str = "auto",
        provider_include: Iterable[str] = (),
        provider_exclude: Iterable[str] = (),
    ) -> ProviderRangeLookup:
        records = []
        for path in paths:
            records.extend(
                load_provider_records(Path(path), source_format=source_format)
            )
        return cls(
            filter_provider_records(
                records,
                provider_include=provider_include,
                provider_exclude=provider_exclude,
            )
        )

    @property
    def count(self) -> int:
        return self._count

    def lookup(self, ip: str) -> ProviderMatch | None:
        matches = self.lookup_all(ip)
        return matches[0] if matches else None

    def lookup_all(self, ip: str) -> tuple[ProviderMatch, ...]:
        if ip in self._cache:
            return self._cache[ip]
        try:
            parsed = ip_address(ip)
        except ValueError:
            self._cache[ip] = ()
            return ()

        value = int(parsed)
        max_prefixlen = 32 if parsed.version == 4 else 128
        prefixes = self._prefixes[parsed.version]
        result = ()
        for prefixlen in range(max_prefixlen, -1, -1):
            networks = prefixes.get(prefixlen)
            if not networks:
                continue
            network_int = _network_int(value, max_prefixlen, prefixlen)
            matches = networks.get(network_int)
            if matches:
                result = matches
                break
        self._cache[ip] = result
        return result


def register_provider_source(
    adapter: ProviderRangeSource, *, prepend: bool = False
) -> None:
    if any(existing.name == adapter.name for existing in _SOURCE_ADAPTERS):
        raise ValueError(f"provider source adapter already registered: {adapter.name}")
    if prepend:
        _SOURCE_ADAPTERS.insert(0, adapter)
    else:
        _SOURCE_ADAPTERS.append(adapter)


def provider_source_names() -> tuple[str, ...]:
    return tuple(adapter.name for adapter in _SOURCE_ADAPTERS)


def load_provider_records(
    path: Path, *, source_format: str = "auto"
) -> list[ProviderRangeRecord]:
    adapters = _matching_adapters(path, source_format=source_format)
    errors = []
    for adapter in adapters:
        try:
            records = list(adapter.load(path))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"{adapter.name}: {exc}")
            continue
        if records:
            return records
    if errors:
        raise ValueError(
            f"{path}: no provider source adapter succeeded ({'; '.join(errors)})"
        )
    raise ValueError(f"{path}: no provider source adapter matched")


def filter_provider_records(
    records: Iterable[ProviderRangeRecord],
    *,
    provider_include: Iterable[str] = (),
    provider_exclude: Iterable[str] = (),
) -> list[ProviderRangeRecord]:
    included = {provider.lower() for provider in provider_include}
    excluded = {provider.lower() for provider in provider_exclude}
    return [
        record
        for record in records
        if (not included or record.provider.lower() in included)
        and record.provider.lower() not in excluded
    ]


def provider_label(match: ProviderMatch | None) -> str:
    if match is None:
        return "-"
    parts = [match.provider]
    if match.service:
        parts.append(match.service)
    if match.region:
        parts.append(match.region)
    return "/".join(parts)


class CloudProviderIPAddressesSource:
    name = "cloud-provider-ip-addresses"

    def can_load(self, path: Path) -> bool:
        return path.is_dir() and (
            (path / "all_providers").is_dir()
            or (path / "README.md").exists()
            and any(path.glob("*/*_ips_merged_v4.txt"))
        )

    def load(self, path: Path) -> Iterable[ProviderRangeRecord]:
        csv_path = path / "all_providers" / "all_providers.csv"
        if csv_path.exists():
            return UnifiedProviderCsvSource().load(csv_path)
        json_path = path / "all_providers" / "all_providers.json"
        if json_path.exists():
            return UnifiedProviderJsonSource().load(json_path)
        records = list(self._load_merged_provider_dirs(path))
        if records:
            return records
        return []

    def _load_merged_provider_dirs(self, root: Path) -> Iterable[ProviderRangeRecord]:
        for provider_dir in sorted(root.iterdir()):
            if (
                not provider_dir.is_dir()
                or provider_dir.name.startswith(".")
                or provider_dir.name == "all_providers"
            ):
                continue
            provider = provider_dir.name
            for path in sorted(provider_dir.glob(f"{provider}_ips_merged_v*.txt")):
                yield from _load_plain_text(path, provider=provider)


class UnifiedProviderCsvSource:
    name = "unified-csv"

    def can_load(self, path: Path) -> bool:
        return path.is_file() and path.suffix.lower() == ".csv"

    def load(self, path: Path) -> Iterable[ProviderRangeRecord]:
        default_provider = _provider_from_path(path)
        with path.open(newline="", encoding="utf-8") as handle:
            for record in csv.DictReader(handle):
                normalized = _record_from_mapping(
                    record, source=str(path), default_provider=default_provider
                )
                if normalized is not None:
                    yield normalized


class UnifiedProviderJsonSource:
    name = "unified-json"

    def can_load(self, path: Path) -> bool:
        return path.is_file() and path.suffix.lower() == ".json"

    def load(self, path: Path) -> Iterable[ProviderRangeRecord]:
        data = json.loads(path.read_text(encoding="utf-8"))
        default_provider = _provider_from_path(path)
        records = _json_records(data)
        for record in records:
            normalized = _record_from_mapping(
                record, source=str(path), default_provider=default_provider
            )
            if normalized is not None:
                yield normalized


class PlainCidrTextSource:
    name = "plain-cidr-text"

    def can_load(self, path: Path) -> bool:
        return path.is_file()

    def load(self, path: Path) -> Iterable[ProviderRangeRecord]:
        yield from _load_plain_text(path, provider=_provider_from_path(path))


def _matching_adapters(path: Path, *, source_format: str) -> list[ProviderRangeSource]:
    if source_format != "auto":
        matches = [
            adapter for adapter in _SOURCE_ADAPTERS if adapter.name == source_format
        ]
        if not matches:
            known = ", ".join(("auto", *provider_source_names()))
            raise ValueError(
                f"unknown provider source format {source_format!r}; expected {known}"
            )
        return matches
    return [adapter for adapter in _SOURCE_ADAPTERS if adapter.can_load(path)]


def _json_records(data: Any) -> Iterable[dict[str, Any]]:
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                yield item
        return
    if isinstance(data, dict):
        for key in ("records", "ranges", "prefixes", "data", "values"):
            value = data.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        yield item
                return
        if _record_cidr(data) is not None:
            yield data


def _record_from_mapping(
    record: dict[str, Any], *, source: str, default_provider: str
) -> ProviderRangeRecord | None:
    cidr = _record_cidr(record)
    if cidr is None:
        return None
    provider = _first_string(record, "provider", "name", "source", "cloud")
    return ProviderRangeRecord(
        cidr=cidr,
        provider=(provider or default_provider or "unknown").strip().lower(),
        service=(_first_string(record, "service", "product") or "").strip().lower(),
        region=(_first_string(record, "region", "scope", "location") or "")
        .strip()
        .lower(),
        source=source,
    )


def _record_cidr(record: dict[str, Any]) -> str | None:
    for key in (
        "cidr",
        "prefix",
        "ip_address",
        "ip_prefix",
        "ipv4_prefix",
        "ipv6_prefix",
    ):
        value = record.get(key)
        if value:
            return str(value).strip()
    return None


def _first_string(record: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _load_plain_text(path: Path, *, provider: str) -> Iterable[ProviderRangeRecord]:
    provider = provider.strip().lower()
    for line in path.read_text(encoding="utf-8").splitlines():
        cidr = line.split("#", 1)[0].strip()
        if not cidr:
            continue
        yield ProviderRangeRecord(cidr=cidr, provider=provider, source=str(path))


def _network_int(value: int, max_prefixlen: int, prefixlen: int) -> int:
    if prefixlen == 0:
        return 0
    host_bits = max_prefixlen - prefixlen
    return (value >> host_bits) << host_bits


def _interval_from_record(record: ProviderRangeRecord) -> _Interval:
    network = ip_network(record.cidr, strict=False)
    match = ProviderMatch(
        provider=record.provider,
        network=str(network),
        service=record.service,
        region=record.region,
        source=record.source,
    )
    return _Interval(
        start=int(network.network_address),
        end=int(network.broadcast_address),
        prefixlen=network.prefixlen,
        match=match,
    )


def _provider_from_path(path: Path) -> str:
    name = path.stem
    for suffix in (
        "_ips_merged_v4",
        "_ips_merged_v6",
        "_ips_merged",
        "_ips_v4",
        "_ips_v6",
        "_ips",
    ):
        if name.endswith(suffix):
            return name[: -len(suffix)].lower()
    if path.is_file():
        return name.lower()
    return path.parent.name.lower() if path.parent.name else "unknown"


register_provider_source(CloudProviderIPAddressesSource())
register_provider_source(UnifiedProviderCsvSource())
register_provider_source(UnifiedProviderJsonSource())
register_provider_source(PlainCidrTextSource())
