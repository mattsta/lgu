from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

DEFAULT_CHECKED_PATHS = (
    Path("README.md"),
    Path("docs"),
    Path("examples"),
    Path("tests/scenarios"),
    Path("tests/sweeps"),
)

LIVE_DETAIL_PATTERNS: tuple[str, ...] = ()

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.%]*(?![0-9A-Fa-f:])"
)
PUBLIC_URL_RE = re.compile(r"https?://(?![a-z0-9.-]*\.example\.test\b)", re.IGNORECASE)
BARE_DOMAIN_RE = re.compile(
    r"\b(?![a-z0-9.-]*\.example\.test\b)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|dev|app|cloud|ai|co|sh|gov|edu|info)\b",
    re.IGNORECASE,
)
LIVE_ROUTE_RE = re.compile(r"/(?:page|p)\d+\b")
CHECKED_SUFFIXES = {
    ".conf",
    ".csv",
    ".example",
    ".json",
    ".log",
    ".md",
    ".txt",
    ".yaml",
    ".yml",
}
SCENARIO_JSON_ROOTS = (Path("tests/scenarios"), Path("tests/sweeps"))
REFERER_ALIASES = {"-", "none", "referrer", "alt_referrer", "junk_referrer"}


@dataclass(frozen=True)
class HygieneFinding:
    path: Path
    line: int
    value: str
    reason: str

    def format(self) -> str:
        return f"{self.path}:{self.line}: {self.reason}: {self.value}"


def find_hygiene_findings(
    paths: tuple[Path, ...] = DEFAULT_CHECKED_PATHS,
) -> list[HygieneFinding]:
    findings = []
    for path in iter_checked_files(paths):
        text = path.read_text(encoding="utf-8")
        lowered = text.lower()
        findings.extend(find_live_ips(path, text))
        findings.extend(find_structured_synthetic_findings(path, text))
        for pattern in LIVE_DETAIL_PATTERNS:
            index = lowered.find(pattern)
            if index >= 0:
                findings.append(
                    HygieneFinding(
                        path=path,
                        line=line_number(text, index),
                        value=pattern,
                        reason="live token",
                    )
                )
        for regex, reason in (
            (PUBLIC_URL_RE, "public URL"),
            (BARE_DOMAIN_RE, "live-looking domain"),
            (LIVE_ROUTE_RE, "live-looking route"),
        ):
            for match in regex.finditer(text):
                findings.append(
                    HygieneFinding(
                        path=path,
                        line=line_number(text, match.start()),
                        value=match.group(0),
                        reason=reason,
                    )
                )
    return findings


def find_live_ips(path: Path, text: str) -> list[HygieneFinding]:
    findings = []
    for regex, family in (
        (IPV4_RE, "IPv4"),
        (IPV6_CANDIDATE_RE, "IPv6"),
    ):
        for match in regex.finditer(text):
            value = match.group(0)
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if not is_documentation_address(address):
                findings.append(
                    HygieneFinding(
                        path=path,
                        line=line_number(text, match.start()),
                        value=value,
                        reason=f"non-documentation {family} address",
                    )
                )
    return findings


def find_structured_synthetic_findings(path: Path, text: str) -> list[HygieneFinding]:
    if path.suffix != ".json" or not is_under_any(path, SCENARIO_JSON_ROOTS):
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return [
            HygieneFinding(
                path=path,
                line=exc.lineno,
                value=exc.msg,
                reason="invalid JSON",
            )
        ]
    findings: list[HygieneFinding] = []
    walk_json(path, text, data, (), findings)
    return findings


def walk_json(
    path: Path,
    text: str,
    value: Any,
    key_path: tuple[str, ...],
    findings: list[HygieneFinding],
) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            walk_json(path, text, child, (*key_path, str(key)), findings)
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            walk_json(path, text, child, (*key_path, str(index)), findings)
        return
    if not isinstance(value, str) or not key_path:
        return

    key = key_path[-1]
    if key == "ip":
        validate_structured_ip(path, text, value, findings)
    elif key in {"path", "path_template"}:
        validate_structured_path(path, text, value, findings)
    elif key == "referer":
        validate_structured_referer(path, text, value, findings)
    elif key == "set" or "." not in key:
        return
    else:
        dotted_key = key
        leaf = dotted_key.rsplit(".", 1)[-1]
        if leaf == "ip":
            validate_structured_ip(path, text, value, findings)
        elif leaf in {"path", "path_template"}:
            validate_structured_path(path, text, value, findings)
        elif leaf == "referer":
            validate_structured_referer(path, text, value, findings)


def validate_structured_ip(
    path: Path, text: str, value: str, findings: list[HygieneFinding]
) -> None:
    if value.startswith("doc:"):
        return
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        findings.append(
            structured_finding(path, text, value, "non-synthetic scenario ip")
        )
        return
    if not is_documentation_address(address):
        findings.append(
            structured_finding(path, text, value, "non-synthetic scenario ip")
        )


def validate_structured_path(
    path: Path, text: str, value: str, findings: list[HygieneFinding]
) -> None:
    if not value.startswith("/synthetic/"):
        findings.append(
            structured_finding(path, text, value, "non-synthetic scenario path")
        )


def validate_structured_referer(
    path: Path, text: str, value: str, findings: list[HygieneFinding]
) -> None:
    if value in REFERER_ALIASES:
        return
    parsed = urlparse(value)
    if parsed.netloc.endswith(".example.test"):
        return
    findings.append(
        structured_finding(path, text, value, "non-synthetic scenario referer")
    )


def structured_finding(
    path: Path, text: str, value: str, reason: str
) -> HygieneFinding:
    index = text.find(json.dumps(value))
    if index < 0:
        index = text.find(value)
    return HygieneFinding(
        path=path,
        line=line_number(text, max(index, 0)),
        value=value,
        reason=reason,
    )


def is_under_any(path: Path, roots: tuple[Path, ...]) -> bool:
    resolved = path.resolve()
    for root in roots:
        try:
            resolved.relative_to(root.resolve())
        except ValueError:
            continue
        return True
    return False


def iter_checked_files(paths: tuple[Path, ...] = DEFAULT_CHECKED_PATHS) -> list[Path]:
    files = []
    for path in paths:
        if path.is_file():
            files.append(path)
            continue
        if not path.exists():
            continue
        files.extend(
            child
            for child in path.rglob("*")
            if child.is_file() and child.suffix in CHECKED_SUFFIXES
        )
    return sorted(files)


def is_documentation_address(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    return any(
        address in network
        for network in (
            ipaddress.ip_network("192.0.2.0/24"),
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("203.0.113.0/24"),
            ipaddress.ip_network("2001:db8::/32"),
        )
    )


def line_number(text: str, offset: int) -> int:
    return text[:offset].count("\n") + 1
