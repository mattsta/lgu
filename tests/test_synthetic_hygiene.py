from __future__ import annotations

from pathlib import Path

from synthetic_hygiene import (
    find_hygiene_findings,
    find_live_ips,
    find_structured_synthetic_findings,
)


def test_docs_examples_scenarios_and_sweeps_are_synthetic() -> None:
    assert [finding.format() for finding in find_hygiene_findings()] == []


def test_live_ip_finder_allows_documentation_ips() -> None:
    text = "203.0.113.10\n198.51.100.20\n192.0.2.30\n2001:db8::1\n"

    assert find_live_ips(Path("sample.md"), text) == []


def test_live_ip_finder_rejects_non_documentation_ips() -> None:
    address = ".".join(("10", "1", "2", "3"))
    findings = find_live_ips(Path("sample.md"), f"client={address}\n")

    assert [finding.format() for finding in findings] == [
        f"sample.md:1: non-documentation IPv4 address: {address}"
    ]


def test_live_ip_finder_rejects_non_documentation_ipv6() -> None:
    address = "fd00::1"
    findings = find_live_ips(Path("sample.md"), f"client={address}\n")

    assert [finding.format() for finding in findings] == [
        f"sample.md:1: non-documentation IPv6 address: {address}"
    ]


def test_structured_scenario_hygiene_rejects_live_shapes() -> None:
    payload = """
    {
      "name": "bad",
      "actors": {"source": {"ip": "client-one"}},
      "events": [
        {"actor": "source", "at": 0, "path": "/real-post", "referer": "https://reader.invalid/"}
      ]
    }
    """

    findings = find_structured_synthetic_findings(
        Path("tests/scenarios/bad.json"), payload
    )

    assert [finding.reason for finding in findings] == [
        "non-synthetic scenario ip",
        "non-synthetic scenario path",
        "non-synthetic scenario referer",
    ]
