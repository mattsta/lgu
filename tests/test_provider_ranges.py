from __future__ import annotations

import json
from pathlib import Path

from synthetic_access import audit_args, doc_ip, row, rows_for_paths, watch_args

from lgu.audit import (
    build_ip_stats,
    build_runtime,
    detect_provider_exclusions,
    provider_activity_proofs,
)
from lgu.provider_ranges import (
    ProviderRangeLookup,
    ProviderRangeRecord,
    load_provider_records,
    provider_label,
    provider_source_names,
    register_provider_source,
)
from lgu.watch import LiveContext, format_json, process_row


def test_plain_text_adapter_uses_provider_name_from_file(tmp_path: Path) -> None:
    path = tmp_path / "synthetichost_ips_merged_v4.txt"
    path.write_text("192.0.2.0/24\n", encoding="utf-8")

    lookup = ProviderRangeLookup.from_path(path)

    assert provider_label(lookup.lookup("192.0.2.44")) == "synthetichost"
    assert lookup.lookup("198.51.100.44") is None


def test_plain_text_adapter_uses_stem_for_simple_cidr_file(tmp_path: Path) -> None:
    path = tmp_path / "SyntheticHost.txt"
    path.write_text("192.0.2.0/24\n", encoding="utf-8")

    lookup = ProviderRangeLookup.from_path(path, provider_include=("synthetichost",))

    assert provider_label(lookup.lookup("192.0.2.44")) == "synthetichost"


def test_unified_csv_adapter_preserves_service_and_longest_prefix(
    tmp_path: Path,
) -> None:
    path = tmp_path / "providers.csv"
    path.write_text(
        "\n".join(
            [
                "cidr,provider,service,region",
                "192.0.2.0/24,synthetichost,generic,us-test-1",
                "192.0.2.32/27,synthetichost,scanner,us-test-2",
            ]
        ),
        encoding="utf-8",
    )

    lookup = ProviderRangeLookup.from_path(path)

    assert provider_label(lookup.lookup("192.0.2.44")) == (
        "synthetichost/scanner/us-test-2"
    )
    assert provider_label(lookup.lookup("192.0.2.200")) == (
        "synthetichost/generic/us-test-1"
    )


def test_lookup_all_returns_multiple_most_specific_matches(tmp_path: Path) -> None:
    path = tmp_path / "providers.csv"
    path.write_text(
        "\n".join(
            [
                "cidr,provider,service",
                "192.0.2.0/24,synthetichost,compute",
                "192.0.2.0/24,otherhost,egress",
            ]
        ),
        encoding="utf-8",
    )

    lookup = ProviderRangeLookup.from_path(path)

    assert [match.provider for match in lookup.lookup_all("192.0.2.44")] == [
        "otherhost",
        "synthetichost",
    ]


def test_unified_json_adapter_supports_nested_records(tmp_path: Path) -> None:
    path = tmp_path / "providers.json"
    path.write_text(
        json.dumps(
            {
                "records": [
                    {
                        "ipv4_prefix": "198.51.100.0/24",
                        "provider": "synthetichost",
                        "service": "compute",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    records = load_provider_records(path, source_format="unified-json")
    lookup = ProviderRangeLookup(records)

    assert provider_label(lookup.lookup("198.51.100.9")) == "synthetichost/compute"


def test_per_provider_csv_can_infer_provider_from_filename(tmp_path: Path) -> None:
    path = tmp_path / "synthetichost_ips.csv"
    path.write_text(
        "ip_address,service,region\n203.0.113.0/24,compute,us-test\n",
        encoding="utf-8",
    )

    lookup = ProviderRangeLookup.from_path(path, source_format="unified-csv")

    assert provider_label(lookup.lookup("203.0.113.9")) == (
        "synthetichost/compute/us-test"
    )


def test_cloud_provider_repo_adapter_prefers_unified_metadata(
    tmp_path: Path,
) -> None:
    root = tmp_path / "cloud-provider-ip-addresses"
    (root / "all_providers").mkdir(parents=True)
    (root / "all_providers" / "all_providers.csv").write_text(
        "\n".join(
            [
                "cidr,ip_version,provider,service,region,last_updated",
                "203.0.113.0/24,IPv4,synthetichost,compute,us-test,2026-01-01",
            ]
        ),
        encoding="utf-8",
    )
    provider_dir = root / "synthetichost"
    provider_dir.mkdir()
    (provider_dir / "synthetichost_ips_merged_v4.txt").write_text(
        "203.0.113.0/24\n", encoding="utf-8"
    )

    lookup = ProviderRangeLookup.from_path(
        root, source_format="cloud-provider-ip-addresses"
    )

    assert provider_label(lookup.lookup("203.0.113.44")) == (
        "synthetichost/compute/us-test"
    )


def test_provider_include_and_exclude_filter_records(tmp_path: Path) -> None:
    path = tmp_path / "providers.csv"
    path.write_text(
        "\n".join(
            [
                "cidr,provider",
                "192.0.2.0/24,synthetichost",
                "198.51.100.0/24,otherhost",
            ]
        ),
        encoding="utf-8",
    )

    lookup = ProviderRangeLookup.from_path(path, provider_include=("synthetichost",))
    excluded = ProviderRangeLookup.from_path(path, provider_exclude=("synthetichost",))

    assert lookup.lookup("192.0.2.8") is not None
    assert lookup.lookup("198.51.100.8") is None
    assert excluded.lookup("192.0.2.8") is None
    assert excluded.lookup("198.51.100.8") is not None


def test_provider_source_registry_lists_builtin_adapters() -> None:
    assert {
        "cloud-provider-ip-addresses",
        "plain-cidr-text",
        "unified-csv",
        "unified-json",
    } <= set(provider_source_names())


def test_provider_source_registry_accepts_custom_adapter(tmp_path: Path) -> None:
    class CustomSource:
        name = "custom-test-source"

        def can_load(self, path: Path) -> bool:
            return path.suffix == ".custom"

        def load(self, path: Path):
            return [ProviderRangeRecord("192.0.2.0/24", "customhost")]

    register_provider_source(CustomSource(), prepend=True)
    path = tmp_path / "ranges.custom"
    path.write_text("ignored by custom adapter\n", encoding="utf-8")

    lookup = ProviderRangeLookup.from_path(path)

    assert provider_label(lookup.lookup("192.0.2.44")) == "customhost"


def test_provider_watch_adds_opt_in_activity_proof(tmp_path: Path) -> None:
    path = tmp_path / "providers.csv"
    path.write_text("cidr,provider\n192.0.2.0/24,synthetichost\n", encoding="utf-8")
    args = audit_args(
        provider_ranges=[str(path)],
        provider_watch=["synthetichost"],
        provider_request_count=20,
        provider_unique_paths=12,
        provider_min_score=0.0,
    )
    runtime = build_runtime(args)
    ip = doc_ip(44)
    rows = rows_for_paths([f"/synthetic/provider-{i:02d}" for i in range(20)], ip=ip)
    stats = build_ip_stats(rows, args, runtime)[ip]

    proofs = provider_activity_proofs(stats, args, runtime)

    assert [proof.kind for proof in proofs] == ["provider-hosted-activity"]
    assert "provider=synthetichost" in proofs[0].detail


def test_exclude_provider_traffic_forces_loaded_provider_matches(
    tmp_path: Path,
) -> None:
    path = tmp_path / "providers.csv"
    path.write_text("cidr,provider\n192.0.2.0/24,synthetichost\n", encoding="utf-8")
    args = audit_args(
        provider_ranges=[str(path)],
        exclude_provider_traffic=True,
    )
    runtime = build_runtime(args)
    provider_ip = doc_ip(44)
    clean_ip = doc_ip(44, net=2)
    rows = [
        row(0, ip=provider_ip, path="/synthetic/provider-hosted"),
        row(1, ip=clean_ip, path="/synthetic/non-provider"),
    ]
    stats = build_ip_stats(rows, args, runtime)

    forced = detect_provider_exclusions(stats, args, runtime)

    assert [proof.kind for proof in forced[provider_ip]] == ["provider-hosted-activity"]
    assert "mode=exclude-provider-traffic" in forced[provider_ip][0].detail
    assert clean_ip not in forced
    assert provider_activity_proofs(stats[provider_ip], args, runtime) == []


def test_live_provider_output_is_enrichment_and_opt_in_suspect(
    tmp_path: Path,
) -> None:
    path = tmp_path / "providers.csv"
    path.write_text("cidr,provider\n192.0.2.0/24,synthetichost\n", encoding="utf-8")
    args = watch_args(
        provider_ranges=[str(path)],
        provider_watch=["synthetichost"],
        provider_request_count=2,
        provider_unique_paths=2,
        provider_min_score=0.0,
        emit_suspects=True,
    )
    context = LiveContext(runtime=build_runtime(args))
    ip = doc_ip(44)

    assert (
        process_row(row(0, ip=ip, path="/synthetic/provider-a"), context, args) is None
    )
    decision = process_row(row(1, ip=ip, path="/synthetic/provider-b"), context, args)

    assert decision is not None
    assert decision.action == "suspect"
    assert decision.provider == "synthetichost"
    assert json.loads(format_json(decision))["provider"] == "synthetichost"


def test_live_exclude_provider_traffic_emits_provider_match_when_suspects_enabled(
    tmp_path: Path,
) -> None:
    path = tmp_path / "providers.csv"
    path.write_text("cidr,provider\n192.0.2.0/24,synthetichost\n", encoding="utf-8")
    args = watch_args(
        provider_ranges=[str(path)],
        exclude_provider_traffic=True,
        emit_suspects=True,
    )
    context = LiveContext(runtime=build_runtime(args))

    decision = process_row(
        row(0, ip=doc_ip(44), path="/synthetic/provider-hosted"),
        context,
        args,
    )

    assert decision is not None
    assert decision.action == "suspect"
    assert decision.reasons == ("provider-hosted-activity",)
    assert decision.provider == "synthetichost"
