from __future__ import annotations

import json
from dataclasses import fields
from pathlib import Path

from synthetic_access import access_line, doc_ip, row

from lgu.audit import (
    STRONG_PROOF_KINDS,
    DetectorConfig,
    build_ip_stats,
    build_parser,
    build_runtime,
    collect_rows_and_stats,
    resolve_detector_config,
    summarize_ua_base,
)
from lgu.detector_catalog import DETECTORS, PROOF_KINDS
from lgu.watch import build_parser as build_watch_parser

VALID_SCOPES = {"per-ip", "cross-ip", "provider"}
VALID_OUTCOMES = {"heuristic", "proof", "optional-proof"}


def test_detector_catalog_kinds_are_unique() -> None:
    kinds = [spec.kind for spec in DETECTORS]

    assert len(kinds) == len(set(kinds))


def test_catalog_strong_proofs_drive_audit_ban_policy() -> None:
    catalog_strong = {spec.kind for spec in DETECTORS if spec.strong_proof}

    assert catalog_strong == STRONG_PROOF_KINDS
    assert catalog_strong < PROOF_KINDS
    assert all(spec.outcome == "proof" for spec in DETECTORS if spec.strong_proof)


def test_catalog_metadata_uses_known_operational_values() -> None:
    assert {spec.scope for spec in DETECTORS} <= VALID_SCOPES
    assert {spec.outcome for spec in DETECTORS} <= VALID_OUTCOMES
    assert all(isinstance(spec.live_coverage_required, bool) for spec in DETECTORS)


def test_catalog_threshold_args_are_declared_on_parser_or_config() -> None:
    args = build_parser().parse_args([])
    config_args = {
        "known_bot_any_patterns",
        "known_bot_ua_patterns",
        "known_bot_referer_patterns",
    }
    missing = {
        threshold
        for spec in DETECTORS
        for threshold in spec.threshold_args
        if not hasattr(args, threshold) and threshold not in config_args
    }

    assert missing == set()


def test_raw_filtered_lines_has_clear_flag() -> None:
    parser = build_parser()

    assert parser.parse_args(["--raw-filtered-lines"]).raw_filtered_output is True


def test_catalog_threshold_args_are_available_to_live_parser_or_config() -> None:
    args = build_watch_parser().parse_args([])
    config_args = {
        "known_bot_any_patterns",
        "known_bot_ua_patterns",
        "known_bot_referer_patterns",
    }
    missing = {
        threshold
        for spec in DETECTORS
        for threshold in spec.threshold_args
        if not hasattr(args, threshold) and threshold not in config_args
    }

    assert missing == set()


def test_detector_config_fields_are_cataloged_as_config_dependencies() -> None:
    cataloged = {
        config_arg
        for spec in DETECTORS
        for config_arg in (*spec.threshold_args, *spec.config_args)
    }
    config_fields = {field.name for field in fields(DetectorConfig)}

    assert config_fields <= cataloged


def test_packaged_default_detector_config_matches_repo_default() -> None:
    repo_default = Path("defaults/detector-config.json")
    package_default = Path("src/lgu/defaults/detector-config.json")

    assert json.loads(package_default.read_text(encoding="utf-8")) == json.loads(
        repo_default.read_text(encoding="utf-8")
    )


def test_default_detector_config_catches_social_preview_fetcher() -> None:
    args = build_parser().parse_args([])
    args.detector_config = resolve_detector_config(args)
    runtime = build_runtime(args)
    ip = doc_ip(82)

    stats = build_ip_stats(
        [
            row(
                0,
                ip=ip,
                ua="facebookexternalhit/1.1 SyntheticLinkPreview",
            )
        ],
        args,
        runtime,
    )[ip]

    assert stats.matched_known_bot is True
    assert stats.is_bot(args) is True


def test_default_detector_config_catches_spoofed_safari_13_iphone_13() -> None:
    args = build_parser().parse_args([])
    args.detector_config = resolve_detector_config(args)
    runtime = build_runtime(args)
    ip = doc_ip(84)

    stats = build_ip_stats(
        [
            row(
                0,
                ip=ip,
                ua=(
                    "Mozilla/5.0 (iPhone; CPU iPhone OS 13_7 like Mac OS X) "
                    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0 "
                    "Mobile/17A577 Safari/604.1"
                ),
            )
        ],
        args,
        runtime,
    )[ip]

    assert stats.matched_known_bot is True
    assert stats.is_bot(args) is True


def test_synthetic_log_safari_13_iphone_13_entry_is_known_bot(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "access.log"
    ip = doc_ip(85)
    ua = (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 13_5_1 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1 "
        "Mobile/17A577 Safari/604.1"
    )
    log_path.write_text(
        access_line(
            ip=ip,
            ts="08/Apr/2026:02:30:52 +0000",
            path="/synthetic/spoofed-safari13",
            ua=ua,
        ),
        encoding="utf-8",
    )
    args = build_parser().parse_args([])
    args.jobs = 1
    args.detector_config = resolve_detector_config(args)
    runtime = build_runtime(args)

    analysis = collect_rows_and_stats(log_path, args, runtime)
    stats = analysis.ip_stats[ip]

    assert summarize_ua_base(analysis.rows[0].ua) == "Safari 13 / iPhone 13 / mobile"
    assert stats.matched_known_bot is True
    assert stats.is_bot(args) is True


def test_no_default_detector_config_disables_social_preview_default() -> None:
    args = build_parser().parse_args(["--no-default-detector-config"])
    args.detector_config = resolve_detector_config(args)
    runtime = build_runtime(args)
    ip = doc_ip(83)

    stats = build_ip_stats(
        [
            row(
                0,
                ip=ip,
                ua="facebookexternalhit/1.1 SyntheticLinkPreview",
            )
        ],
        args,
        runtime,
    )[ip]

    assert stats.matched_known_bot is False
    assert stats.is_bot(args) is False
