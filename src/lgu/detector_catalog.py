from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DetectorSpec:
    kind: str
    scope: str
    outcome: str
    threshold_args: tuple[str, ...]
    live_coverage_required: bool = True
    config_args: tuple[str, ...] = ()
    strong_proof: bool = False


DETECTORS: tuple[DetectorSpec, ...] = (
    DetectorSpec(
        kind="known-ua-or-referer",
        scope="per-ip",
        outcome="heuristic",
        threshold_args=("known_bot_any_patterns", "known_bot_ua_patterns"),
        config_args=(
            "known_bot_any_patterns",
            "known_bot_ua_patterns",
            "known_bot_referer_patterns",
        ),
    ),
    DetectorSpec(
        kind="burst",
        scope="per-ip",
        outcome="heuristic",
        threshold_args=("window_seconds", "burst_count", "unique_paths"),
    ),
    DetectorSpec(
        kind="head-burst",
        scope="per-ip",
        outcome="heuristic",
        threshold_args=("head_burst", "head_unique_paths"),
    ),
    DetectorSpec(
        kind="paced-sweep",
        scope="per-ip",
        outcome="heuristic",
        threshold_args=(
            "sweep_window_seconds",
            "sweep_count",
            "sweep_unique_paths",
            "sweep_dominant_referer_ratio",
        ),
    ),
    DetectorSpec(
        kind="fast-streak",
        scope="per-ip",
        outcome="heuristic",
        threshold_args=("streak_gap", "streak_count", "streak_unique_total"),
    ),
    DetectorSpec(
        kind="repeated-pair",
        scope="per-ip",
        outcome="proof",
        threshold_args=("pair_gap_seconds", "pair_repeat_count"),
        strong_proof=True,
    ),
    DetectorSpec(
        kind="tight-multifetch",
        scope="per-ip",
        outcome="proof",
        threshold_args=(
            "multi_fetch_window_seconds",
            "multi_fetch_count",
            "multi_fetch_unique_paths",
            "multi_fetch_repeat_paths",
            "multi_fetch_same_second_unique_paths",
            "multi_fetch_dominant_referer_ratio",
        ),
        strong_proof=True,
    ),
    DetectorSpec(
        kind="asset-primed-probe",
        scope="per-ip",
        outcome="proof",
        threshold_args=(
            "exposure_probe_window_seconds",
            "exposure_probe_asset_count",
            "exposure_probe_count",
        ),
        strong_proof=True,
    ),
    DetectorSpec(
        kind="redundant-revisit",
        scope="per-ip",
        outcome="proof",
        threshold_args=(
            "revisit_paths",
            "revisit_repeat_requests",
            "revisit_dominant_referer_ratio",
        ),
        strong_proof=True,
    ),
    DetectorSpec(
        kind="cadenced-repeat",
        scope="per-ip",
        outcome="proof",
        threshold_args=(
            "cadence_repeat_count",
            "cadence_min_gap_seconds",
            "cadence_gap_tolerance_seconds",
            "cadence_dominant_referer_ratio",
            "cadence_hour_repeat_count",
            "cadence_hour_gap_seconds",
            "cadence_hour_gap_tolerance_seconds",
        ),
        strong_proof=True,
    ),
    DetectorSpec(
        kind="rotating-ua",
        scope="per-ip",
        outcome="proof",
        threshold_args=("rotate_ua_count", "rotate_ua_family_count"),
    ),
    DetectorSpec(
        kind="periodic-poller",
        scope="per-ip",
        outcome="proof",
        threshold_args=("poll_repeat_count", "poll_min_gap_seconds"),
        strong_proof=True,
    ),
    DetectorSpec(
        kind="serial-sweep",
        scope="per-ip",
        outcome="proof",
        threshold_args=(
            "serial_min_gap_seconds",
            "serial_max_gap_seconds",
            "serial_count",
            "serial_unique_paths",
        ),
        strong_proof=True,
    ),
    DetectorSpec(
        kind="payload-fuzzer",
        scope="per-ip",
        outcome="proof",
        threshold_args=(
            "payload_pair_gap_seconds",
            "payload_show_analysis_count",
            "payload_injection_count",
            "payload_referer_junk_count",
            "payload_mutation_count",
        ),
        config_args=("payload_marker_patterns",),
        strong_proof=True,
    ),
    DetectorSpec(
        kind="same-second-ua-swap",
        scope="per-ip",
        outcome="proof",
        threshold_args=("same_second_ua_swap_count",),
        config_args=("payload_marker_patterns",),
        strong_proof=True,
    ),
    DetectorSpec(
        kind="rapid-ua-switch",
        scope="per-ip",
        outcome="proof",
        threshold_args=(
            "ua_switch_window_seconds",
            "ua_switch_count",
            "ua_switch_distinct_uas",
            "ua_switch_distinct_families",
        ),
        strong_proof=True,
    ),
    DetectorSpec(
        kind="coordinated-ua",
        scope="cross-ip",
        outcome="proof",
        threshold_args=(
            "coord_window_seconds",
            "coord_count",
            "coord_unique_paths",
            "coord_unique_ips",
            "coord_max_ip_share",
        ),
        strong_proof=True,
    ),
    DetectorSpec(
        kind="coordinated-target-fanout",
        scope="cross-ip",
        outcome="proof",
        threshold_args=(
            "target_fanout_window_seconds",
            "target_fanout_count",
            "target_fanout_unique_ips",
            "target_fanout_max_ip_share",
            "target_fanout_dominant_referer_ratio",
            "target_fanout_same_ua_window_seconds",
            "target_fanout_same_ua_count",
            "target_fanout_same_ua_unique_ips",
        ),
        strong_proof=True,
    ),
    DetectorSpec(
        kind="payload-campaign",
        scope="cross-ip",
        outcome="proof",
        threshold_args=(
            "payload_campaign_window_seconds",
            "payload_campaign_count",
            "payload_campaign_unique_ips",
            "payload_campaign_unique_paths",
        ),
        config_args=("payload_marker_patterns",),
        strong_proof=True,
    ),
    DetectorSpec(
        kind="provider-hosted-activity",
        scope="provider",
        outcome="optional-proof",
        threshold_args=(
            "provider_ranges",
            "provider_watch",
            "provider_request_count",
            "provider_unique_paths",
            "provider_min_score",
        ),
        config_args=("provider_ranges", "provider_watch"),
    ),
)

DETECTOR_KINDS = frozenset(spec.kind for spec in DETECTORS)
PROOF_KINDS = frozenset(spec.kind for spec in DETECTORS if spec.outcome == "proof")
STRONG_PROOF_KINDS = frozenset(spec.kind for spec in DETECTORS if spec.strong_proof)
