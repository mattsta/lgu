from __future__ import annotations

from collections import Counter

from synthetic_access import (
    CHROME_120_UA,
    CHROME_133_UA,
    FIREFOX_122_UA,
    FIREFOX_150_UA,
    REFERRER,
    doc_ip,
    row,
    watch_args,
)

from lgu.audit import build_runtime
from lgu.watch import LiveContext, gc_ip_states, process_row

DEFAULT_IP = doc_ip(1)
CADENCED_IP = doc_ip(44, net=2)
MULTIFETCH_IP = doc_ip(51, net=3)
CADENCED_PATH = "/synthetic/cadenced-content-target"
MULTIFETCH_PATH_A = "/synthetic/multifetch-content-alpha"
MULTIFETCH_PATH_B = "/synthetic/multifetch-content-beta"


def make_context(args) -> LiveContext:
    return LiveContext(runtime=build_runtime(args))


def test_suspect_suppressed_until_ban_escalation() -> None:
    args = watch_args(
        emit_suspects=False,
        suspect_score=1.0,
        ban_score=50.0,
        streak_count=1,
        streak_unique_total=2,
        ua_switch_count=2,
        ua_switch_distinct_uas=2,
        ua_switch_distinct_families=2,
    )
    context = make_context(args)

    assert (
        process_row(
            row(ts=0.0, path="/synthetic/a", ua=CHROME_120_UA),
            context,
            args,
        )
        is None
    )
    assert (
        process_row(
            row(ts=0.5, path="/synthetic/b", ua=CHROME_120_UA),
            context,
            args,
        )
        is None
    )
    assert context.ip_states[DEFAULT_IP].last_action == "suspect"

    decision = process_row(
        row(ts=1.0, path="/synthetic/c", ua=FIREFOX_122_UA), context, args
    )
    assert decision is not None
    assert decision.action == "ban"
    assert "rapid-ua-switch" in decision.reasons


def test_live_ip_state_eviction_after_inactivity() -> None:
    args = watch_args(
        live_ip_memory_seconds=10.0,
        cooldown_seconds=5.0,
        emit_suspects=True,
        suspect_score=1.0,
        ban_score=50.0,
        streak_count=1,
        streak_unique_total=2,
    )
    context = make_context(args)
    process_row(row(ts=0.0, path="/synthetic/a"), context, args)
    process_row(row(ts=0.5, path="/synthetic/b"), context, args)
    assert DEFAULT_IP in context.ip_states

    gc_ip_states(context, 20.0, args)
    assert DEFAULT_IP not in context.ip_states


def test_suppressed_suspects_do_not_count_as_emitted() -> None:
    args = watch_args(
        emit_suspects=False,
        suspect_score=1.0,
        ban_score=50.0,
        streak_count=1,
        streak_unique_total=2,
    )
    context = make_context(args)
    process_row(row(ts=0.0, path="/synthetic/a"), context, args)
    process_row(row(ts=0.5, path="/synthetic/b"), context, args)
    assert context.emitted_counts == Counter()


def test_live_cadenced_repeat_forces_ban() -> None:
    args = watch_args(cadence_hour_repeat_count=99)
    context = make_context(args)

    assert (
        process_row(
            row(
                ts=0.0,
                ip=CADENCED_IP,
                path=CADENCED_PATH,
                ua=CHROME_133_UA,
            ),
            context,
            args,
        )
        is None
    )
    assert (
        process_row(
            row(
                ts=3660.0,
                ip=CADENCED_IP,
                path=CADENCED_PATH,
                ua=CHROME_133_UA,
            ),
            context,
            args,
        )
        is None
    )
    decision = process_row(
        row(
            ts=7320.0,
            ip=CADENCED_IP,
            path=CADENCED_PATH,
            ua=CHROME_133_UA,
        ),
        context,
        args,
    )

    assert decision is not None
    assert decision.action == "ban"
    assert "cadenced-repeat" in decision.reasons


def test_live_near_hour_two_hit_cadenced_repeat_forces_ban() -> None:
    args = watch_args()
    context = make_context(args)

    assert (
        process_row(
            row(
                ts=0.0,
                ip=CADENCED_IP,
                path=CADENCED_PATH,
                ua=CHROME_133_UA,
            ),
            context,
            args,
        )
        is None
    )
    decision = process_row(
        row(
            ts=3661.0,
            ip=CADENCED_IP,
            path=CADENCED_PATH,
            ua=CHROME_133_UA,
        ),
        context,
        args,
    )

    assert decision is not None
    assert decision.action == "ban"
    assert "cadenced-repeat" in decision.reasons
    assert "near-hour" in decision.proof_detail


def test_live_tight_multifetch_forces_ban() -> None:
    args = watch_args()
    context = make_context(args)
    shared = {
        "ip": MULTIFETCH_IP,
        "ua": FIREFOX_150_UA,
        "referer": REFERRER,
    }

    assert (
        process_row(
            row(
                ts=0.0,
                path=MULTIFETCH_PATH_A,
                **shared,
            ),
            context,
            args,
        )
        is None
    )
    assert (
        process_row(
            row(
                ts=0.0,
                path=MULTIFETCH_PATH_B,
                **shared,
            ),
            context,
            args,
        )
        is None
    )
    assert (
        process_row(
            row(
                ts=25.0,
                path=MULTIFETCH_PATH_A,
                **shared,
            ),
            context,
            args,
        )
        is None
    )
    decision = process_row(
        row(
            ts=28.0,
            path=MULTIFETCH_PATH_B,
            **shared,
        ),
        context,
        args,
    )

    assert decision is not None
    assert decision.action == "ban"
    assert "tight-multifetch" in decision.reasons
