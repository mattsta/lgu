from __future__ import annotations

import pytest
from synthetic_access import FIREFOX_150_UA, REFERRER, audit_args, doc_ip, row

from lgu.audit import analyze_ip_behaviors, build_runtime, is_self_referer

SITE = "https://site.example.test"


@pytest.mark.parametrize(
    ("path", "referer", "expected"),
    [
        ("/synthetic/post", f"{SITE}/synthetic/post", True),
        ("/synthetic/post?page=2", f"{SITE}/synthetic/post?page=2", True),
        ("/style?v=abc123", f"{SITE}/style?v=abc123", True),
        # Any host counts: the log does not record which vhost served the row.
        ("/synthetic/post", "https://other.example.test/synthetic/post", True),
        # Root is excluded: home-logo clicks and reloads produce / -> /.
        ("/", f"{SITE}/", False),
        ("/", SITE, False),
        # Pagination and other query changes are normal navigation.
        ("/synthetic/post?page=2", f"{SITE}/synthetic/post?page=1", False),
        ("/synthetic/post", f"{SITE}/synthetic/post?ref=feed", False),
        # Trailing-slash redirects are a different target.
        ("/synthetic/post/", f"{SITE}/synthetic/post", False),
        ("/synthetic/post", f"{SITE}/synthetic/other", False),
        ("/synthetic/post", "-", False),
        # Only absolute URLs are real Referer values.
        ("/synthetic/post", "/synthetic/post", False),
        ("/synthetic/post", "http://[broken/synthetic/post", False),
    ],
)
def test_is_self_referer_matches_exact_non_root_targets(
    path: str, referer: str, expected: bool
) -> None:
    assert is_self_referer(path, referer) is expected


def self_referer_proofs(rows: list) -> list[str]:
    args = audit_args()
    _, proofs = analyze_ip_behaviors(rows[0].ip, rows, args, build_runtime(args))
    return [proof.detail for proof in proofs if proof.kind == "self-referer"]


def self_rows(ip: str, count: int, method: str = "GET", start: float = 0.0) -> list:
    return [
        row(
            start + index * 40.0,
            ip=ip,
            path=f"/synthetic/self-{index}",
            referer=f"{SITE}/synthetic/self-{index}",
            ua=FIREFOX_150_UA,
            method=method,
        )
        for index in range(count)
    ]


def test_proof_detail_reports_targets_ratio_and_samples() -> None:
    details = self_referer_proofs(self_rows(doc_ip(30), 4))

    assert details == [
        "targets=4 self-ref=4/4 (100%) samples=/synthetic/self-0, "
        "/synthetic/self-1, /synthetic/self-2"
    ]


def test_form_posts_back_to_the_same_page_do_not_count() -> None:
    assert self_referer_proofs(self_rows(doc_ip(31), 4, method="POST")) == []


def test_direct_requests_do_not_dilute_the_ratio() -> None:
    ip = doc_ip(32)
    direct = [
        row(1000.0 + index, ip=ip, path=f"/synthetic/direct-{index}", referer="-")
        for index in range(10)
    ]

    assert self_referer_proofs(self_rows(ip, 3) + direct) != []


def test_referred_human_reads_dilute_the_ratio_below_threshold() -> None:
    ip = doc_ip(33)
    reads = [
        row(
            1000.0 + index * 40,
            ip=ip,
            path=f"/synthetic/read-{index}",
            referer=REFERRER,
        )
        for index in range(4)
    ]

    assert self_referer_proofs(self_rows(ip, 3) + reads) == []
