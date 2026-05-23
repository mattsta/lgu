from __future__ import annotations

import json
from pathlib import Path

from scenario_dsl import ScenarioCase, build_rows
from scenario_sanitize import (
    REFERRER_OTHER,
    REFERRER_PRIMARY,
    main,
    sanitize_log_snippet,
)
from synthetic_access import (
    CHROME_120_UA,
    FIREFOX_122_UA,
    SAFARI_17_UA,
    access_line,
)


def test_sanitize_log_snippet_emits_dsl_compatible_scenario() -> None:
    snippet = "".join(
        [
            access_line(
                ip="198.51.100.20",
                ts="08/Apr/2026:02:30:52 +0000",
                path="/private/feed?id=1",
                referer="https://news.example.com/article",
                ua=CHROME_120_UA,
            ),
            access_line(
                ip="198.51.100.20",
                ts="08/Apr/2026:02:30:57 +0000",
                path="/private/feed?id=1",
                referer="https://news.example.com/article",
                ua=CHROME_120_UA,
            ),
            access_line(
                ip="203.0.113.44",
                ts="08/Apr/2026:02:31:00 +0000",
                path="/members/hidden",
                referer="https://social.example.com/",
                ua=FIREFOX_122_UA,
                method="POST",
                status="404",
            ),
        ]
    )

    scenario = sanitize_log_snippet(snippet, name="draft_case")

    assert scenario["name"] == "draft_case"
    assert scenario["actors"] == {
        "source_01": {
            "ip": "doc:2:20",
            "ua": "chrome_120",
            "referer": REFERRER_PRIMARY,
            "method": "GET",
            "status": "200",
        },
        "source_02": {
            "ip": "doc:3:44",
            "ua": "firefox_122",
            "referer": REFERRER_OTHER,
            "method": "POST",
            "status": "404",
        },
    }

    events = scenario["events"]
    assert [event["at"] for event in events] == [0, 5, 8]
    assert events[0]["path"] == events[1]["path"]
    assert all(event["path"].startswith("/synthetic/") for event in events)

    case = ScenarioCase(path=Path("draft_case.json"), data=scenario)
    rows, actor_ips = build_rows(case)
    assert actor_ips == {
        "source_01": "198.51.100.20",
        "source_02": "203.0.113.44",
    }
    assert [row.ts for row in rows] == [0, 5, 8]
    assert [row.referer for row in rows] == [
        REFERRER_PRIMARY,
        REFERRER_PRIMARY,
        REFERRER_OTHER,
    ]


def test_sanitize_paths_preserve_base_query_and_asset_cardinality() -> None:
    snippet = "".join(
        [
            access_line(
                ip="192.0.2.10",
                ts="08/Apr/2026:02:30:52 +0000",
                path="/catalog/private?id=1",
                referer="-",
                ua=SAFARI_17_UA,
            ),
            access_line(
                ip="192.0.2.10",
                ts="08/Apr/2026:02:30:53 +0000",
                path="/catalog/private?id=2",
                referer="-",
                ua=SAFARI_17_UA,
            ),
            access_line(
                ip="192.0.2.10",
                ts="08/Apr/2026:02:30:54 +0000",
                path="/catalog/private?id=1",
                referer="-",
                ua=SAFARI_17_UA,
            ),
            access_line(
                ip="192.0.2.10",
                ts="08/Apr/2026:02:30:55 +0000",
                path="/assets/app.js",
                referer="-",
                ua=SAFARI_17_UA,
            ),
        ]
    )

    scenario = sanitize_log_snippet(snippet)
    paths = [event["path"] for event in scenario["events"]]

    assert paths[0] == paths[2]
    assert paths[0] != paths[1]
    assert paths[0].split("?", 1)[0] == paths[1].split("?", 1)[0]
    assert paths[3].endswith(".js")
    assert len(set(paths)) == 3
    assert scenario["actors"]["source_01"]["ua"] == "safari_17"


def test_main_writes_standalone_json(tmp_path: Path, capsys) -> None:
    log_path = tmp_path / "snippet.log"
    log_path.write_text(
        access_line(
            ip="192.0.2.88",
            ts="08/Apr/2026:02:30:52 +0000",
            path="/visible/content",
            referer="https://search.example.com/",
            ua=CHROME_120_UA,
        ),
        encoding="utf-8",
    )

    assert main([str(log_path), "--name", "cli_case"]) == 0

    output = json.loads(capsys.readouterr().out)
    assert output["name"] == "cli_case"
    assert output["actors"]["source_01"]["ip"] == "doc:1:88"
    assert output["events"][0]["at"] == 0
