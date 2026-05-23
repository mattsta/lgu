from __future__ import annotations

import json

from decision_diff import diff_decisions, load_bans, main
from synthetic_access import doc_ip


def ban_line(ip: str, reasons: str = "burst", path: str = "/synthetic/a") -> str:
    return f"2026-11-05T10:00:00Z action=ban ip={ip} score=1.0 reasons={reasons} path={path}\n"


def test_load_bans_ignores_suspects_and_keeps_first_ban(tmp_path) -> None:
    log = tmp_path / "bans.txt"
    log.write_text(
        ban_line(doc_ip(1), reasons="first")
        + ban_line(doc_ip(1), reasons="second")
        + f"2026-11-05T10:00:00Z action=suspect ip={doc_ip(2)} score=1.0 reasons=x path=/\n",
        encoding="utf-8",
    )

    bans = load_bans(log)

    assert set(bans) == {doc_ip(1)}
    assert bans[doc_ip(1)].reasons == "first"


def test_diff_reports_addresses_unique_to_each_side(tmp_path) -> None:
    old = tmp_path / "old.txt"
    new = tmp_path / "new.txt"
    old.write_text(ban_line(doc_ip(1)) + ban_line(doc_ip(2)), encoding="utf-8")
    new.write_text(ban_line(doc_ip(2)) + ban_line(doc_ip(3)), encoding="utf-8")

    diff = diff_decisions(load_bans(old), load_bans(new))

    assert [record.ip for record in diff.only_old] == [doc_ip(1)]
    assert [record.ip for record in diff.only_new] == [doc_ip(3)]


def test_cli_emits_json(tmp_path, capsys) -> None:
    old = tmp_path / "old.txt"
    new = tmp_path / "new.txt"
    old.write_text(ban_line(doc_ip(1)), encoding="utf-8")
    new.write_text("", encoding="utf-8")

    assert main([str(old), str(new), "--format", "json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["old_banned_ips"] == 1
    assert payload["new_banned_ips"] == 0
    assert payload["only_old"][0]["ip"] == doc_ip(1)
