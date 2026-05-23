"""Compare two `log-watch --output-format fail2ban` runs by banned address.

Use it to answer "whose ban did this change add or remove?" on a sanitized or
private log, by replaying the same input through two versions of LGU.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

BAN_LINE_RE = re.compile(
    r"^\S+ action=ban ip=(?P<ip>\S+) score=\S+ reasons=(?P<reasons>\S+) path=(?P<path>\S*)"
)


@dataclass(frozen=True)
class BanRecord:
    ip: str
    reasons: str
    path: str


@dataclass(frozen=True)
class DecisionDiff:
    old_bans: int
    new_bans: int
    only_old: tuple[BanRecord, ...]
    only_new: tuple[BanRecord, ...]


def load_bans(path: Path) -> dict[str, BanRecord]:
    """Map each banned address to its first ban line."""
    bans: dict[str, BanRecord] = {}
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if match := BAN_LINE_RE.match(line):
                ip = match["ip"]
                bans.setdefault(
                    ip, BanRecord(ip=ip, reasons=match["reasons"], path=match["path"])
                )
    return bans


def diff_decisions(
    old: dict[str, BanRecord], new: dict[str, BanRecord]
) -> DecisionDiff:
    return DecisionDiff(
        old_bans=len(old),
        new_bans=len(new),
        only_old=tuple(old[ip] for ip in sorted(old.keys() - new.keys())),
        only_new=tuple(new[ip] for ip in sorted(new.keys() - old.keys())),
    )


def format_text(diff: DecisionDiff, sample: int) -> str:
    lines = [
        f"old_banned_ips={diff.old_bans}",
        f"new_banned_ips={diff.new_bans}",
        f"only_old={len(diff.only_old)}",
        f"only_new={len(diff.only_new)}",
    ]
    for label, records in (("only_old", diff.only_old), ("only_new", diff.only_new)):
        for record in records[:sample]:
            lines.append(f"{label}\t{record.ip}\t{record.reasons}\t{record.path}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("old", type=Path, help="fail2ban output from the old version.")
    parser.add_argument("new", type=Path, help="fail2ban output from the new version.")
    parser.add_argument(
        "--sample", type=int, default=20, help="Records to list per side."
    )
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)

    diff = diff_decisions(load_bans(args.old), load_bans(args.new))
    if args.format == "json":
        print(
            json.dumps(
                {
                    "old_banned_ips": diff.old_bans,
                    "new_banned_ips": diff.new_bans,
                    "only_old": [vars(record) for record in diff.only_old],
                    "only_new": [vars(record) for record in diff.only_new],
                }
            )
        )
    else:
        print(format_text(diff, args.sample))
    return 0


if __name__ == "__main__":
    sys.exit(main())
