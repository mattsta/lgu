from __future__ import annotations

import argparse
import json
from pathlib import Path

from scenario_dsl import (
    ScenarioCase,
    build_rows,
    load_scenario_cases,
    run_batch,
    run_live,
    scenario_diagnostics,
)


def summarize_case(case: ScenarioCase) -> dict[str, object]:
    _, actor_ips = build_rows(case)
    actor_by_ip = {ip: actor for actor, ip in actor_ips.items()}
    batch = run_batch(case)
    live = run_live(case)
    return {
        "id": case.id,
        "batch": {
            "bot_actors": sorted(
                actor_by_ip[ip] for ip in batch.bot_ips if ip in actor_by_ip
            ),
            "proofs": {
                actor_by_ip[ip]: [proof.kind for proof in proofs]
                for ip, proofs in sorted(batch.proofs_by_ip.items())
                if ip in actor_by_ip
            },
        },
        "live": {
            "emissions": [
                {
                    "actor": emission.actor,
                    "action": emission.decision.action,
                    "reasons": list(emission.decision.reasons),
                    "path": emission.decision.path,
                }
                for emission in live.emissions
            ]
        },
        "diagnostics": scenario_diagnostics(case),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Print actual detector outcomes for synthetic scenario files."
    )
    parser.add_argument("path", type=Path, help="Scenario JSON file or directory.")
    args = parser.parse_args()

    path = args.path
    cases = load_scenario_cases(path if path.is_dir() else path.parent)
    if path.is_file():
        cases = [case for case in cases if case.path == path]
    print(json.dumps([summarize_case(case) for case in cases], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
