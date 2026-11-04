"""Scenario runner CLI. Runs inside the lab (the `runner` service).

    docker compose exec runner python -m scenarios list
    docker compose exec runner python -m scenarios run credential_stuffing
    docker compose exec runner python -m scenarios run-all
    docker compose exec runner python -m scenarios check     # self-test, see below

`check` runs every scenario twice: with every defence off (monitoring on), then
with every defence on. It asserts that each attack works in the first pass
and is blocked in the second, and that the expected alerts fire. It restores
your defence switches afterwards.
"""
import argparse
import json
import sys

from . import library  # noqa: F401 - registers the scenarios
from .base import ADMIN_TOKEN, APP_URL, REGISTRY, format_card, run_scenario
from .client import LabClient


def _set_all(client: LabClient, flags: dict[str, bool]) -> None:
    for flag, value in flags.items():
        r = client.put("/admin/defences", {"flag": flag, "enabled": value})
        if r.status != 200:
            raise SystemExit(f"Could not set {flag}: {r.status} {r.body}")


def _current(client: LabClient) -> dict[str, bool]:
    r = client.get("/admin/defences")
    return {f"{s}.{k}": v for s, vals in r.body.items() if isinstance(vals, dict)
            for k, v in vals.items() if isinstance(v, bool)}


def check() -> int:
    admin = LabClient(APP_URL, "self-check", admin_token=ADMIN_TOKEN)
    original = _current(admin)
    problems = []
    try:
        for label, value in (("defences OFF, monitoring ON", False), ("defences ON", True)):
            flags = {f: value for f in original}
            flags["monitoring.enabled"] = True
            _set_all(admin, flags)
            print(f"\n=== {label} ===")
            for name, sc in REGISTRY.items():
                card = run_scenario(name, log=lambda *_: None)
                want = sc.baseline_goal if not value else False
                ok_goal = card["goal"]["reached"] == want and card["status"] == "completed"
                ok_alerts = value or not card["alerts"]["missing"]
                mark = "ok  " if ok_goal and ok_alerts else "FAIL"
                print(f"{mark} {name:22} {card['verdict']:45} alerts: {', '.join(card['alerts']['fired']) or '-'}")
                if not ok_goal:
                    problems.append(f"{label}: {name} goal reached={card['goal']['reached']}, expected {want} "
                                    f"({card['goal']['detail']}; steps: {card['steps']})")
                if not ok_alerts:
                    problems.append(f"{label}: {name} missing alerts {card['alerts']['missing']}")
    finally:
        _set_all(admin, original)
        print("\nDefence switches restored.")
    print("\n" + ("SELF-CHECK PASSED" if not problems else "SELF-CHECK FAILED:\n- " + "\n- ".join(problems)))
    return 1 if problems else 0


def main() -> None:
    ap = argparse.ArgumentParser(prog="python -m scenarios", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    run = sub.add_parser("run")
    run.add_argument("name")
    run.add_argument("--json", action="store_true")
    sub.add_parser("run-all")
    sub.add_parser("check")
    args = ap.parse_args()

    if args.cmd == "list":
        for name, sc in REGISTRY.items():
            print(f"{name:22} {sc.title}\n{'':22} {sc.summary}\n")
    elif args.cmd == "run":
        card = run_scenario(args.name)
        print(json.dumps(card, indent=2, default=str) if args.json else format_card(card))
    elif args.cmd == "run-all":
        for name in REGISTRY:
            print(format_card(run_scenario(name)) + "\n")
    elif args.cmd == "check":
        sys.exit(check())


if __name__ == "__main__":
    main()
