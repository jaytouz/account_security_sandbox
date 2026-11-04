"""Calls to the scenario runner's internal API."""
import os

import requests

BASE = os.environ.get("LAB_RUNNER_URL", "http://runner:8100")


class RunnerError(Exception):
    pass


def scenarios() -> list[dict]:
    try:
        r = requests.get(BASE + "/scenarios", timeout=5)
        r.raise_for_status()
        return r.json()
    except requests.RequestException as exc:
        raise RunnerError(f"Scenario runner not reachable: {exc}") from exc


def run(name: str) -> dict:
    try:
        r = requests.post(BASE + "/runs", json={"scenario": name}, timeout=180)
    except requests.RequestException as exc:
        raise RunnerError(f"Scenario runner not reachable: {exc}") from exc
    if r.status_code == 409:
        raise RunnerError("Another scenario is still running. Try again in a few seconds.")
    if r.status_code >= 400:
        raise RunnerError(f"{r.status_code} {r.text[:200]}")
    return r.json()
