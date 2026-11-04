"""Calls to the app's lab-internal /admin API. All writes go through here."""
import os

import requests

BASE = os.environ.get("LAB_APP_URL", "http://app:8000")
TOKEN = os.environ.get("LAB_ADMIN_TOKEN", "")


class AdminError(Exception):
    pass


def _call(method: str, path: str, json: dict | None = None) -> dict:
    try:
        r = requests.request(method, BASE + path, json=json, timeout=10,
                             headers={"X-Lab-Admin-Token": TOKEN})
    except requests.RequestException as exc:
        raise AdminError(f"App not reachable: {exc}") from exc
    if r.status_code >= 400:
        raise AdminError(f"{r.status_code} {r.text[:200]}")
    return r.json()


def defences() -> dict:
    return _call("GET", "/admin/defences")


def set_defence(flag: str, enabled: bool) -> dict:
    return _call("PUT", "/admin/defences", {"flag": flag, "enabled": enabled})


def lock(account_id: str) -> dict:
    return _call("POST", f"/admin/accounts/{account_id}/lock")


def unlock(account_id: str) -> dict:
    return _call("POST", f"/admin/accounts/{account_id}/unlock")


def revoke_sessions(account_id: str) -> dict:
    return _call("POST", f"/admin/accounts/{account_id}/revoke-sessions")


def force_reset(account_id: str) -> dict:
    return _call("POST", f"/admin/accounts/{account_id}/force-reset")
