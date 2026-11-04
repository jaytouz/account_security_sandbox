"""Reads the defence switches from config.yaml, reloading when the file changes."""
import os
import threading

import yaml

from ..settings import settings

_lock = threading.Lock()
_cache: dict = {"mtime": None, "data": {}}


def _load() -> dict:
    path = settings.security_config
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return {}
    with _lock:
        if _cache["mtime"] != mtime:
            with open(path, encoding="utf-8") as f:
                _cache["data"] = yaml.safe_load(f) or {}
            _cache["mtime"] = mtime
        return _cache["data"]


def enabled(dotted: str) -> bool:
    """enabled("baseline.generic_errors") -> bool. Missing keys count as off."""
    node = _load()
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return False
        node = node[part]
    return bool(node)


def snapshot() -> dict:
    return _load()
