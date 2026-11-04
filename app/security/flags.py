"""Reads the defence switches from config.yaml, reloading when the file changes.

The file is two levels deep (section -> flag: true/false) and is edited in
place by set_flag(), which keeps its comments.
"""
import os
import re
import threading

import yaml

from ..settings import settings

_lock = threading.Lock()
_cache: dict = {"mtime": None, "data": {}}

_SECTION = re.compile(r"^([A-Za-z0-9_]+):\s*(#.*)?$")
_FLAG = re.compile(r"^(\s+)([A-Za-z0-9_]+):\s*(true|false)\b(.*)$")


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


def flatten() -> dict[str, bool]:
    """{"baseline.generic_errors": False, ...} for every true/false flag."""
    out = {}
    for section, flags in snapshot().items():
        if isinstance(flags, dict):
            for key, value in flags.items():
                if isinstance(value, bool):
                    out[f"{section}.{key}"] = value
    return out


def set_flag(dotted: str, value: bool) -> None:
    """Flip one existing flag in config.yaml. Raises KeyError if it isn't there."""
    section, _, key = dotted.partition(".")
    path = settings.security_config
    with _lock:
        with open(path, encoding="utf-8", newline="") as f:
            lines = f.readlines()
        current = None
        for i, line in enumerate(lines):
            if m := _SECTION.match(line):
                current = m.group(1)
            elif (m := _FLAG.match(line)) and current == section and m.group(2) == key:
                ending = "\r\n" if line.endswith("\r\n") else "\n"
                rest = m.group(4).rstrip("\r")
                lines[i] = f"{m.group(1)}{key}: {'true' if value else 'false'}{rest}{ending}"
                break
        else:
            raise KeyError(dotted)
        # Rewrite in place (no rename) so the bind-mounted file keeps its identity.
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.writelines(lines)
        _cache["mtime"] = None
