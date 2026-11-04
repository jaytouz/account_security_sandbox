"""Breached-password check against a local list of SHA-1 hashes (HIBP format).

The shipped sample holds a few dozen well-known weak passwords. You can swap in
the full Have I Been Pwned hash list later; lines look like HASH or HASH:COUNT.
"""
import hashlib
from functools import lru_cache
from pathlib import Path

LIST = Path(__file__).with_name("breached_sample.txt")


@lru_cache(maxsize=1)
def _hashes() -> frozenset[str]:
    out = set()
    for line in LIST.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.add(line.split(":", 1)[0].upper())
    return frozenset(out)


def is_breached(password: str) -> bool:
    return hashlib.sha1(password.encode()).hexdigest().upper() in _hashes()
