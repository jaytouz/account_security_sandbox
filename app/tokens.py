import hashlib
import secrets


def new_token() -> tuple[str, bytes]:
    """Random token for a cookie or link, plus the sha256 that gets stored."""
    token = secrets.token_urlsafe(32)
    return token, digest(token)


def digest(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()
