from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from . import breached, flags

_ph = PasswordHasher()

# Checked against when the email matches no account, so both paths cost the same.
DUMMY_HASH = _ph.hash("lab-dummy-password-for-timing")


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _ph.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def policy_problems(password: str, email: str) -> list[str]:
    if not password:
        return ["Password is required."]
    if len(password) > 256:
        return ["Password is too long."]
    problems = []
    if flags.enabled("breached_passwords.enabled") and breached.is_breached(password):
        problems.append("This password appears in a known breach list. Choose another one.")
    if not flags.enabled("baseline.password_policy"):
        return problems
    if len(password) < 12:
        problems.append("Use at least 12 characters.")
    local = email.split("@", 1)[0].lower()
    if local and len(local) >= 3 and local in password.lower():
        problems.append("Password must not contain your email name.")
    return problems
