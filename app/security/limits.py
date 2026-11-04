"""Thresholds for the defences, and the counters they read from telemetry."""
from psycopg import Connection

from . import flags

LOGIN_WINDOW = "5 minutes"
ACCOUNT_FAILURES = 5          # rate_limiting.per_account
IP_FAILURES = 20              # rate_limiting.per_ip
LOCK_AFTER = 10               # lockout.enabled: wrong passwords in a row
LOCK_MINUTES = 15
MFA_MAX_ATTEMPTS = 5          # codes per challenge
RECOVERY_WINDOW = "10 minutes"
RESET_PER_ACCOUNT = 3
RESET_PER_IP = 5
RECOVERY_WRONG_ANSWERS = 5
REAUTH_MINUTES = 10           # mfa.reauth_for_sensitive
TRADE_HOLD_HOURS = 24         # recovery.trade_cooldown
STEP_UP_SCORE = 3             # risk.step_up

FAILED_LOGIN_RESULTS = ["bad_password", "unknown_account", "mfa_fail", "password_disabled", "passkey_fail"]


def login_rate_limited(conn: Connection, ip: str | None, account_id) -> bool:
    if ip and flags.enabled("rate_limiting.per_ip"):
        n = conn.execute(
            """SELECT count(*) AS n FROM telemetry.login_event
                WHERE ip = %s AND ts > now() - %s::interval AND result = ANY(%s)""",
            (ip, LOGIN_WINDOW, FAILED_LOGIN_RESULTS)).fetchone()["n"]
        if n >= IP_FAILURES:
            return True
    if account_id and flags.enabled("rate_limiting.per_account"):
        n = conn.execute(
            """SELECT count(*) AS n FROM telemetry.login_event
                WHERE account_id = %s AND ts > now() - %s::interval AND result = ANY(%s)""",
            (account_id, LOGIN_WINDOW, FAILED_LOGIN_RESULTS)).fetchone()["n"]
        if n >= ACCOUNT_FAILURES:
            return True
    return False


def reset_rate_limited(conn: Connection, ip: str | None, account_id) -> bool:
    if ip and flags.enabled("rate_limiting.per_ip"):
        n = conn.execute(
            """SELECT count(*) AS n FROM telemetry.recovery_event
                WHERE kind = 'reset_request' AND ip = %s AND ts > now() - %s::interval
                  AND result IN ('accepted', 'unknown_account')""",
            (ip, RECOVERY_WINDOW)).fetchone()["n"]
        if n >= RESET_PER_IP:
            return True
    if account_id and flags.enabled("rate_limiting.per_account"):
        n = conn.execute(
            """SELECT count(*) AS n FROM telemetry.recovery_event
                WHERE kind = 'reset_request' AND account_id = %s AND ts > now() - %s::interval
                  AND result = 'accepted'""",
            (account_id, RECOVERY_WINDOW)).fetchone()["n"]
        if n >= RESET_PER_ACCOUNT:
            return True
    return False


def recovery_answers_limited(conn: Connection, account_id) -> bool:
    if not flags.enabled("rate_limiting.per_account"):
        return False
    n = conn.execute(
        """SELECT count(*) AS n FROM telemetry.recovery_event
            WHERE kind = 'question_answer' AND account_id = %s AND ts > now() - %s::interval
              AND result = 'wrong'""",
        (account_id, RECOVERY_WINDOW)).fetchone()["n"]
    return n >= RECOVERY_WRONG_ANSWERS
