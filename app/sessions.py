import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Request, Response
from psycopg import Connection

from telemetry import events

from .context import RequestContext, get_context
from .db import deny
from .security import flags, limits
from .settings import settings
from .tokens import digest, new_token

SESSION_COOKIE = "lab_session"
MFA_COOKIE = "lab_mfa"


def _set_cookie(response: Response, name: str, value: str, max_age: int) -> None:
    strict = flags.enabled("session.secure_cookies")
    response.set_cookie(name, value, max_age=max_age, httponly=True, secure=strict,
                        samesite="strict" if strict else "lax")


def create(conn: Connection, ctx: RequestContext, response: Response,
           account_id, login_event_id: int) -> dict:
    token, token_hash = new_token()
    expires = datetime.now(timezone.utc) + timedelta(minutes=settings.session_ttl_minutes)
    row = conn.execute(
        """INSERT INTO app.web_session (token_hash, account_id, expires_at, device_fp, ip)
           VALUES (%s, %s, %s, %s, %s) RETURNING session_id""",
        (token_hash, account_id, expires, ctx.device_fp, ctx.ip),
    ).fetchone()
    events.start_session(conn, ctx, session_id=row["session_id"],
                         account_id=account_id, login_event_id=login_event_id)
    _set_cookie(response, SESSION_COOKIE, token, settings.session_ttl_minutes * 60)
    return {"session_id": row["session_id"], "expires_at": expires}


def current(conn: Connection, request: Request) -> dict | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    return conn.execute(
        """SELECT s.session_id, s.created_at, s.expires_at, s.device_fp, s.ip, s.reauth_at,
                  a.account_id, a.email, a.display_name, a.status, a.totp_enabled, a.totp_secret,
                  a.password_hash, a.password_login_disabled,
                  coalesce(a.trade_hold_until > clock_timestamp(), false) AS trade_hold
             FROM app.web_session s JOIN app.account a USING (account_id)
            WHERE s.token_hash = %s AND s.revoked_at IS NULL
              AND s.expires_at > clock_timestamp()""",
        (digest(token),),
    ).fetchone()


def require(conn: Connection, request: Request, ctx: RequestContext | None = None) -> dict:
    sess = current(conn, request)
    if sess is None:
        deny(conn, 401, "not_authenticated", "Log in first.")
    if sess["status"] != "active":
        deny(conn, 403, "account_locked", "This account is locked.")

    ctx = ctx or get_context(request)
    if sess["device_fp"] and ctx.device_fp != sess["device_fp"]:
        # Always a signal; only enforced when session.bind_to_device is on.
        events.record_session_event(conn, ctx, session_id=sess["session_id"], account_id=sess["account_id"],
                                    kind="device_mismatch", expected_device_fp=sess["device_fp"])
        if flags.enabled("session.bind_to_device"):
            revoke(conn, sess["session_id"], "device_mismatch")
            deny(conn, 401, "session_revoked", "This session was ended: it was used from another device.")
    return sess


def require_recent_auth(conn: Connection, sess: dict) -> None:
    """mfa.reauth_for_sensitive: the session must have re-authenticated recently."""
    if not flags.enabled("mfa.reauth_for_sensitive"):
        return
    row = conn.execute(
        """SELECT coalesce(reauth_at > clock_timestamp() - %s::interval, false) AS fresh
             FROM app.web_session WHERE session_id = %s""",
        (f"{limits.REAUTH_MINUTES} minutes", sess["session_id"]),
    ).fetchone()
    if not row["fresh"]:
        deny(conn, 403, "reauth_required", "Confirm it's you first: POST /account/reauth.")


def revoke(conn: Connection, session_id, reason: str) -> None:
    conn.execute(
        "UPDATE app.web_session SET revoked_at = clock_timestamp() "
        "WHERE session_id = %s AND revoked_at IS NULL",
        (session_id,),
    )
    events.end_session(conn, session_id=session_id, reason=reason)


def revoke_all(conn: Connection, account_id, reason: str, keep=None) -> int:
    """Revoke every live session of an account (except `keep`). Returns how many."""
    rows = conn.execute(
        """UPDATE app.web_session SET revoked_at = clock_timestamp()
            WHERE account_id = %s AND revoked_at IS NULL AND expires_at > clock_timestamp()
              AND (%s::uuid IS NULL OR session_id <> %s::uuid)
        RETURNING session_id""",
        (account_id, keep, keep),
    ).fetchall()
    for r in rows:
        events.end_session(conn, session_id=r["session_id"], reason=reason)
    return len(rows)


def start_challenge(conn: Connection, response: Response, account_id, kind: str = "totp") -> str | None:
    """Second-step challenge. For kind='email' returns the code to send."""
    token, token_hash = new_token()
    code = f"{secrets.randbelow(10**6):06d}" if kind == "email" else None
    expires = datetime.now(timezone.utc) + timedelta(seconds=settings.mfa_challenge_ttl_seconds)
    conn.execute(
        """INSERT INTO app.mfa_challenge (token_hash, account_id, expires_at, kind, code_hash)
           VALUES (%s, %s, %s, %s, %s)""",
        (token_hash, account_id, expires, kind, hashlib.sha256(code.encode()).digest() if code else None),
    )
    _set_cookie(response, MFA_COOKIE, token, settings.mfa_challenge_ttl_seconds)
    return code
