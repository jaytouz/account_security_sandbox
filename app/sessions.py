from datetime import datetime, timedelta, timezone

from fastapi import Request, Response
from psycopg import Connection

from telemetry import events

from .context import RequestContext
from .db import deny
from .settings import settings
from .tokens import digest, new_token

SESSION_COOKIE = "lab_session"
MFA_COOKIE = "lab_mfa"


def _set_cookie(response: Response, name: str, value: str, max_age: int) -> None:
    # Secure/strict cookie settings become a switch in Phase 4 (session hardening).
    response.set_cookie(name, value, max_age=max_age, httponly=True, samesite="lax")


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
        """SELECT s.session_id, s.created_at, s.expires_at, s.device_fp, s.ip,
                  a.account_id, a.email, a.display_name, a.status, a.totp_enabled,
                  a.password_hash
             FROM app.web_session s JOIN app.account a USING (account_id)
            WHERE s.token_hash = %s AND s.revoked_at IS NULL
              AND s.expires_at > clock_timestamp()""",
        (digest(token),),
    ).fetchone()


def require(conn: Connection, request: Request) -> dict:
    sess = current(conn, request)
    if sess is None:
        deny(conn, 401, "not_authenticated", "Log in first.")
    if sess["status"] != "active":
        deny(conn, 403, "account_locked", "This account is locked.")
    return sess


def revoke(conn: Connection, session_id, reason: str) -> None:
    conn.execute(
        "UPDATE app.web_session SET revoked_at = clock_timestamp() "
        "WHERE session_id = %s AND revoked_at IS NULL",
        (session_id,),
    )
    events.end_session(conn, session_id=session_id, reason=reason)


def revoke_all(conn: Connection, account_id, reason: str) -> int:
    """Revoke every live session of an account. Returns how many were revoked."""
    rows = conn.execute(
        """UPDATE app.web_session SET revoked_at = clock_timestamp()
            WHERE account_id = %s AND revoked_at IS NULL AND expires_at > clock_timestamp()
        RETURNING session_id""",
        (account_id,),
    ).fetchall()
    for r in rows:
        events.end_session(conn, session_id=r["session_id"], reason=reason)
    return len(rows)


def start_mfa_challenge(conn: Connection, response: Response, account_id) -> None:
    token, token_hash = new_token()
    expires = datetime.now(timezone.utc) + timedelta(seconds=settings.mfa_challenge_ttl_seconds)
    conn.execute(
        "INSERT INTO app.mfa_challenge (token_hash, account_id, expires_at) VALUES (%s, %s, %s)",
        (token_hash, account_id, expires),
    )
    _set_cookie(response, MFA_COOKIE, token, settings.mfa_challenge_ttl_seconds)
