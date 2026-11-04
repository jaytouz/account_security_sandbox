"""Lab-internal admin API used by the review dashboard.

Needs the X-Lab-Admin-Token header. The gateway blocks /admin from the host,
so only containers on the lab network can reach it. Every action is logged to
telemetry with channel 'admin'.
"""
import hmac
import secrets
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel

from telemetry import events

from .. import sessions
from ..context import get_context
from ..db import connection, deny
from ..security import flags
from ..security.passwords import hash_password
from ..settings import settings
from .recovery import create_reset_token, send_reset_email


def require_admin(x_lab_admin_token: str = Header(default="")) -> None:
    if not settings.admin_token or not hmac.compare_digest(x_lab_admin_token, settings.admin_token):
        raise HTTPException(status_code=404)


router = APIRouter(prefix="/admin", tags=["admin (lab-internal)"], dependencies=[Depends(require_admin)])


class FlagIn(BaseModel):
    flag: str
    enabled: bool


@router.get("/defences")
def get_defences():
    return flags.snapshot()


@router.put("/defences")
def set_defence(body: FlagIn):
    try:
        flags.set_flag(body.flag, body.enabled)
    except KeyError:
        raise HTTPException(status_code=404, detail={"code": "unknown_flag", "message": body.flag})
    with connection() as conn:
        events.record_defence_state(conn, flags.flatten(), actor="admin_api")
    return flags.snapshot()


def _account(conn, account_id: uuid.UUID) -> dict:
    acct = conn.execute("SELECT account_id, email, status FROM app.account WHERE account_id = %s",
                        (account_id,)).fetchone()
    if acct is None:
        deny(conn, 404, "unknown_account", "No such account.")
    return acct


@router.post("/accounts/{account_id}/lock")
def lock(account_id: uuid.UUID, request: Request):
    ctx = get_context(request)
    with connection() as conn:
        _account(conn, account_id)
        conn.execute("UPDATE app.account SET status = 'locked' WHERE account_id = %s", (account_id,))
        n = sessions.revoke_all(conn, account_id, "admin_lock")
        events.record_change(conn, ctx, account_id=account_id, session_id=None, change_type="admin_lock",
                             channel="admin", detail={"sessions_revoked": n})
    return {"status": "locked", "sessions_revoked": n}


@router.post("/accounts/{account_id}/unlock")
def unlock(account_id: uuid.UUID, request: Request):
    ctx = get_context(request)
    with connection() as conn:
        _account(conn, account_id)
        conn.execute("UPDATE app.account SET status = 'active' WHERE account_id = %s", (account_id,))
        events.record_change(conn, ctx, account_id=account_id, session_id=None, change_type="admin_unlock",
                             channel="admin")
    return {"status": "active"}


@router.post("/accounts/{account_id}/revoke-sessions")
def revoke_sessions(account_id: uuid.UUID, request: Request):
    ctx = get_context(request)
    with connection() as conn:
        _account(conn, account_id)
        n = sessions.revoke_all(conn, account_id, "admin_revoke")
        events.record_change(conn, ctx, account_id=account_id, session_id=None,
                             change_type="admin_revoke_sessions", channel="admin",
                             detail={"sessions_revoked": n})
    return {"status": "revoked", "sessions_revoked": n}


@router.post("/accounts/{account_id}/force-reset")
def force_reset(account_id: uuid.UUID, request: Request):
    """Replace the password with an unusable one, end all sessions, email a reset token."""
    ctx = get_context(request)
    with connection() as conn:
        acct = _account(conn, account_id)
        conn.execute(
            """UPDATE app.account SET password_hash = %s, password_changed_at = clock_timestamp()
                WHERE account_id = %s""",
            (hash_password(secrets.token_urlsafe(32)), account_id),
        )
        n = sessions.revoke_all(conn, account_id, "admin_force_reset")
        token = create_reset_token(conn, account_id)
        events.record_change(conn, ctx, account_id=account_id, session_id=None,
                             change_type="admin_force_reset", channel="admin",
                             detail={"sessions_revoked": n})
    sent = send_reset_email(acct["email"], token,
                            "An administrator reset your password after suspicious activity.")
    return {"status": "reset_required", "sessions_revoked": n, "email_sent": sent}
