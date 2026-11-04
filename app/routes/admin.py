"""Lab-internal admin API used by the review dashboard.

Needs the X-Lab-Admin-Token header. The gateway blocks /admin from the host,
so only containers on the lab network can reach it. Every action is logged to
telemetry with channel 'admin'.
"""
import hmac
import random
import secrets
import uuid

import pyotp
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from psycopg.errors import UniqueViolation
from pydantic import BaseModel, Field

from data.lab_constants import ITEMS, SECURITY_QUESTION
from telemetry import events

from .. import sessions
from ..context import get_context
from ..db import connection, deny
from ..security import flags
from ..security.passwords import hash_password
from ..settings import settings
from ..validation import normalise_email
from .recovery import create_reset_token, normalise_answer, send_reset_email


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
    """Clears both an admin lock and a temporary lockout."""
    ctx = get_context(request)
    with connection() as conn:
        _account(conn, account_id)
        conn.execute("""UPDATE app.account SET status = 'active', locked_until = NULL, failed_streak = 0
                         WHERE account_id = %s""", (account_id,))
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


class FixtureIn(BaseModel):
    email: str
    password: str = Field(min_length=12, max_length=256)
    display_name: str = "Scenario account"
    totp: bool = False
    items: int = Field(default=0, ge=0, le=20)
    security_answer: str | None = None


@router.post("/fixtures/account", status_code=201)
def create_fixture(body: FixtureIn, request: Request):
    """Fresh fake account for a scenario run (only @lab.test addresses)."""
    ctx = get_context(request)
    email = normalise_email(body.email)
    if not email.endswith("@lab.test"):
        raise HTTPException(status_code=400, detail={"code": "bad_email", "message": "Fixtures must use @lab.test."})
    totp_secret = pyotp.random_base32() if body.totp else None
    answer_hash = hash_password(normalise_answer(body.security_answer)) if body.security_answer else None
    with connection() as conn:
        try:
            with conn.transaction():
                row = conn.execute(
                    """INSERT INTO app.account (email, display_name, password_hash, totp_secret, totp_enabled,
                                                security_question, security_answer_hash)
                       VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING account_id""",
                    (email, body.display_name, hash_password(body.password), totp_secret, body.totp,
                     SECURITY_QUESTION if answer_hash else None, answer_hash),
                ).fetchone()
        except UniqueViolation:
            deny(conn, 409, "email_taken", "Fixture email already exists.")
        rng = random.Random()
        for _ in range(body.items):
            conn.execute("INSERT INTO app.item (owner_account_id, name, value_cents) VALUES (%s, %s, %s)",
                         (row["account_id"], rng.choice(ITEMS), rng.randrange(2_000, 40_000, 25)))
        events.record_change(conn, ctx, account_id=row["account_id"], session_id=None,
                             change_type="fixture_created", channel="admin")
    return {"account_id": row["account_id"], "email": email, "totp_secret": totp_secret}


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
