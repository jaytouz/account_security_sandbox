"""Password reset by emailed, single-use, expiring token.

Weaker recovery fallbacks (for the Phase 5 recovery lesson) are added later.
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from telemetry import events

from .. import mailer
from ..context import get_context
from ..db import connection, deny
from ..security import flags
from ..security.passwords import hash_password, policy_problems
from ..settings import settings
from ..tokens import digest, new_token
from ..validation import normalise_email

router = APIRouter(prefix="/auth/reset", tags=["recovery"])

GENERIC_RESET_REPLY = {"status": "accepted",
                       "message": "If an account exists for this email, a reset link was sent."}


class ResetRequestIn(BaseModel):
    email: str


class ResetConfirmIn(BaseModel):
    token: str = Field(min_length=10, max_length=128)
    new_password: str = Field(max_length=256)


@router.post("/request", status_code=202)
def request_reset(body: ResetRequestIn, request: Request):
    ctx = get_context(request)
    email = normalise_email(body.email)
    with connection() as conn:
        acct = conn.execute("SELECT account_id FROM app.account WHERE email = %s", (email,)).fetchone()
        if acct is None:
            if flags.enabled("baseline.generic_errors"):
                return GENERIC_RESET_REPLY
            deny(conn, 404, "unknown_account", "No account with this email.")

        token, token_hash = new_token()
        expires = datetime.now(timezone.utc) + timedelta(minutes=settings.reset_token_ttl_minutes)
        conn.execute(
            "INSERT INTO app.reset_token (token_hash, account_id, expires_at) VALUES (%s, %s, %s)",
            (token_hash, acct["account_id"], expires),
        )
        events.record_change(conn, ctx, account_id=acct["account_id"], session_id=None,
                             change_type="reset_requested", channel="email")

    mailer.send(
        email,
        "Reset your Account Lab password",
        f"Use this token within {settings.reset_token_ttl_minutes} minutes:\n\n{token}\n\n"
        f"POST {settings.base_url}/auth/reset/confirm with "
        '{"token": "<token>", "new_password": "<new password>"}\n',
    )
    return GENERIC_RESET_REPLY


@router.post("/confirm")
def confirm_reset(body: ResetConfirmIn, request: Request):
    ctx = get_context(request)
    with connection() as conn:
        row = conn.execute(
            """SELECT t.account_id, a.email FROM app.reset_token t JOIN app.account a USING (account_id)
                WHERE t.token_hash = %s AND t.used_at IS NULL AND t.expires_at > clock_timestamp()""",
            (digest(body.token),),
        ).fetchone()
        if row is None:
            deny(conn, 400, "reset_token_invalid", "This reset link is invalid or has expired.")

        problems = policy_problems(body.new_password, row["email"])
        if problems:
            deny(conn, 400, "weak_password", " ".join(problems))

        conn.execute("UPDATE app.reset_token SET used_at = clock_timestamp() WHERE token_hash = %s",
                     (digest(body.token),))
        conn.execute(
            """UPDATE app.account SET password_hash = %s, password_changed_at = clock_timestamp()
                WHERE account_id = %s""",
            (hash_password(body.new_password), row["account_id"]),
        )
        events.record_change(conn, ctx, account_id=row["account_id"], session_id=None,
                             change_type="password_reset", channel="email")
    return {"status": "password_reset"}
