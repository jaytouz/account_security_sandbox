"""Profile and security settings for the logged-in account."""
import pyotp
from fastapi import APIRouter, Request
from psycopg.errors import UniqueViolation
from pydantic import BaseModel, Field

from telemetry import events

from .. import notify, sessions
from ..context import get_context
from ..db import connection, deny
from ..security import flags, limits
from ..security.passwords import hash_password, policy_problems, verify_password
from ..validation import normalise_email
from .recovery import normalise_answer

router = APIRouter(prefix="/account", tags=["account"])


class PasswordChangeIn(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


class EmailChangeIn(BaseModel):
    new_email: str
    current_password: str = Field(max_length=256)


class CodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class PasswordIn(BaseModel):
    current_password: str = Field(max_length=256)


class ReauthIn(BaseModel):
    password: str = Field(max_length=256)
    code: str | None = Field(default=None, max_length=8)


class PasswordLoginIn(BaseModel):
    enabled: bool


class SecurityQuestionIn(BaseModel):
    question: str = Field(min_length=5, max_length=200)
    answer: str = Field(min_length=1, max_length=128)
    current_password: str = Field(max_length=256)


def _check_password(conn, sess, password: str) -> None:
    if not verify_password(sess["password_hash"], password):
        deny(conn, 401, "bad_password", "Current password is wrong.")


@router.post("/reauth")
def reauth(body: ReauthIn, request: Request):
    """Confirm it's you (password, plus TOTP code if enabled). Unlocks sensitive actions for 10 minutes."""
    ctx = get_context(request)
    with connection() as conn:
        sess = sessions.require(conn, request, ctx)
        _check_password(conn, sess, body.password)
        if sess["totp_enabled"] and not (body.code and pyotp.TOTP(sess["totp_secret"]).verify(body.code, valid_window=1)):
            deny(conn, 401, "mfa_fail", "A valid authenticator code is required.")
        conn.execute("UPDATE app.web_session SET reauth_at = clock_timestamp() WHERE session_id = %s",
                     (sess["session_id"],))
        events.record_change(conn, ctx, account_id=sess["account_id"], session_id=sess["session_id"],
                             change_type="reauth")
    return {"status": "ok", "valid_minutes": limits.REAUTH_MINUTES}


@router.post("/password")
def change_password(body: PasswordChangeIn, request: Request):
    ctx = get_context(request)
    with connection() as conn:
        sess = sessions.require(conn, request, ctx)
        _check_password(conn, sess, body.current_password)
        problems = policy_problems(body.new_password, sess["email"])
        if problems:
            deny(conn, 400, "weak_password", " ".join(problems))
        conn.execute(
            """UPDATE app.account SET password_hash = %s, password_changed_at = clock_timestamp()
                WHERE account_id = %s""",
            (hash_password(body.new_password), sess["account_id"]),
        )
        ended = 0
        if flags.enabled("session.revoke_on_password_change"):
            ended = sessions.revoke_all(conn, sess["account_id"], "password_change", keep=sess["session_id"])
        events.record_change(conn, ctx, account_id=sess["account_id"], session_id=sess["session_id"],
                             change_type="password_change", detail={"other_sessions_revoked": ended})
    notify.security_change(sess["email"], "Your password was changed")
    return {"status": "password_changed", "other_sessions_revoked": ended}


@router.post("/email")
def change_email(body: EmailChangeIn, request: Request):
    ctx = get_context(request)
    new_email = normalise_email(body.new_email)
    with connection() as conn:
        sess = sessions.require(conn, request, ctx)
        sessions.require_recent_auth(conn, sess)
        _check_password(conn, sess, body.current_password)
        try:
            with conn.transaction():
                conn.execute(
                    """UPDATE app.account SET email = %s, trade_hold_until = clock_timestamp() + %s::interval
                        WHERE account_id = %s""",
                    (new_email, f"{limits.TRADE_HOLD_HOURS} hours", sess["account_id"]))
        except UniqueViolation:
            deny(conn, 409, "email_taken", "That email is already in use.")
        events.record_change(conn, ctx, account_id=sess["account_id"], session_id=sess["session_id"],
                             change_type="email_change",
                             detail={"from": sess["email"], "to": new_email})
    # Tell the OLD address: that's the one the real owner still reads.
    notify.security_change(sess["email"], f"Your sign-in email was changed to {new_email}")
    return {"status": "email_changed", "email": new_email}


@router.post("/mfa/totp/enroll")
def totp_enroll(request: Request):
    ctx = get_context(request)
    with connection() as conn:
        sess = sessions.require(conn, request, ctx)
        if sess["totp_enabled"]:
            deny(conn, 409, "mfa_already_enabled", "TOTP is already on.")
        secret = pyotp.random_base32()
        conn.execute("UPDATE app.account SET totp_secret = %s WHERE account_id = %s",
                     (secret, sess["account_id"]))
        events.record_change(conn, ctx, account_id=sess["account_id"], session_id=sess["session_id"],
                             change_type="mfa_enroll_started")
    uri = pyotp.TOTP(secret).provisioning_uri(name=sess["email"], issuer_name="Account Lab")
    return {"secret": secret, "otpauth_uri": uri, "next": "/account/mfa/totp/confirm"}


@router.post("/mfa/totp/confirm")
def totp_confirm(body: CodeIn, request: Request):
    ctx = get_context(request)
    with connection() as conn:
        sess = sessions.require(conn, request, ctx)
        row = conn.execute("SELECT totp_secret FROM app.account WHERE account_id = %s",
                           (sess["account_id"],)).fetchone()
        if not row["totp_secret"]:
            deny(conn, 400, "mfa_not_enrolling", "Start enrolment first.")
        if not pyotp.TOTP(row["totp_secret"]).verify(body.code.strip(), valid_window=1):
            deny(conn, 400, "mfa_fail", "Wrong code.")
        conn.execute("UPDATE app.account SET totp_enabled = true WHERE account_id = %s",
                     (sess["account_id"],))
        events.record_change(conn, ctx, account_id=sess["account_id"], session_id=sess["session_id"],
                             change_type="mfa_enabled")
    return {"status": "mfa_enabled"}


@router.post("/mfa/totp/disable")
def totp_disable(body: PasswordIn, request: Request):
    ctx = get_context(request)
    with connection() as conn:
        sess = sessions.require(conn, request, ctx)
        sessions.require_recent_auth(conn, sess)
        _check_password(conn, sess, body.current_password)
        conn.execute("UPDATE app.account SET totp_enabled = false, totp_secret = NULL WHERE account_id = %s",
                     (sess["account_id"],))
        events.record_change(conn, ctx, account_id=sess["account_id"], session_id=sess["session_id"],
                             change_type="mfa_disabled")
    notify.security_change(sess["email"], "Two-step sign-in was turned off")
    return {"status": "mfa_disabled"}


@router.post("/password-login")
def set_password_login(body: PasswordLoginIn, request: Request):
    """Turn password login off (passkey-only) or back on."""
    ctx = get_context(request)
    with connection() as conn:
        sess = sessions.require(conn, request, ctx)
        sessions.require_recent_auth(conn, sess)
        if not body.enabled:
            n = conn.execute("SELECT count(*) AS n FROM app.passkey WHERE account_id = %s",
                             (sess["account_id"],)).fetchone()["n"]
            if n == 0:
                deny(conn, 400, "no_passkey", "Add a passkey before turning password login off.")
        conn.execute("UPDATE app.account SET password_login_disabled = %s WHERE account_id = %s",
                     (not body.enabled, sess["account_id"]))
        change = "password_login_enabled" if body.enabled else "password_login_disabled"
        events.record_change(conn, ctx, account_id=sess["account_id"], session_id=sess["session_id"],
                             change_type=change)
    notify.security_change(sess["email"], "Password sign-in was turned " + ("on" if body.enabled else "off"))
    return {"status": change}


@router.post("/security-question")
def set_security_question(body: SecurityQuestionIn, request: Request):
    ctx = get_context(request)
    with connection() as conn:
        sess = sessions.require(conn, request, ctx)
        _check_password(conn, sess, body.current_password)
        conn.execute("UPDATE app.account SET security_question = %s, security_answer_hash = %s WHERE account_id = %s",
                     (body.question.strip(), hash_password(normalise_answer(body.answer)), sess["account_id"]))
        events.record_change(conn, ctx, account_id=sess["account_id"], session_id=sess["session_id"],
                             change_type="security_question_changed")
    notify.security_change(sess["email"], "Your security question was changed")
    return {"status": "security_question_set"}


@router.get("/sessions")
def list_sessions(request: Request):
    with connection() as conn:
        sess = sessions.require(conn, request)
        rows = conn.execute(
            """SELECT session_id, created_at, expires_at, revoked_at, device_fp, host(ip) AS ip
                 FROM app.web_session WHERE account_id = %s ORDER BY created_at DESC LIMIT 50""",
            (sess["account_id"],),
        ).fetchall()
    for r in rows:
        r["current"] = r["session_id"] == sess["session_id"]
    return rows
