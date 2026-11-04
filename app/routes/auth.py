"""Sign-up, login (with optional TOTP step), logout, and who-am-I."""
import pyotp
from fastapi import APIRouter, Request, Response
from psycopg.errors import UniqueViolation
from pydantic import BaseModel, Field

from telemetry import events

from .. import sessions
from ..context import get_context
from ..db import connection, deny
from ..security import flags
from ..security.passwords import DUMMY_HASH, hash_password, policy_problems, verify_password
from ..tokens import digest
from ..validation import normalise_email

router = APIRouter(prefix="/auth", tags=["auth"])

GENERIC_LOGIN_ERROR = "Invalid email or password."


class SignupIn(BaseModel):
    email: str
    password: str = Field(max_length=256)
    display_name: str = Field(min_length=1, max_length=64)


class LoginIn(BaseModel):
    email: str
    password: str = Field(max_length=256)


class MfaIn(BaseModel):
    code: str = Field(min_length=6, max_length=8)


@router.post("/signup", status_code=201)
def signup(body: SignupIn, request: Request):
    ctx = get_context(request)
    email = normalise_email(body.email)
    with connection() as conn:
        problems = policy_problems(body.password, email)
        if problems:
            deny(conn, 400, "weak_password", " ".join(problems))
        try:
            with conn.transaction():
                row = conn.execute(
                    """INSERT INTO app.account (email, display_name, password_hash)
                       VALUES (%s, %s, %s) RETURNING account_id""",
                    (email, body.display_name.strip(), hash_password(body.password)),
                ).fetchone()
        except UniqueViolation:
            deny(conn, 409, "email_taken", "An account with this email already exists.")
        events.record_change(conn, ctx, account_id=row["account_id"], session_id=None,
                             change_type="account_created")
    return {"account_id": row["account_id"], "email": email}


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response):
    ctx = get_context(request)
    email = normalise_email(body.email)
    generic = flags.enabled("baseline.generic_errors")

    with connection() as conn:
        acct = conn.execute(
            "SELECT account_id, password_hash, status, totp_enabled FROM app.account WHERE email = %s",
            (email,),
        ).fetchone()

        if acct is None:
            verify_password(DUMMY_HASH, body.password)
            events.record_login(conn, ctx, account_id=None, email_attempted=email,
                                result="unknown_account")
            deny(conn, 401, "invalid_credentials" if generic else "unknown_account",
                 GENERIC_LOGIN_ERROR if generic else "No account with this email.")

        password_ok = verify_password(acct["password_hash"], body.password)

        if acct["status"] != "active":
            events.record_login(conn, ctx, account_id=acct["account_id"],
                                email_attempted=email, result="locked")
            if generic and not password_ok:
                deny(conn, 401, "invalid_credentials", GENERIC_LOGIN_ERROR)
            deny(conn, 403, "account_locked", "This account is locked.")

        if not password_ok:
            events.record_login(conn, ctx, account_id=acct["account_id"],
                                email_attempted=email, result="bad_password")
            deny(conn, 401, "invalid_credentials" if generic else "bad_password",
                 GENERIC_LOGIN_ERROR if generic else "Wrong password.")

        if acct["totp_enabled"]:
            events.record_login(conn, ctx, account_id=acct["account_id"],
                                email_attempted=email, result="mfa_required")
            sessions.start_mfa_challenge(conn, response, acct["account_id"])
            return {"status": "mfa_required", "next": "/auth/mfa/verify"}

        event_id = events.record_login(conn, ctx, account_id=acct["account_id"],
                                       email_attempted=email, result="success")
        sess = sessions.create(conn, ctx, response, acct["account_id"], event_id)
    return {"status": "ok", "account_id": acct["account_id"], **sess}


@router.post("/mfa/verify")
def mfa_verify(body: MfaIn, request: Request, response: Response):
    ctx = get_context(request)
    token = request.cookies.get(sessions.MFA_COOKIE)
    with connection() as conn:
        ch = None
        if token:
            ch = conn.execute(
                """SELECT c.challenge_id, c.attempts, a.account_id, a.email, a.totp_secret
                     FROM app.mfa_challenge c JOIN app.account a USING (account_id)
                    WHERE c.token_hash = %s AND c.completed_at IS NULL
                      AND c.expires_at > clock_timestamp()""",
                (digest(token),),
            ).fetchone()
        if ch is None:
            deny(conn, 401, "mfa_challenge_invalid", "Log in again.")

        if not pyotp.TOTP(ch["totp_secret"]).verify(body.code.strip(), valid_window=1):
            conn.execute("UPDATE app.mfa_challenge SET attempts = attempts + 1 WHERE challenge_id = %s",
                         (ch["challenge_id"],))
            events.record_login(conn, ctx, account_id=ch["account_id"], email_attempted=ch["email"],
                                result="mfa_fail", mfa_used=True)
            deny(conn, 401, "mfa_fail", "Wrong code.")

        conn.execute("UPDATE app.mfa_challenge SET completed_at = clock_timestamp() WHERE challenge_id = %s",
                     (ch["challenge_id"],))
        event_id = events.record_login(conn, ctx, account_id=ch["account_id"], email_attempted=ch["email"],
                                       result="success", mfa_used=True)
        sess = sessions.create(conn, ctx, response, ch["account_id"], event_id)
    response.delete_cookie(sessions.MFA_COOKIE)
    return {"status": "ok", "account_id": ch["account_id"], **sess}


@router.post("/logout")
def logout(request: Request, response: Response):
    with connection() as conn:
        sess = sessions.current(conn, request)
        if sess:
            sessions.revoke(conn, sess["session_id"], "logout")
    response.delete_cookie(sessions.SESSION_COOKIE)
    return {"status": "logged_out"}


@router.get("/me")
def me(request: Request):
    with connection() as conn:
        sess = sessions.require(conn, request)
    return {
        "account_id": sess["account_id"],
        "email": sess["email"],
        "display_name": sess["display_name"],
        "totp_enabled": sess["totp_enabled"],
        "session": {
            "session_id": sess["session_id"],
            "created_at": sess["created_at"],
            "expires_at": sess["expires_at"],
            "device_fp": sess["device_fp"],
        },
    }
