"""Sign-up, login (with TOTP or step-up second step), logout, and who-am-I."""
import hashlib
import hmac

import pyotp
from fastapi import APIRouter, Request, Response
from psycopg.errors import UniqueViolation
from pydantic import BaseModel, Field

from telemetry import events

from .. import mailer, sessions
from ..context import get_context
from ..db import connection, deny
from ..security import flags, limits, risk
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


class CodeIn(BaseModel):
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
    step_up_code = None

    def fail(conn, code, message, status=401):
        if generic and status in (401, 403):
            deny(conn, 401, "invalid_credentials", GENERIC_LOGIN_ERROR)
        deny(conn, status, code, message)

    with connection() as conn:
        acct = conn.execute(
            """SELECT account_id, password_hash, status, totp_enabled, password_login_disabled,
                      coalesce(locked_until > clock_timestamp(), false) AS temp_locked
                 FROM app.account WHERE email = %s""",
            (email,),
        ).fetchone()
        account_id = acct["account_id"] if acct else None

        def log(result, **kw):
            return events.record_login(conn, ctx, account_id=account_id, email_attempted=email,
                                       result=result, **kw)

        if limits.login_rate_limited(conn, ctx.ip, account_id):
            log("rate_limited")
            deny(conn, 429, "rate_limited", "Too many failed attempts. Try again in a few minutes.")

        if acct is None:
            verify_password(DUMMY_HASH, body.password)
            log("unknown_account")
            fail(conn, "unknown_account", "No account with this email.")

        password_ok = verify_password(acct["password_hash"], body.password)

        if acct["status"] != "active" or acct["temp_locked"]:
            log("locked")
            fail(conn, "account_locked", "This account is locked.", 403)

        if acct["password_login_disabled"]:
            log("password_disabled")
            fail(conn, "password_login_disabled", "This account signs in with a passkey.", 403)

        if not password_ok:
            log("bad_password")
            if flags.enabled("lockout.enabled"):
                streak = conn.execute(
                    "UPDATE app.account SET failed_streak = failed_streak + 1 WHERE account_id = %s "
                    "RETURNING failed_streak", (account_id,)).fetchone()["failed_streak"]
                if streak >= limits.LOCK_AFTER:
                    conn.execute(
                        """UPDATE app.account SET failed_streak = 0,
                                  locked_until = clock_timestamp() + %s::interval
                            WHERE account_id = %s""",
                        (f"{limits.LOCK_MINUTES} minutes", account_id))
                    events.record_change(conn, ctx, account_id=account_id, session_id=None,
                                         change_type="auto_lock", channel="system",
                                         detail={"minutes": limits.LOCK_MINUTES})
            fail(conn, "bad_password", "Wrong password.")

        conn.execute("UPDATE app.account SET failed_streak = 0 WHERE account_id = %s AND failed_streak > 0",
                     (account_id,))
        score = risk.assess(conn, ctx, account_id)

        if acct["totp_enabled"]:
            log("mfa_required", risk=score)
            sessions.start_challenge(conn, response, account_id, "totp")
            return {"status": "mfa_required", "next": "/auth/mfa/verify"}

        if flags.enabled("risk.step_up") and score[0] >= limits.STEP_UP_SCORE:
            log("step_up", risk=score)
            step_up_code = sessions.start_challenge(conn, response, account_id, "email")
        else:
            event_id = log("success", risk=score)
            sess = sessions.create(conn, ctx, response, account_id, event_id)

    if step_up_code:
        mailer.send(email, "Your Account Lab sign-in code",
                    f"Someone signed in from a new or unusual place ({', '.join(score[1])}).\n\n"
                    f"If it was you, enter this code: {step_up_code}\n")
        return {"status": "step_up_required", "next": "/auth/step-up/verify", "reasons": score[1]}
    return {"status": "ok", "account_id": account_id, **sess}


def _verify_challenge(kind: str, code: str, request: Request, response: Response):
    ctx = get_context(request)
    token = request.cookies.get(sessions.MFA_COOKIE)
    with connection() as conn:
        ch = None
        if token:
            ch = conn.execute(
                """SELECT c.challenge_id, c.attempts, c.code_hash, a.account_id, a.email, a.totp_secret
                     FROM app.mfa_challenge c JOIN app.account a USING (account_id)
                    WHERE c.token_hash = %s AND c.kind = %s AND c.completed_at IS NULL
                      AND c.expires_at > clock_timestamp()""",
                (digest(token), kind),
            ).fetchone()
        if ch is None:
            deny(conn, 401, "challenge_invalid", "Log in again.")

        def log(result):
            return events.record_login(conn, ctx, account_id=ch["account_id"], email_attempted=ch["email"],
                                       result=result, mfa_used=True)

        capped = kind == "email" or flags.enabled("rate_limiting.per_account")
        if capped and ch["attempts"] >= limits.MFA_MAX_ATTEMPTS:
            conn.execute("UPDATE app.mfa_challenge SET expires_at = clock_timestamp() WHERE challenge_id = %s",
                         (ch["challenge_id"],))
            log("rate_limited")
            deny(conn, 429, "too_many_codes", "Too many wrong codes. Log in again.")

        code = code.strip()
        if kind == "totp":
            ok = pyotp.TOTP(ch["totp_secret"]).verify(code, valid_window=1)
        else:
            ok = hmac.compare_digest(hashlib.sha256(code.encode()).digest(), bytes(ch["code_hash"]))
        if not ok:
            conn.execute("UPDATE app.mfa_challenge SET attempts = attempts + 1 WHERE challenge_id = %s",
                         (ch["challenge_id"],))
            log("mfa_fail")
            deny(conn, 401, "mfa_fail", "Wrong code.")

        conn.execute("UPDATE app.mfa_challenge SET completed_at = clock_timestamp() WHERE challenge_id = %s",
                     (ch["challenge_id"],))
        sess = sessions.create(conn, ctx, response, ch["account_id"], log("success"))
    response.delete_cookie(sessions.MFA_COOKIE)
    return {"status": "ok", "account_id": ch["account_id"], **sess}


@router.post("/mfa/verify")
def mfa_verify(body: CodeIn, request: Request, response: Response):
    return _verify_challenge("totp", body.code, request, response)


@router.post("/step-up/verify")
def step_up_verify(body: CodeIn, request: Request, response: Response):
    """Second step after a risky password login: the code emailed to the account (see Mailpit)."""
    return _verify_challenge("email", body.code, request, response)


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
        passkeys = conn.execute("SELECT count(*) AS n FROM app.passkey WHERE account_id = %s",
                                (sess["account_id"],)).fetchone()["n"]
    return {
        "account_id": sess["account_id"],
        "email": sess["email"],
        "display_name": sess["display_name"],
        "totp_enabled": sess["totp_enabled"],
        "passkeys": passkeys,
        "password_login_disabled": sess["password_login_disabled"],
        "session": {
            "session_id": sess["session_id"],
            "created_at": sess["created_at"],
            "expires_at": sess["expires_at"],
            "device_fp": sess["device_fp"],
            "reauth_at": sess["reauth_at"],
        },
    }
