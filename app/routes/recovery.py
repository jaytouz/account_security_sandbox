"""Account recovery.

- Email reset: single-use, expiring token sent to the mail catcher. The strong path.
- Security question: the weak fallback used in the recovery lesson. It resets the
  password AND re-enables password login, so it walks around a passkey.
  Turn it off with recovery.block_security_questions.
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from data.lab_constants import SECURITY_QUESTION
from telemetry import events

from .. import mailer, notify, sessions
from ..context import get_context
from ..db import connection, deny
from ..security import flags, limits
from ..security.passwords import hash_password, policy_problems, verify_password
from ..settings import settings
from ..tokens import digest, new_token
from ..validation import normalise_email

router = APIRouter(prefix="/auth", tags=["recovery"])

GENERIC_RESET_REPLY = {"status": "accepted",
                       "message": "If an account exists for this email, a reset link was sent."}


class ResetRequestIn(BaseModel):
    email: str


class ResetConfirmIn(BaseModel):
    token: str = Field(min_length=10, max_length=128)
    new_password: str = Field(max_length=256)


class QuestionStartIn(BaseModel):
    email: str


class QuestionAnswerIn(BaseModel):
    email: str
    answer: str = Field(min_length=1, max_length=128)
    new_password: str = Field(max_length=256)


def normalise_answer(answer: str) -> str:
    return " ".join(answer.lower().split())


def create_reset_token(conn, account_id) -> str:
    token, token_hash = new_token()
    expires = datetime.now(timezone.utc) + timedelta(minutes=settings.reset_token_ttl_minutes)
    conn.execute(
        "INSERT INTO app.reset_token (token_hash, account_id, expires_at) VALUES (%s, %s, %s)",
        (token_hash, account_id, expires),
    )
    return token


def send_reset_email(email: str, token: str, reason: str = "") -> bool:
    return mailer.send(
        email,
        "Reset your Account Lab password",
        (reason + "\n\n" if reason else "")
        + f"Use this token within {settings.reset_token_ttl_minutes} minutes:\n\n{token}\n\n"
        f"POST {settings.base_url}/auth/reset/confirm with "
        '{"token": "<token>", "new_password": "<new password>"}\n',
    )


def _after_password_recovery(conn, ctx, account_id, change_type: str, channel: str) -> int:
    """Shared bookkeeping after any recovery that sets a new password."""
    conn.execute(
        """UPDATE app.account SET failed_streak = 0, locked_until = NULL,
                  trade_hold_until = clock_timestamp() + %s::interval
            WHERE account_id = %s""",
        (f"{limits.TRADE_HOLD_HOURS} hours", account_id))
    ended = 0
    if flags.enabled("session.revoke_on_password_change"):
        ended = sessions.revoke_all(conn, account_id, change_type)
    events.record_change(conn, ctx, account_id=account_id, session_id=None, change_type=change_type,
                         channel=channel, detail={"sessions_revoked": ended})
    return ended


# ---------------------------------------------------------------- email reset
@router.post("/reset/request", status_code=202)
def request_reset(body: ResetRequestIn, request: Request):
    ctx = get_context(request)
    email = normalise_email(body.email)
    with connection() as conn:
        acct = conn.execute("SELECT account_id FROM app.account WHERE email = %s", (email,)).fetchone()
        account_id = acct["account_id"] if acct else None

        if limits.reset_rate_limited(conn, ctx.ip, account_id):
            events.record_recovery(conn, ctx, kind="reset_request", email=email, account_id=account_id,
                                   result="rate_limited")
            deny(conn, 429, "rate_limited", "Too many reset requests. Try again later.")

        if acct is None:
            events.record_recovery(conn, ctx, kind="reset_request", email=email, account_id=None,
                                   result="unknown_account")
            if flags.enabled("baseline.generic_errors"):
                return GENERIC_RESET_REPLY
            deny(conn, 404, "unknown_account", "No account with this email.")

        token = create_reset_token(conn, account_id)
        events.record_recovery(conn, ctx, kind="reset_request", email=email, account_id=account_id,
                               result="accepted")
        events.record_change(conn, ctx, account_id=account_id, session_id=None,
                             change_type="reset_requested", channel="email")

    send_reset_email(email, token)
    return GENERIC_RESET_REPLY


@router.post("/reset/confirm")
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
        # A passkey-only account stays passkey-only: email reset does not downgrade it.
        conn.execute(
            """UPDATE app.account SET password_hash = %s, password_changed_at = clock_timestamp()
                WHERE account_id = %s""",
            (hash_password(body.new_password), row["account_id"]),
        )
        _after_password_recovery(conn, ctx, row["account_id"], "password_reset", "email")
    notify.security_change(row["email"], "Your password was reset")
    return {"status": "password_reset"}


# ---------------------------------------------------------------- security question (weak)
@router.post("/recover/question/start")
def question_start(body: QuestionStartIn, request: Request):
    ctx = get_context(request)
    email = normalise_email(body.email)
    generic = flags.enabled("baseline.generic_errors")
    with connection() as conn:
        acct = conn.execute("SELECT account_id, security_question FROM app.account WHERE email = %s",
                            (email,)).fetchone()
        account_id = acct["account_id"] if acct else None

        def log(result):
            events.record_recovery(conn, ctx, kind="question_start", email=email, account_id=account_id,
                                   result=result)

        if flags.enabled("recovery.block_security_questions"):
            log("disabled")
            deny(conn, 403, "recovery_method_disabled", "Security-question recovery is turned off.")
        if acct is None or not acct["security_question"]:
            log("unknown_account" if acct is None else "no_question")
            if generic:
                return {"question": SECURITY_QUESTION}
            deny(conn, 404, "no_question", "No security question for this email.")
        log("accepted")
    return {"question": acct["security_question"]}


@router.post("/recover/question")
def question_answer(body: QuestionAnswerIn, request: Request):
    ctx = get_context(request)
    email = normalise_email(body.email)
    with connection() as conn:
        acct = conn.execute(
            "SELECT account_id, security_answer_hash FROM app.account WHERE email = %s", (email,)).fetchone()
        account_id = acct["account_id"] if acct else None

        def log(result):
            events.record_recovery(conn, ctx, kind="question_answer", email=email, account_id=account_id,
                                   result=result)

        if flags.enabled("recovery.block_security_questions"):
            log("disabled")
            deny(conn, 403, "recovery_method_disabled", "Security-question recovery is turned off.")
        if acct is None or not acct["security_answer_hash"]:
            log("unknown_account" if acct is None else "no_question")
            deny(conn, 400, "recovery_failed", "That answer is not correct.")
        if limits.recovery_answers_limited(conn, account_id):
            log("rate_limited")
            deny(conn, 429, "rate_limited", "Too many wrong answers. Try again later.")
        if not verify_password(acct["security_answer_hash"], normalise_answer(body.answer)):
            log("wrong")
            deny(conn, 400, "recovery_failed", "That answer is not correct.")

        problems = policy_problems(body.new_password, email)
        if problems:
            deny(conn, 400, "weak_password", " ".join(problems))

        log("correct")
        # The weakness on purpose: this also turns password login back on.
        conn.execute(
            """UPDATE app.account SET password_hash = %s, password_changed_at = clock_timestamp(),
                      password_login_disabled = false
                WHERE account_id = %s""",
            (hash_password(body.new_password), account_id))
        _after_password_recovery(conn, ctx, account_id, "recovery_security_question", "recovery")
    notify.security_change(email, "Your password was reset with your security question")
    return {"status": "password_reset", "password_login": "enabled"}
