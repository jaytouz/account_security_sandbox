"""Passkeys (WebAuthn): register on a logged-in account, then sign in without a password.

Passkeys only work on a named host. Open the app at http://localhost:8000
(the test page is /lab/passkeys), not 127.0.0.1.
"""
import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, Field
from webauthn import (generate_authentication_options, generate_registration_options, options_to_json,
                      verify_authentication_response, verify_registration_response)
from webauthn.helpers import base64url_to_bytes
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement, UserVerificationRequirement)

from telemetry import events

from .. import notify, sessions
from ..context import get_context
from ..db import connection, deny
from ..settings import settings
from ..validation import normalise_email

router = APIRouter(tags=["passkeys"])

CHALLENGE_TTL = timedelta(minutes=5)


class RegisterFinishIn(BaseModel):
    credential: dict
    label: str = Field(default="passkey", max_length=64)


class LoginBeginIn(BaseModel):
    email: str | None = None


class LoginFinishIn(BaseModel):
    credential: dict


def _store_challenge(conn, challenge: bytes, account_id, purpose: str) -> None:
    conn.execute(
        """INSERT INTO app.webauthn_challenge (challenge, account_id, purpose, expires_at)
           VALUES (%s, %s, %s, %s)""",
        (challenge, account_id, purpose, datetime.now(timezone.utc) + CHALLENGE_TTL))


def _take_challenge(conn, credential: dict, purpose: str) -> dict | None:
    """Find and consume the challenge echoed in the credential's clientDataJSON."""
    try:
        client_data = json.loads(base64url_to_bytes(credential["response"]["clientDataJSON"]))
        challenge = base64url_to_bytes(client_data["challenge"])
    except (KeyError, ValueError, TypeError):
        return None
    return conn.execute(
        """UPDATE app.webauthn_challenge SET used_at = clock_timestamp()
            WHERE challenge = %s AND purpose = %s AND used_at IS NULL AND expires_at > clock_timestamp()
        RETURNING challenge, account_id""",
        (challenge, purpose)).fetchone()


# ---------------------------------------------------------------- registration
@router.post("/account/passkeys/register/begin")
def register_begin(request: Request):
    with connection() as conn:
        sess = sessions.require(conn, request)
        existing = conn.execute("SELECT credential_id FROM app.passkey WHERE account_id = %s",
                                (sess["account_id"],)).fetchall()
        opts = generate_registration_options(
            rp_id=settings.webauthn_rp_id,
            rp_name="Account Lab",
            user_id=sess["account_id"].bytes,
            user_name=sess["email"],
            user_display_name=sess["display_name"],
            exclude_credentials=[PublicKeyCredentialDescriptor(id=bytes(r["credential_id"])) for r in existing],
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.PREFERRED),
        )
        _store_challenge(conn, opts.challenge, sess["account_id"], "register")
    return json.loads(options_to_json(opts))


@router.post("/account/passkeys/register/finish", status_code=201)
def register_finish(body: RegisterFinishIn, request: Request):
    ctx = get_context(request)
    with connection() as conn:
        sess = sessions.require(conn, request, ctx)
        ch = _take_challenge(conn, body.credential, "register")
        if ch is None or ch["account_id"] != sess["account_id"]:
            deny(conn, 400, "challenge_invalid", "Start registration again.")
        try:
            v = verify_registration_response(
                credential=body.credential, expected_challenge=bytes(ch["challenge"]),
                expected_rp_id=settings.webauthn_rp_id, expected_origin=settings.webauthn_origin,
                require_user_verification=False)
        except Exception as exc:  # noqa: BLE001 - any verification problem is a 400
            deny(conn, 400, "passkey_invalid", f"Passkey not accepted: {exc}")
        conn.execute(
            """INSERT INTO app.passkey (credential_id, account_id, public_key, sign_count, label)
               VALUES (%s, %s, %s, %s, %s)""",
            (v.credential_id, sess["account_id"], v.credential_public_key, v.sign_count, body.label))
        events.record_change(conn, ctx, account_id=sess["account_id"], session_id=sess["session_id"],
                             change_type="passkey_added", detail={"label": body.label})
    notify.security_change(sess["email"], "A passkey was added")
    return {"status": "passkey_added"}


@router.get("/account/passkeys")
def list_passkeys(request: Request):
    with connection() as conn:
        sess = sessions.require(conn, request)
        return conn.execute(
            "SELECT label, created_at, last_used_at FROM app.passkey WHERE account_id = %s ORDER BY created_at",
            (sess["account_id"],)).fetchall()


# ---------------------------------------------------------------- sign-in
@router.post("/auth/passkey/begin")
def login_begin(body: LoginBeginIn):
    with connection() as conn:
        account_id, allow = None, []
        if body.email:
            acct = conn.execute("SELECT account_id FROM app.account WHERE email = %s",
                                (normalise_email(body.email),)).fetchone()
            if acct:
                account_id = acct["account_id"]
                allow = [PublicKeyCredentialDescriptor(id=bytes(r["credential_id"])) for r in conn.execute(
                    "SELECT credential_id FROM app.passkey WHERE account_id = %s", (account_id,)).fetchall()]
        opts = generate_authentication_options(
            rp_id=settings.webauthn_rp_id, allow_credentials=allow,
            user_verification=UserVerificationRequirement.PREFERRED)
        _store_challenge(conn, opts.challenge, account_id, "login")
    return json.loads(options_to_json(opts))


@router.post("/auth/passkey/finish")
def login_finish(body: LoginFinishIn, request: Request, response: Response):
    ctx = get_context(request)
    with connection() as conn:
        try:
            cred_id = base64url_to_bytes(body.credential["rawId"])
        except (KeyError, ValueError, TypeError):
            deny(conn, 400, "passkey_invalid", "Malformed credential.")
        pk = conn.execute(
            """SELECT p.credential_id, p.public_key, p.sign_count, a.account_id, a.email, a.status,
                      coalesce(a.locked_until > clock_timestamp(), false) AS temp_locked
                 FROM app.passkey p JOIN app.account a USING (account_id) WHERE p.credential_id = %s""",
            (cred_id,)).fetchone()

        def log(result, account_id=None, email="(unknown passkey)"):
            return events.record_login(conn, ctx, account_id=account_id, email_attempted=email, result=result,
                                       mfa_used=True, method="passkey")

        ch = _take_challenge(conn, body.credential, "login")
        if pk is None or ch is None or (ch["account_id"] and ch["account_id"] != pk["account_id"]):
            log("passkey_fail", pk and pk["account_id"], pk["email"] if pk else "(unknown passkey)")
            deny(conn, 401, "passkey_fail", "Passkey sign-in failed.")
        if pk["status"] != "active" or pk["temp_locked"]:
            log("locked", pk["account_id"], pk["email"])
            deny(conn, 403, "account_locked", "This account is locked.")
        try:
            v = verify_authentication_response(
                credential=body.credential, expected_challenge=bytes(ch["challenge"]),
                expected_rp_id=settings.webauthn_rp_id, expected_origin=settings.webauthn_origin,
                credential_public_key=bytes(pk["public_key"]), credential_current_sign_count=pk["sign_count"],
                require_user_verification=False)
        except Exception:  # noqa: BLE001
            log("passkey_fail", pk["account_id"], pk["email"])
            deny(conn, 401, "passkey_fail", "Passkey sign-in failed.")
        conn.execute("UPDATE app.passkey SET sign_count = %s, last_used_at = clock_timestamp() WHERE credential_id = %s",
                     (v.new_sign_count, cred_id))
        event_id = log("success", pk["account_id"], pk["email"])
        sess = sessions.create(conn, ctx, response, pk["account_id"], event_id)
    return {"status": "ok", "account_id": pk["account_id"], "method": "passkey", **sess}
