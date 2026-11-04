"""Fake inventory and trades between accounts."""
from fastapi import APIRouter, Request
from pydantic import BaseModel

from telemetry import events

from .. import sessions
from ..context import get_context
from ..db import connection, deny
from ..security import flags
from ..validation import normalise_email

router = APIRouter(tags=["assets"])


class TradeIn(BaseModel):
    item_id: int
    to_email: str


@router.get("/inventory")
def inventory(request: Request):
    with connection() as conn:
        sess = sessions.require(conn, request)
        return conn.execute(
            "SELECT item_id, name, value_cents FROM app.item WHERE owner_account_id = %s ORDER BY item_id",
            (sess["account_id"],),
        ).fetchall()


@router.post("/trades", status_code=201)
def trade(body: TradeIn, request: Request):
    ctx = get_context(request)
    to_email = normalise_email(body.to_email)
    with connection() as conn:
        sess = sessions.require(conn, request, ctx)
        sessions.require_recent_auth(conn, sess)
        if sess["trade_hold"] and flags.enabled("recovery.trade_cooldown"):
            deny(conn, 403, "trade_hold", "Trades are paused for 24 hours after a recent security change.")
        item = conn.execute(
            "SELECT item_id, name, value_cents FROM app.item WHERE item_id = %s AND owner_account_id = %s "
            "FOR UPDATE",
            (body.item_id, sess["account_id"]),
        ).fetchone()
        if item is None:
            deny(conn, 404, "item_not_found", "You don't own that item.")
        to = conn.execute("SELECT account_id FROM app.account WHERE email = %s AND status = 'active'",
                          (to_email,)).fetchone()
        if to is None or to["account_id"] == sess["account_id"]:
            deny(conn, 400, "bad_recipient", "Recipient not found.")
        conn.execute("UPDATE app.item SET owner_account_id = %s WHERE item_id = %s",
                     (to["account_id"], item["item_id"]))
        events.record_transfer(conn, ctx, account_id=sess["account_id"], counterparty=to["account_id"],
                               item_id=item["item_id"], value_cents=item["value_cents"],
                               session_id=sess["session_id"])
    return {"status": "transferred", "item": item, "to": to_email}
