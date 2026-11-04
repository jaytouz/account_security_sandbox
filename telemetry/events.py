"""Write path for telemetry events.

Every function takes the caller's connection so events commit (or roll back)
with the action they describe. `ctx` is the app's RequestContext.
"""
from psycopg import Connection
from psycopg.types.json import Jsonb


def upsert_device(conn: Connection, ctx) -> None:
    c = ctx.device_components
    conn.execute(
        """INSERT INTO telemetry.device_fingerprint (device_fp_id, ua_hash, lang_hash, sim_hash)
           VALUES (%s, %s, %s, %s)
           ON CONFLICT (device_fp_id) DO UPDATE
              SET last_seen = clock_timestamp(),
                  seen_count = telemetry.device_fingerprint.seen_count + 1""",
        (ctx.device_fp, c.get("ua_hash"), c.get("lang_hash"), c.get("sim_hash")),
    )


def record_login(conn: Connection, ctx, *, account_id, email_attempted: str, result: str,
                 mfa_used: bool = False) -> int:
    upsert_device(conn, ctx)
    row = conn.execute(
        """INSERT INTO telemetry.login_event
               (account_id, email_attempted, ip, asn, ip_type, geo_country, geo_lat, geo_lon,
                user_agent, device_fp, mfa_used, result, run_id)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
           RETURNING login_event_id""",
        (account_id, email_attempted, ctx.ip, ctx.asn, ctx.ip_type, ctx.geo_country,
         ctx.geo_lat, ctx.geo_lon, ctx.user_agent, ctx.device_fp, mfa_used, result, ctx.run_id),
    ).fetchone()
    return row["login_event_id"]


def start_session(conn: Connection, ctx, *, session_id, account_id, login_event_id: int) -> None:
    conn.execute(
        """INSERT INTO telemetry.session (session_id, account_id, login_event_id, device_fp, ip, run_id)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (session_id, account_id, login_event_id, ctx.device_fp, ctx.ip, ctx.run_id),
    )


def end_session(conn: Connection, *, session_id, reason: str) -> None:
    conn.execute(
        """UPDATE telemetry.session SET ended_at = clock_timestamp(), end_reason = %s
            WHERE session_id = %s AND ended_at IS NULL""",
        (reason, session_id),
    )


def record_change(conn: Connection, ctx, *, account_id, session_id, change_type: str,
                  channel: str = "web", detail: dict | None = None) -> None:
    conn.execute(
        """INSERT INTO telemetry.account_change
               (account_id, session_id, change_type, channel, ip, device_fp, detail, run_id)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
        (account_id, session_id, change_type, channel, ctx.ip, ctx.device_fp,
         Jsonb(detail) if detail is not None else None, ctx.run_id),
    )


def record_transfer(conn: Connection, ctx, *, account_id, counterparty, item_id: int,
                    value_cents: int, session_id) -> None:
    conn.execute(
        """INSERT INTO telemetry.asset_transfer
               (account_id, counterparty, item_id, asset_value_cents, session_id, ip, device_fp, run_id)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
        (account_id, counterparty, item_id, value_cents, session_id, ctx.ip, ctx.device_fp, ctx.run_id),
    )
