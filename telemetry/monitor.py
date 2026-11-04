"""Monitoring service: reads recent telemetry every 2 seconds and raises alerts.

    python -m telemetry.monitor            # run forever (the `monitor` service)
    python -m telemetry.monitor --once     # one pass
    python -m telemetry.monitor --rules    # list the rules

Only raises alerts while monitoring.enabled is on in app/security/config.yaml.
Each rule looks back 10 minutes. The same rule never fires twice for the same
subject (account, IP or session) within 30 minutes.
"""
import argparse
import json
import logging
import math
import os
import time
from dataclasses import dataclass
from typing import Callable, Iterable

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from app.security import flags

log = logging.getLogger("lab.monitor")

INTERVAL_S = 2.0
LOOKBACK = "10 minutes"
DEDUP = "30 minutes"
FAILED = ["bad_password", "unknown_account", "rate_limited", "password_disabled", "locked"]
PASSWORD_KNOWN = ["success", "mfa_required", "step_up"]
SENSITIVE = ["email_change", "password_reset", "recovery_security_question", "mfa_disabled"]


@dataclass
class Rule:
    rule_id: str
    severity: str
    description: str
    fn: Callable[[psycopg.Connection], Iterable[dict]]


RULES: list[Rule] = []


def rule(rule_id: str, severity: str, description: str):
    def deco(fn):
        RULES.append(Rule(rule_id, severity, description, fn))
        return fn
    return deco


def _km(lat1, lon1, lat2, lon2) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 6371 * 2 * math.asin(math.sqrt(a))


# ---------------------------------------------------------------- rules
@rule("stuffing_many_accounts_one_ip", "high",
      "One IP failed logins on 6 or more different accounts in 10 minutes (credential stuffing).")
def _stuffing(conn):
    for r in conn.execute(f"""
            SELECT host(ip) AS ip, count(DISTINCT coalesce(account_id::text, email_attempted)) AS accounts,
                   count(*) AS attempts, max(run_id) AS run_id
              FROM telemetry.login_event
             WHERE ts > now() - interval '{LOOKBACK}' AND ip IS NOT NULL AND result = ANY(%s)
             GROUP BY ip HAVING count(DISTINCT coalesce(account_id::text, email_attempted)) >= 6""", (FAILED,)):
        yield {"subject": f"ip:{r['ip']}", "run_id": r["run_id"], "evidence": r}


@rule("guessing_one_account", "medium",
      "8 or more failed or blocked password attempts on one account in 10 minutes (password guessing).")
def _guessing(conn):
    for r in conn.execute(f"""
            SELECT account_id, min(email_attempted) AS email, count(*) AS attempts,
                   count(DISTINCT ip) AS ips, max(run_id) AS run_id
              FROM telemetry.login_event
             WHERE ts > now() - interval '{LOOKBACK}' AND account_id IS NOT NULL
               AND result IN ('bad_password', 'rate_limited', 'locked')
             GROUP BY account_id HAVING count(*) >= 8"""):
        yield {"subject": f"account:{r['account_id']}", "account_id": r["account_id"], "run_id": r["run_id"],
               "evidence": r}


@rule("success_after_failures", "high",
      "A login got the password right after 5+ wrong passwords on the same account in 15 minutes.")
def _success_after_failures(conn):
    for r in conn.execute(f"""
            SELECT s.account_id, s.email_attempted AS email, s.result, host(s.ip) AS ip, s.run_id,
                   (SELECT count(*) FROM telemetry.login_event f
                     WHERE f.account_id = s.account_id AND f.result = 'bad_password'
                       AND f.ts BETWEEN s.ts - interval '15 minutes' AND s.ts) AS failures_before
              FROM telemetry.login_event s
             WHERE s.ts > now() - interval '{LOOKBACK}' AND s.account_id IS NOT NULL
               AND s.result = ANY(%s)""", (PASSWORD_KNOWN,)):
        if r["failures_before"] >= 5:
            yield {"subject": f"account:{r['account_id']}", "account_id": r["account_id"],
                   "run_id": r["run_id"], "evidence": r}


@rule("impossible_travel", "high",
      "Two password-correct logins on one account too far apart to travel between (over 900 km/h).")
def _impossible_travel(conn):
    for r in conn.execute(f"""
            SELECT b.account_id, b.email_attempted AS email, b.run_id,
                   a.geo_country AS from_country, a.geo_lat AS lat1, a.geo_lon AS lon1,
                   b.geo_country AS to_country, b.geo_lat AS lat2, b.geo_lon AS lon2,
                   extract(epoch FROM b.ts - a.ts) AS seconds
              FROM telemetry.login_event b
              JOIN LATERAL (
                    SELECT * FROM telemetry.login_event a
                     WHERE a.account_id = b.account_id AND a.ts < b.ts AND a.ts > b.ts - interval '6 hours'
                       AND a.result = ANY(%(known)s) AND a.geo_lat IS NOT NULL
                     ORDER BY a.ts DESC LIMIT 1) a ON true
             WHERE b.ts > now() - interval '{LOOKBACK}' AND b.result = ANY(%(known)s)
               AND b.geo_lat IS NOT NULL AND b.account_id IS NOT NULL""", {"known": PASSWORD_KNOWN}):
        km = _km(r["lat1"], r["lon1"], r["lat2"], r["lon2"])
        kmh = km / (max(float(r["seconds"]), 1.0) / 3600)
        if km > 500 and kmh > 900:
            yield {"subject": f"account:{r['account_id']}", "account_id": r["account_id"], "run_id": r["run_id"],
                   "evidence": {"email": r["email"], "from": r["from_country"], "to": r["to_country"],
                                "km": round(km), "seconds": round(float(r["seconds"]), 1), "kmh": round(kmh)}}


@rule("new_device_new_country", "medium",
      "Password-correct login from a device and a country never seen on this account before.")
def _new_device_new_country(conn):
    for r in conn.execute(f"""
            SELECT b.account_id, b.email_attempted AS email, b.result, b.geo_country AS country,
                   left(b.device_fp, 8) AS device, host(b.ip) AS ip, b.ip_type, b.run_id
              FROM telemetry.login_event b
             WHERE b.ts > now() - interval '{LOOKBACK}' AND b.result = ANY(%(known)s)
               AND b.account_id IS NOT NULL AND b.geo_country IS NOT NULL
               AND EXISTS (SELECT 1 FROM telemetry.login_event a
                            WHERE a.account_id = b.account_id AND a.result = 'success' AND a.ts < b.ts)
               AND NOT EXISTS (SELECT 1 FROM telemetry.login_event a
                                WHERE a.account_id = b.account_id AND a.result = 'success' AND a.ts < b.ts
                                  AND (a.device_fp = b.device_fp OR a.geo_country = b.geo_country))""",
                             {"known": PASSWORD_KNOWN}):
        yield {"subject": f"account:{r['account_id']}", "account_id": r["account_id"], "run_id": r["run_id"],
               "evidence": r}


@rule("password_on_passkey_account", "medium",
      "Someone tried a password on a passkey-only account: the old password is probably known.")
def _password_on_passkey_account(conn):
    for r in conn.execute(f"""
            SELECT account_id, min(email_attempted) AS email, count(*) AS attempts,
                   array_agg(DISTINCT host(ip)) AS ips, max(run_id) AS run_id
              FROM telemetry.login_event
             WHERE ts > now() - interval '{LOOKBACK}' AND result = 'password_disabled' AND account_id IS NOT NULL
             GROUP BY account_id"""):
        yield {"subject": f"account:{r['account_id']}", "account_id": r["account_id"], "run_id": r["run_id"],
               "evidence": r}


@rule("session_hijack_suspected", "critical",
      "A session was used from a device other than the one that created it.")
def _session_hijack(conn):
    for r in conn.execute(f"""
            SELECT session_id, account_id, count(*) AS requests, max(run_id) AS run_id,
                   array_agg(DISTINCT left(device_fp, 8)) AS devices,
                   min(left(expected_device_fp, 8)) AS expected_device,
                   array_agg(DISTINCT host(ip)) AS ips
              FROM telemetry.session_event
             WHERE ts > now() - interval '{LOOKBACK}' AND kind = 'device_mismatch'
             GROUP BY session_id, account_id"""):
        yield {"subject": f"session:{r['session_id']}", "account_id": r["account_id"], "run_id": r["run_id"],
               "evidence": r}


@rule("mfa_fail_burst", "high",
      "5 or more wrong second-step codes on one account in 10 minutes: the password is likely known.")
def _mfa_fail_burst(conn):
    for r in conn.execute(f"""
            SELECT account_id, min(email_attempted) AS email, count(*) AS wrong_codes, max(run_id) AS run_id
              FROM telemetry.login_event
             WHERE ts > now() - interval '{LOOKBACK}' AND result = 'mfa_fail' AND account_id IS NOT NULL
             GROUP BY account_id HAVING count(*) >= 5"""):
        yield {"subject": f"account:{r['account_id']}", "account_id": r["account_id"], "run_id": r["run_id"],
               "evidence": r}


@rule("reset_burst", "medium",
      "5+ password-reset requests for one account, or 8+ from one IP, in 10 minutes.")
def _reset_burst(conn):
    for r in conn.execute(f"""
            SELECT account_id, min(email_attempted) AS email, count(*) AS requests, max(run_id) AS run_id
              FROM telemetry.recovery_event
             WHERE ts > now() - interval '{LOOKBACK}' AND kind = 'reset_request' AND account_id IS NOT NULL
             GROUP BY account_id HAVING count(*) >= 5"""):
        yield {"subject": f"account:{r['account_id']}", "account_id": r["account_id"], "run_id": r["run_id"],
               "evidence": r}
    for r in conn.execute(f"""
            SELECT host(ip) AS ip, count(*) AS requests, count(DISTINCT email_attempted) AS emails,
                   max(run_id) AS run_id
              FROM telemetry.recovery_event
             WHERE ts > now() - interval '{LOOKBACK}' AND kind = 'reset_request' AND ip IS NOT NULL
             GROUP BY ip HAVING count(*) >= 8"""):
        yield {"subject": f"ip:{r['ip']}", "run_id": r["run_id"], "evidence": r}


@rule("recovery_then_change", "high",
      "Email or MFA changed within 30 minutes of a password recovery: a classic takeover sequence.")
def _recovery_then_change(conn):
    for r in conn.execute(f"""
            SELECT c.account_id, c.change_type, r.change_type AS after_recovery, c.run_id,
                   extract(epoch FROM c.ts - r.ts)::int AS seconds_after
              FROM telemetry.account_change c
              JOIN LATERAL (
                    SELECT change_type, ts FROM telemetry.account_change r
                     WHERE r.account_id = c.account_id
                       AND r.change_type IN ('password_reset', 'recovery_security_question')
                       AND r.ts <= c.ts AND r.ts > c.ts - interval '30 minutes'
                     ORDER BY r.ts DESC LIMIT 1) r ON true
             WHERE c.ts > now() - interval '{LOOKBACK}'
               AND c.change_type IN ('email_change', 'mfa_disabled', 'security_question_changed')"""):
        yield {"subject": f"account:{r['account_id']}", "account_id": r["account_id"], "run_id": r["run_id"],
               "evidence": r}


@rule("asset_outflow_burst", "high",
      "4+ transfers or $500+ out of one account in 10 minutes. Critical after a sensitive change "
      "or a session anomaly.")
def _asset_outflow(conn):
    for r in conn.execute(f"""
            SELECT t.account_id, count(*) AS transfers, sum(t.asset_value_cents) AS cents,
                   count(DISTINCT t.counterparty) AS recipients, max(t.run_id) AS run_id,
                   EXISTS (SELECT 1 FROM telemetry.account_change c
                            WHERE c.account_id = t.account_id AND c.change_type = ANY(%(sensitive)s)
                              AND c.ts > now() - interval '60 minutes') AS after_sensitive_change,
                   EXISTS (SELECT 1 FROM telemetry.session_event e
                            WHERE e.account_id = t.account_id AND e.ts > now() - interval '60 minutes')
                       AS session_anomaly
              FROM telemetry.asset_transfer t
             WHERE t.ts > now() - interval '{LOOKBACK}'
             GROUP BY t.account_id
            HAVING count(*) >= 4 OR sum(t.asset_value_cents) >= 50000""", {"sensitive": SENSITIVE}):
        critical = r["after_sensitive_change"] or r["session_anomaly"]
        yield {"subject": f"account:{r['account_id']}", "account_id": r["account_id"], "run_id": r["run_id"],
               "severity": "critical" if critical else None, "evidence": r}


@rule("security_question_recovery", "medium",
      "A password was reset with a security question (weak recovery path used).")
def _security_question_recovery(conn):
    for r in conn.execute(f"""
            SELECT account_id, max(run_id) AS run_id, count(*) AS recoveries, host(max(ip)) AS ip
              FROM telemetry.account_change
             WHERE ts > now() - interval '{LOOKBACK}' AND change_type = 'recovery_security_question'
             GROUP BY account_id"""):
        yield {"subject": f"account:{r['account_id']}", "account_id": r["account_id"], "run_id": r["run_id"],
               "evidence": r}


@rule("recovery_answer_guessing", "medium",
      "3 or more wrong security-question answers on one account in 10 minutes.")
def _recovery_guessing(conn):
    for r in conn.execute(f"""
            SELECT account_id, min(email_attempted) AS email, count(*) AS wrong_answers, max(run_id) AS run_id
              FROM telemetry.recovery_event
             WHERE ts > now() - interval '{LOOKBACK}' AND kind = 'question_answer'
               AND result IN ('wrong', 'rate_limited') AND account_id IS NOT NULL
             GROUP BY account_id HAVING count(*) >= 3"""):
        yield {"subject": f"account:{r['account_id']}", "account_id": r["account_id"], "run_id": r["run_id"],
               "evidence": r}


# ---------------------------------------------------------------- engine
def _jsonb(obj) -> Jsonb:
    return Jsonb(obj, dumps=lambda o: json.dumps(o, default=str))


def _fire(conn, r: Rule, hit: dict) -> bool:
    subject = hit["subject"]
    if conn.execute(
            "SELECT 1 FROM telemetry.alert WHERE rule_id = %s AND subject = %s AND ts > now() - %s::interval",
            (r.rule_id, subject, DEDUP)).fetchone():
        return False
    conn.execute(
        """INSERT INTO telemetry.alert (rule_id, severity, account_id, run_id, subject, evidence)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (r.rule_id, hit.get("severity") or r.severity, hit.get("account_id"), hit.get("run_id"), subject,
         _jsonb(hit.get("evidence"))))
    log.info("ALERT %s %s %s", r.severity, r.rule_id, subject)
    return True


def evaluate(conn: psycopg.Connection) -> int:
    started = conn.execute("SELECT clock_timestamp() AS t").fetchone()["t"]
    on = flags.enabled("monitoring.enabled")
    raised = 0
    if on:
        for r in RULES:
            try:
                with conn.transaction():
                    for hit in r.fn(conn):
                        raised += _fire(conn, r, hit)
            except Exception:  # noqa: BLE001 - one broken rule must not stop the others
                log.exception("Rule %s failed", r.rule_id)
    conn.execute(
        """UPDATE telemetry.monitor_state
              SET last_eval_at = %s, enabled = %s, alerts_raised = alerts_raised + %s WHERE id = 1""",
        (started, on, raised))
    conn.commit()
    return raised


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--rules", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")

    if args.rules:
        for r in RULES:
            print(f"{r.rule_id:32} {r.severity:9} {r.description}")
        return

    url = os.environ["DATABASE_URL"]
    while True:
        try:
            with psycopg.connect(url, row_factory=dict_row) as conn:
                log.info("Monitoring %d rules every %.0fs", len(RULES), INTERVAL_S)
                while True:
                    evaluate(conn)
                    if args.once:
                        return
                    time.sleep(INTERVAL_S)
        except psycopg.OperationalError as exc:
            log.warning("Database unavailable (%s); retrying", exc)
            time.sleep(3)


if __name__ == "__main__":
    main()
