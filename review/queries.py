"""SQL behind the dashboard. Times are shown in UTC."""
import pandas as pd

from db import one, query

TS = "to_char({col} AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS.MS')"
FAILED = "result NOT IN ('success', 'mfa_required')"

# One row per thing that happened, across all telemetry tables.
EVENTS = f"""
WITH ev AS (
    SELECT l.ts, 'login' AS kind, l.account_id, l.email_attempted AS account,
           l.result || CASE WHEN l.method <> 'password' THEN ' (' || l.method || ')' ELSE '' END
                    || CASE WHEN l.risk_score > 0 THEN ' · risk ' || l.risk_score || ': '
                                 || array_to_string(l.risk_reasons, ', ') ELSE '' END AS event,
           host(l.ip) AS ip, l.geo_country AS country, left(l.device_fp, 8) AS device, l.run_id
      FROM telemetry.login_event l
    UNION ALL
    SELECT r.ts, 'recovery', r.account_id, r.email_attempted, r.kind || ': ' || r.result,
           host(r.ip), NULL, left(r.device_fp, 8), r.run_id
      FROM telemetry.recovery_event r
    UNION ALL
    SELECT e.ts, 'session', e.account_id, a.email,
           'session used from another device (expected ' || left(e.expected_device_fp, 8) || ')',
           host(e.ip), NULL, left(e.device_fp, 8), e.run_id
      FROM telemetry.session_event e LEFT JOIN app.account a USING (account_id)
    UNION ALL
    SELECT s.started_at, 'session', s.account_id, a.email, 'session started',
           host(s.ip), NULL, left(s.device_fp, 8), s.run_id
      FROM telemetry.session s LEFT JOIN app.account a USING (account_id)
    UNION ALL
    SELECT s.ended_at, 'session', s.account_id, a.email,
           'session ended (' || coalesce(s.end_reason, '?') || ')',
           host(s.ip), NULL, left(s.device_fp, 8), s.run_id
      FROM telemetry.session s LEFT JOIN app.account a USING (account_id)
     WHERE s.ended_at IS NOT NULL
    UNION ALL
    SELECT c.ts, 'change', c.account_id, a.email,
           c.change_type || CASE WHEN c.channel <> 'web' THEN ' (' || c.channel || ')' ELSE '' END,
           host(c.ip), NULL, left(c.device_fp, 8), c.run_id
      FROM telemetry.account_change c LEFT JOIN app.account a USING (account_id)
    UNION ALL
    SELECT t.ts, 'transfer', t.account_id, a.email,
           'sent item #' || t.item_id || ' ($' || to_char(t.asset_value_cents / 100.0, 'FM9999990.00')
           || ') to ' || coalesce(b.email, '?'),
           host(t.ip), NULL, left(t.device_fp, 8), t.run_id
      FROM telemetry.asset_transfer t
      LEFT JOIN app.account a ON a.account_id = t.account_id
      LEFT JOIN app.account b ON b.account_id = t.counterparty
    UNION ALL
    SELECT al.ts, 'alert', al.account_id, a.email, al.severity || ': ' || al.rule_id,
           NULL, NULL, NULL, al.run_id
      FROM telemetry.alert al LEFT JOIN app.account a USING (account_id)
)
"""


def run_clause(run: str | None) -> str:
    """None = all runs, "" = untagged events only, otherwise one run id (as %(run)s)."""
    if run is None:
        return "TRUE"
    if run == "":
        return "run_id IS NULL"
    return "run_id = %(run)s"


def params(window: str, run: str | None) -> dict:
    return {"win": window, "run": run}


def run_ids() -> list[str]:
    df = query("""SELECT run_id FROM telemetry.login_event WHERE run_id IS NOT NULL
                  GROUP BY run_id ORDER BY max(ts) DESC LIMIT 100""")
    return df["run_id"].tolist()


def kpis(window: str, run: str | None) -> dict:
    p, rc = params(window, run), run_clause(run)
    logins = one(f"""
        SELECT count(*) AS attempts,
               count(*) FILTER (WHERE result = 'success') AS successes,
               count(*) FILTER (WHERE {FAILED}) AS failures,
               count(DISTINCT ip) AS source_ips,
               count(DISTINCT coalesce(account_id::text, email_attempted)) FILTER (WHERE {FAILED})
                   AS accounts_failing
          FROM telemetry.login_event
         WHERE ts > now() - %(win)s::interval AND {rc}""", p)
    other = one(f"""
        SELECT (SELECT count(*) FROM telemetry.asset_transfer
                 WHERE ts > now() - %(win)s::interval AND {rc}) AS transfers,
               (SELECT coalesce(sum(asset_value_cents), 0) FROM telemetry.asset_transfer
                 WHERE ts > now() - %(win)s::interval AND {rc}) AS transfer_cents,
               (SELECT count(*) FROM telemetry.account_change
                 WHERE ts > now() - %(win)s::interval AND {rc}) AS changes,
               (SELECT count(*) FROM telemetry.alert
                 WHERE ts > now() - %(win)s::interval AND {rc}) AS alerts""", p)
    return {**logins, **other}


def login_outcomes(window: str, bucket: str, run: str | None) -> pd.DataFrame:
    df = query(f"""
        SELECT date_bin(%(bucket)s::interval, ts, timestamptz '2000-01-01') AS bucket,
               CASE WHEN result = 'success' THEN 'success'
                    WHEN result = 'mfa_required' THEN 'MFA step'
                    ELSE 'failed' END AS outcome,
               count(*) AS n
          FROM telemetry.login_event
         WHERE ts > now() - %(win)s::interval AND {run_clause(run)}
         GROUP BY 1, 2 ORDER BY 1""", {**params(window, run), "bucket": bucket})
    if df.empty:
        return df
    wide = df.pivot_table(index="bucket", columns="outcome", values="n", aggfunc="sum", fill_value=0)
    wide = wide.reindex(columns=["success", "failed", "MFA step"], fill_value=0)
    wide.index = wide.index.tz_convert("UTC").tz_localize(None)
    return wide


def feed(window: str, run: str | None, kinds: list[str], limit: int = 200) -> pd.DataFrame:
    return query(EVENTS + f"""
        SELECT {TS.format(col='ts')} AS "time (UTC)", kind, account, event, ip, country, device, run_id
          FROM ev
         WHERE ts > now() - %(win)s::interval AND {run_clause(run)} AND kind = ANY(%(kinds)s)
         ORDER BY ts DESC LIMIT {int(limit)}""", {**params(window, run), "kinds": kinds})


def top_failing_accounts(window: str, run: str | None) -> pd.DataFrame:
    return query(f"""
        SELECT email_attempted AS account, count(*) AS failures,
               count(DISTINCT ip) AS source_ips,
               {TS.format(col='max(ts)')} AS "last failure (UTC)"
          FROM telemetry.login_event
         WHERE ts > now() - %(win)s::interval AND {run_clause(run)} AND {FAILED}
         GROUP BY 1 ORDER BY 2 DESC LIMIT 10""", params(window, run))


def accounts() -> pd.DataFrame:
    return query("""
        SELECT a.account_id::text AS account_id, a.email, a.display_name, a.status, a.totp_enabled, a.is_seed
          FROM app.account a
          LEFT JOIN LATERAL (SELECT max(ts) AS last_ts FROM telemetry.login_event l
                              WHERE l.account_id = a.account_id) l ON true
         ORDER BY l.last_ts DESC NULLS LAST, a.email""")


def account_summary(account_id: str, window: str) -> dict:
    return one("""
        SELECT (SELECT count(*) FROM app.passkey WHERE account_id = %(id)s) AS passkeys,
               (SELECT password_login_disabled FROM app.account WHERE account_id = %(id)s) AS passkey_only,
               (SELECT to_char(locked_until AT TIME ZONE 'UTC', 'HH24:MI') FROM app.account
                 WHERE account_id = %(id)s AND locked_until > now()) AS locked_until,
               (SELECT to_char(trade_hold_until AT TIME ZONE 'UTC', 'Mon DD HH24:MI') FROM app.account
                 WHERE account_id = %(id)s AND trade_hold_until > now()) AS trade_hold_until,
               (SELECT count(*) FROM app.web_session
                 WHERE account_id = %(id)s AND revoked_at IS NULL AND expires_at > now()) AS live_sessions,
               (SELECT count(*) FROM telemetry.login_event
                 WHERE account_id = %(id)s AND ts > now() - %(win)s::interval
                   AND result NOT IN ('success', 'mfa_required')) AS failures,
               (SELECT to_char(max(ts) AT TIME ZONE 'UTC', 'Mon DD HH24:MI') FROM telemetry.login_event
                 WHERE account_id = %(id)s AND result = 'success') AS last_login""",
               {"id": account_id, "win": window})


def live_sessions(account_id: str) -> pd.DataFrame:
    return query(f"""
        SELECT session_id::text AS session_id, {TS.format(col='created_at')} AS "started (UTC)",
               {TS.format(col='expires_at')} AS "expires (UTC)", left(device_fp, 8) AS device, host(ip) AS ip
          FROM app.web_session
         WHERE account_id = %(id)s AND revoked_at IS NULL AND expires_at > now()
         ORDER BY created_at DESC""", {"id": account_id})


def account_timeline(account_id: str, limit: int = 300) -> pd.DataFrame:
    return query(EVENTS + f"""
        SELECT {TS.format(col='ts')} AS "time (UTC)", kind, event, ip, country, device, run_id
          FROM ev WHERE account_id = %(id)s
         ORDER BY ts DESC LIMIT {int(limit)}""", {"id": account_id})


def alerts(window: str, run: str | None) -> pd.DataFrame:
    return query(f"""
        SELECT {TS.format(col='al.ts')} AS "time (UTC)", al.severity, al.rule_id, al.subject,
               a.email AS account, al.run_id, al.evidence::text AS evidence
          FROM telemetry.alert al LEFT JOIN app.account a USING (account_id)
         WHERE al.ts > now() - %(win)s::interval AND {run_clause(run).replace('run_id', 'al.run_id')}
         ORDER BY al.ts DESC LIMIT 500""", params(window, run))


def runs() -> pd.DataFrame:
    return query(f"""
        WITH r AS (
            SELECT run_id, ts, 'login' AS k, result FROM telemetry.login_event WHERE run_id IS NOT NULL
            UNION ALL SELECT run_id, ts, 'change', NULL FROM telemetry.account_change WHERE run_id IS NOT NULL
            UNION ALL SELECT run_id, ts, 'transfer', NULL FROM telemetry.asset_transfer WHERE run_id IS NOT NULL
            UNION ALL SELECT run_id, ts, 'alert', NULL FROM telemetry.alert WHERE run_id IS NOT NULL
        )
        SELECT run_id, {TS.format(col='min(ts)')} AS "started (UTC)",
               round(extract(epoch FROM max(ts) - min(ts))::numeric, 1) AS "duration (s)",
               count(*) FILTER (WHERE k = 'login') AS logins,
               count(*) FILTER (WHERE k = 'login' AND result = 'success') AS successes,
               count(*) FILTER (WHERE k = 'login' AND result NOT IN ('success', 'mfa_required')) AS failures,
               count(*) FILTER (WHERE k = 'change') AS changes,
               count(*) FILTER (WHERE k = 'transfer') AS transfers,
               count(*) FILTER (WHERE k = 'alert') AS alerts
          FROM r GROUP BY run_id ORDER BY min(ts) DESC LIMIT 200""")


def run_breakdown(run: str) -> pd.DataFrame:
    return query("""
        SELECT 'login: ' || result AS metric, count(*) AS n FROM telemetry.login_event
         WHERE run_id = %(run)s GROUP BY 1
        UNION ALL
        SELECT 'change: ' || change_type, count(*) FROM telemetry.account_change
         WHERE run_id = %(run)s GROUP BY 1
        UNION ALL
        SELECT 'transfers', count(*) FROM telemetry.asset_transfer
         WHERE run_id = %(run)s HAVING count(*) > 0
        UNION ALL
        SELECT 'alert: ' || rule_id, count(*) FROM telemetry.alert
         WHERE run_id = %(run)s GROUP BY 1""", {"run": run})


def scenario_runs(limit: int = 100) -> pd.DataFrame:
    return query(f"""
        SELECT run_id, scenario, {TS.format(col='started_at')} AS "started (UTC)", status,
               (scorecard -> 'goal' ->> 'reached')::boolean AS goal_reached,
               scorecard ->> 'verdict' AS verdict,
               coalesce(jsonb_array_length(scorecard -> 'alerts' -> 'fired'), 0) AS alerts_fired,
               (SELECT count(*) FROM jsonb_each(defences) WHERE value = 'true'::jsonb) AS defences_on,
               scorecard::text AS scorecard
          FROM telemetry.scenario_run ORDER BY started_at DESC LIMIT {int(limit)}""")


def monitor_state() -> dict:
    return one("""SELECT enabled, alerts_raised,
                         round(extract(epoch FROM now() - last_eval_at)::numeric, 1) AS seconds_ago
                    FROM telemetry.monitor_state WHERE id = 1""")


def defences_at_run_start(run: str) -> pd.DataFrame:
    """Defences in force when the run started: the scenario's snapshot, else the change history."""
    snap = query("""SELECT key AS flag, value::text::boolean AS enabled
                      FROM telemetry.scenario_run, jsonb_each(defences)
                     WHERE run_id = %(run)s ORDER BY key""", {"run": run})
    if not snap.empty:
        return snap
    return query("""
        WITH start AS (
            SELECT min(ts) AS t FROM (
                SELECT ts FROM telemetry.login_event WHERE run_id = %(run)s
                UNION ALL SELECT ts FROM telemetry.account_change WHERE run_id = %(run)s) x)
        SELECT DISTINCT ON (flag) flag, enabled
          FROM telemetry.defence_change, start
         WHERE ts <= start.t
         ORDER BY flag, ts DESC""", {"run": run})


def defence_history(limit: int = 100) -> pd.DataFrame:
    return query(f"""
        SELECT {TS.format(col='ts')} AS "time (UTC)", flag, enabled, actor
          FROM telemetry.defence_change ORDER BY ts DESC LIMIT {int(limit)}""")
