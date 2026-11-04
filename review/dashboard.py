"""Account Lab review dashboard.

Reads telemetry through the read-only lab_review role. Every action (lock,
revoke, force reset, defence switches) goes through the app's /admin API.
"""
import pandas as pd
import streamlit as st

import admin_api
import queries as q

st.set_page_config(page_title="Account Lab · Review", layout="wide")

# label -> (look-back window, chart bucket)
WINDOWS = {
    "15 minutes": ("15 minutes", "1 minute"),
    "1 hour": ("1 hour", "2 minutes"),
    "6 hours": ("6 hours", "10 minutes"),
    "24 hours": ("24 hours", "30 minutes"),
    "7 days": ("7 days", "6 hours"),
}
KINDS = ["login", "session", "change", "transfer", "alert"]
OUTCOME_COLOURS = {"success": "#2e7d32", "failed": "#c62828", "MFA step": "#f9a825"}
SEVERITIES = ["critical", "high", "medium", "low"]
DEFENCE_HELP = {
    "baseline.password_policy": "At least 12 characters, and must not contain the email name.",
    "baseline.generic_errors": "Same reply for unknown accounts and wrong passwords, "
                               "and for reset requests on unknown emails.",
}


def flash(key: str) -> None:
    if msg := st.session_state.pop(key, None):
        st.success(msg)


# ---------------------------------------------------------------- sidebar
with st.sidebar:
    st.title("Account Lab")
    st.caption("Review dashboard · synthetic data only")
    try:
        run_ids = q.run_ids()
    except Exception as exc:  # noqa: BLE001 - show any DB problem to the user
        st.error(f"Can't read the lab database: {exc}")
        st.stop()
    window_label = st.selectbox("Time window", list(WINDOWS), index=1)
    window, bucket = WINDOWS[window_label]
    run_choice = st.selectbox("Run", ["All events", "Untagged only", *run_ids],
                              help="Scenario runs and the smoke test tag their events with a run id.")
    run = None if run_choice == "All events" else "" if run_choice == "Untagged only" else run_choice
    auto = st.toggle("Auto-refresh live view (5 s)", value=True)
    st.caption("Times are UTC.")

live_tab, accounts_tab, alerts_tab, runs_tab, defences_tab = st.tabs(
    ["Live", "Accounts", "Alerts", "Runs", "Defences"])


# ---------------------------------------------------------------- live
def live_view() -> None:
    k = q.kpis(window, run)
    c = st.columns(6)
    c[0].metric("Login attempts", k["attempts"])
    c[1].metric("Failed", k["failures"])
    c[2].metric("Succeeded", k["successes"])
    c[3].metric("Source IPs", k["source_ips"])
    c[4].metric("Transfers", k["transfers"], help=f"${int(k['transfer_cents']) / 100:,.2f} moved")
    c[5].metric("Alerts", k["alerts"])

    left, right = st.columns([3, 2])
    with left:
        st.subheader("Login outcomes")
        chart = q.login_outcomes(window, bucket, run)
        if chart.empty:
            st.info("No login attempts in this window.")
        else:
            # Streamlit assigns colours to series in sorted name order.
            colours = [OUTCOME_COLOURS[c] for c in sorted(chart.columns)]
            st.bar_chart(chart[sorted(chart.columns)], color=colours, y_label="attempts", height=280)
    with right:
        st.subheader("Most failed accounts")
        top = q.top_failing_accounts(window, run)
        if top.empty:
            st.caption("No failed logins in this window.")
        else:
            st.dataframe(top, hide_index=True, use_container_width=True)

    st.subheader("Event feed")
    kinds = st.multiselect("Show", KINDS, default=KINDS, label_visibility="collapsed")
    events = q.feed(window, run, kinds or KINDS)
    if events.empty:
        st.caption("Nothing happened in this window.")
    else:
        st.dataframe(events, hide_index=True, use_container_width=True, height=420)


with live_tab:
    st.fragment(run_every="5s" if auto else None)(live_view)()


# ---------------------------------------------------------------- accounts
def act(fn, account_id: str, done: str) -> None:
    try:
        r = fn(account_id)
    except admin_api.AdminError as exc:
        st.error(f"Action failed: {exc}")
        return
    ended = r.get("sessions_revoked")
    st.session_state["flash_acct"] = done + (f" {ended} session(s) ended." if ended is not None else "")
    st.rerun()


def confirm(label: str, text: str, key: str, fn, account_id: str, done: str) -> None:
    with st.popover(label, use_container_width=True):
        st.write(text)
        if st.button("Confirm", type="primary", key=key):
            act(fn, account_id, done)


with accounts_tab:
    flash("flash_acct")
    accts = q.accounts()
    if accts.empty:
        st.info("No accounts yet. Seed some with: docker compose run --rm seed")
    else:
        names = {r.account_id: r.email + ("  (locked)" if r.status != "active" else "")
                 for r in accts.itertuples()}
        account_id = st.selectbox("Account", accts["account_id"], format_func=names.get,
                                  help="Accounts with the most recent activity come first.")
        acct = accts.set_index("account_id").loc[account_id]
        s = q.account_summary(account_id, window)

        c = st.columns(5)
        c[0].metric("Status", acct["status"])
        c[1].metric("MFA", "on" if acct["totp_enabled"] else "off")
        c[2].metric("Live sessions", s["live_sessions"])
        c[3].metric(f"Failed logins ({window_label})", s["failures"])
        c[4].metric("Last login (UTC)", s["last_login"] or "never")

        st.markdown("**Respond**")
        b = st.columns(3)
        with b[0]:
            if acct["status"] == "active":
                confirm("Lock account", "Blocks logins and ends every live session.",
                        "lock", admin_api.lock, account_id, "Account locked.")
            else:
                confirm("Unlock account", "Allows logins again. Sessions stay ended.",
                        "unlock", admin_api.unlock, account_id, "Account unlocked.")
        with b[1]:
            confirm("Revoke sessions", "Ends every live session. The password stays the same.",
                    "revoke", admin_api.revoke_sessions, account_id, "Sessions revoked.")
        with b[2]:
            confirm("Force password reset",
                    "Replaces the password with a random one, ends every session, and emails a "
                    "reset token (see Mailpit at 127.0.0.1:8025).",
                    "reset", admin_api.force_reset, account_id, "Password reset forced.")

        st.subheader("Live sessions")
        sessions = q.live_sessions(account_id)
        if sessions.empty:
            st.caption("No live sessions.")
        else:
            st.dataframe(sessions, hide_index=True, use_container_width=True)

        st.subheader("Timeline")
        timeline = q.account_timeline(account_id)
        if timeline.empty:
            st.caption("No events for this account yet.")
        else:
            st.dataframe(timeline, hide_index=True, use_container_width=True, height=420)


# ---------------------------------------------------------------- alerts
with alerts_tab:
    alerts = q.alerts(window, run)
    counts = alerts["severity"].value_counts() if not alerts.empty else pd.Series(dtype=int)
    c = st.columns(4)
    for i, sev in enumerate(SEVERITIES):
        c[i].metric(sev.capitalize(), int(counts.get(sev, 0)))
    if alerts.empty:
        st.info("No alerts in this window. Monitoring rules that raise alerts arrive in Phase 4.")
    else:
        pick = st.multiselect("Severity", SEVERITIES, default=SEVERITIES)
        st.dataframe(alerts[alerts["severity"].isin(pick)], hide_index=True, use_container_width=True)


# ---------------------------------------------------------------- runs
with runs_tab:
    runs = q.runs()
    if runs.empty:
        st.info("No tagged runs yet. Scenario runs (Phase 3) and the smoke test tag their events.")
    else:
        st.dataframe(runs, hide_index=True, use_container_width=True)

        st.subheader("Compare two runs")
        ids = runs["run_id"].tolist()
        c1, c2 = st.columns(2)
        run_a = c1.selectbox("Run A", ids, index=min(1, len(ids) - 1))
        run_b = c2.selectbox("Run B", ids, index=0)

        merged = pd.merge(q.run_breakdown(run_a).rename(columns={"n": "A"}),
                          q.run_breakdown(run_b).rename(columns={"n": "B"}),
                          on="metric", how="outer")
        merged[["A", "B"]] = merged[["A", "B"]].fillna(0).astype(int)
        merged["B − A"] = merged["B"] - merged["A"]
        st.dataframe(merged.sort_values("metric"), hide_index=True, use_container_width=True)

        st.markdown("**Defences at the start of each run**")
        defs = pd.merge(q.defences_at_run_start(run_a).rename(columns={"enabled": "A"}),
                        q.defences_at_run_start(run_b).rename(columns={"enabled": "B"}),
                        on="flag", how="outer")
        if defs.empty:
            st.caption("No defence history recorded before these runs.")
        else:
            for col in ("A", "B"):
                defs[col] = defs[col].map({True: "on", False: "off"}).fillna("unknown")
            st.dataframe(defs, hide_index=True, use_container_width=True)


# ---------------------------------------------------------------- defences
def flip_defence(path: str) -> None:
    """Toggle callback: runs once per click, before the script reruns."""
    new = st.session_state[f"flag:{path}"]
    try:
        admin_api.set_defence(path, new)
        st.session_state["flash_def"] = f"{path} turned {'on' if new else 'off'}."
    except admin_api.AdminError as exc:
        st.session_state["flash_def_error"] = f"Couldn't change {path}: {exc}"


with defences_tab:
    flash("flash_def")
    try:
        current = admin_api.defences()
    except admin_api.AdminError as exc:
        st.error(f"Can't read defences from the app: {exc}")
        current = {}

    if err := st.session_state.pop("flash_def_error", None):
        st.error(err)

    for section, flags in current.items():
        if not isinstance(flags, dict):
            continue
        st.subheader(section.replace("_", " ").capitalize())
        for key, value in flags.items():
            if not isinstance(value, bool):
                continue
            path = f"{section}.{key}"
            widget_key = f"flag:{path}"
            # Always show the value the app reports, not a stale widget state.
            st.session_state[widget_key] = value
            st.toggle(key.replace("_", " ").capitalize(), key=widget_key, on_change=flip_defence,
                      args=(path,), help=DEFENCE_HELP.get(path, path))

    st.caption("Changes apply from the app's next request and are logged below. "
               "More defences arrive in Phase 4.")
    st.subheader("Change history")
    history = q.defence_history()
    if history.empty:
        st.caption("No changes recorded yet.")
    else:
        st.dataframe(history, hide_index=True, use_container_width=True)
