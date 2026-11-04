"""Scenario framework: registry, per-run context, and the scorecard."""
import json
import os
import secrets
import time
import traceback
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Callable

import psycopg
import pyotp
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .client import LabClient, Origin, Response, check_target

APP_URL = os.environ.get("LAB_APP_URL", "http://app:8000")
ADMIN_TOKEN = os.environ.get("LAB_ADMIN_TOKEN", "")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
RP_ID = os.environ.get("WEBAUTHN_RP_ID", "localhost")
RP_ORIGIN = os.environ.get("WEBAUTHN_ORIGIN", "http://localhost:8000")
MONITOR_WAIT_S = 20


@dataclass
class Scenario:
    name: str
    title: str
    summary: str             # what happens, in plain words
    goal: str                # what the simulated attacker wants
    signals: str             # what it should leave in telemetry
    expected_alerts: list    # rules that should fire with monitoring on and defences off
    countered_by: list       # defence flags that should stop it
    baseline_goal: bool = True   # does the goal succeed with every defence off?
    fn: Callable = field(default=None, repr=False)

    def meta(self) -> dict:
        d = asdict(self)
        d.pop("fn")
        return d


REGISTRY: dict[str, Scenario] = {}


def scenario(**meta):
    def deco(fn):
        REGISTRY[meta["name"]] = Scenario(fn=fn, **meta)
        return fn
    return deco


@dataclass
class Account:
    email: str
    password: str
    account_id: str
    totp_secret: str | None = None
    security_answer: str | None = None


class Run:
    """Everything one scenario run needs: clients, fixtures, notes and the attacker's outcome."""

    def __init__(self, sc: Scenario):
        self.scenario = sc
        self.run_id = f"{sc.name}-{secrets.token_hex(3)}"
        self.short = self.run_id.rsplit("-", 1)[1]
        self.blocked: Counter = Counter()
        self.steps: list[str] = []
        self.goal_reached = False
        self.goal_detail = ""
        self._n = 0

    # -- clients
    def client(self, origin: Origin) -> LabClient:
        return LabClient(APP_URL, self.run_id, origin)

    def _admin(self) -> LabClient:
        return LabClient(APP_URL, self.run_id, admin_token=ADMIN_TOKEN)

    # -- fixtures
    def account(self, label: str = "victim", *, totp=False, items=0, security_answer=None) -> Account:
        self._n += 1
        email = f"{label}-{self.short}-{self._n}@lab.test"
        password = secrets.token_urlsafe(12)
        r = self._admin().post("/admin/fixtures/account", {
            "email": email, "password": password, "display_name": f"Scenario {label}",
            "totp": totp, "items": items, "security_answer": security_answer})
        if r.status != 201:
            raise RuntimeError(f"Fixture creation failed: {r.status} {r.body}")
        return Account(email, password, r.body["account_id"], r.body.get("totp_secret"), security_answer)

    # -- common flows
    def login(self, c: LabClient, acct: Account, password: str | None = None) -> Response:
        """Password login, completing the TOTP step when we hold the secret (the real owner does)."""
        r = c.post("/auth/login", {"email": acct.email, "password": password or acct.password})
        if r.ok and r.code == "mfa_required" and acct.totp_secret and password is None:
            r = c.post("/auth/mfa/verify", {"code": pyotp.TOTP(acct.totp_secret).now()})
        return r

    def attacker(self, r: Response) -> bool:
        """Record a step taken by the simulated attacker; count it if a defence stopped it."""
        if not r.ok:
            self.blocked[r.code or str(r.status)] += 1
        elif isinstance(r.body, dict) and r.body.get("status") in ("step_up_required", "mfa_required"):
            self.blocked[r.body["status"]] += 1
        return r.ok and not (isinstance(r.body, dict) and r.body.get("status") in ("step_up_required", "mfa_required"))

    def note(self, text: str) -> None:
        self.steps.append(text)

    def goal(self, reached: bool, detail: str) -> None:
        self.goal_reached, self.goal_detail = reached, detail


# ---------------------------------------------------------------- running and scoring
def _flat_defences() -> dict:
    r = LabClient(APP_URL, "defences-read").get("/defences")
    out = {}
    for section, values in (r.body or {}).items():
        if isinstance(values, dict):
            for k, v in values.items():
                if isinstance(v, bool):
                    out[f"{section}.{k}"] = v
    return out


def _jsonb(obj) -> Jsonb:
    return Jsonb(obj, dumps=lambda o: json.dumps(o, default=str))


def _verdict(status, reached, monitoring, fired) -> str:
    if status == "error":
        return "Scenario error: see the steps"
    if reached and fired:
        return "Attack succeeded, and was detected"
    if reached and not monitoring:
        return "Attack succeeded, unseen: monitoring is off"
    if reached:
        return "Attack succeeded, and was NOT detected"
    if fired:
        return "Attack blocked, and detected"
    return "Attack blocked"


def run_scenario(name: str, log=print) -> dict:
    check_target(APP_URL)
    if name not in REGISTRY:
        raise KeyError(f"Unknown scenario {name!r}. Try: {', '.join(REGISTRY)}")
    sc = REGISTRY[name]
    run = Run(sc)
    defences = _flat_defences()
    monitoring = defences.get("monitoring.enabled", False)

    with psycopg.connect(DATABASE_URL, autocommit=True, row_factory=dict_row) as db:
        db.execute("INSERT INTO telemetry.scenario_run (run_id, scenario, defences) VALUES (%s, %s, %s)",
                   (run.run_id, name, _jsonb(defences)))
        log(f"> {sc.title}  [{run.run_id}]")
        status = "completed"
        t0 = time.monotonic()
        try:
            sc.fn(run)
        except Exception as exc:  # noqa: BLE001 - recorded in the scorecard
            status = "error"
            run.note(f"ERROR: {exc!r}")
            log(traceback.format_exc())
        duration = round(time.monotonic() - t0, 1)
        finished = db.execute("SELECT clock_timestamp() AS t").fetchone()["t"]

        if monitoring:
            deadline = time.monotonic() + MONITOR_WAIT_S
            while time.monotonic() < deadline:
                st = db.execute("SELECT last_eval_at FROM telemetry.monitor_state WHERE id = 1").fetchone()
                if st and st["last_eval_at"] and st["last_eval_at"] > finished:
                    break
                time.sleep(0.5)
            else:
                run.note("Monitoring did not report back in time; alert results may be incomplete.")

        logins = {r["result"]: r["n"] for r in db.execute(
            "SELECT result, count(*) AS n FROM telemetry.login_event WHERE run_id = %s GROUP BY 1 ORDER BY 2 DESC",
            (run.run_id,))}
        fired = sorted({r["rule_id"] for r in db.execute(
            "SELECT DISTINCT rule_id FROM telemetry.alert WHERE run_id = %s", (run.run_id,))})
        expected = list(sc.expected_alerts)
        card = {
            "scenario": name,
            "title": sc.title,
            "run_id": run.run_id,
            "status": status,
            "duration_s": duration,
            "monitoring": monitoring,
            "defences_on": sorted(k for k, v in defences.items() if v),
            "goal": {"description": sc.goal, "reached": run.goal_reached, "detail": run.goal_detail},
            "blocked": dict(run.blocked),
            "login_results": logins,
            "alerts": {"expected": expected, "fired": fired,
                       "missing": [a for a in expected if a not in fired] if monitoring else [],
                       "unexpected": [a for a in fired if a not in expected]},
            "steps": run.steps,
        }
        card["verdict"] = _verdict(status, run.goal_reached, monitoring, fired)
        db.execute("UPDATE telemetry.scenario_run SET finished_at = %s, status = %s, scorecard = %s WHERE run_id = %s",
                   (finished, status, _jsonb(card), run.run_id))
    return card


def format_card(card: dict) -> str:
    a = card["alerts"]
    lines = [
        f"  verdict   {card['verdict']}",
        f"  goal      {card['goal']['description']}: {'REACHED' if card['goal']['reached'] else 'blocked'}"
        + (f" ({card['goal']['detail']})" if card["goal"]["detail"] else ""),
        f"  defences  {', '.join(card['defences_on']) or 'none'}",
        f"  blocked   {', '.join(f'{k} x{v}' for k, v in card['blocked'].items()) or 'nothing'}",
        f"  logins    {', '.join(f'{k} x{v}' for k, v in card['login_results'].items()) or 'none'}",
        f"  alerts    fired: {', '.join(a['fired']) or 'none'}"
        + ("" if card["monitoring"] else "  (monitoring off)"),
    ]
    if a["missing"]:
        lines.append(f"            missing: {', '.join(a['missing'])}")
    lines.append(f"  run_id    {card['run_id']}  ({card['duration_s']}s)")
    return "\n".join(lines)
