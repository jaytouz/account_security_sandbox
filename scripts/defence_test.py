"""Checks each defence switch on its own: turn it on, confirm its exact effect, turn it off.

    docker compose exec runner python scripts/defence_test.py

Uses fresh fake accounts, tags events with run_id 'defence-test-*', and
restores your defence switches at the end.
"""
import json
import re
import secrets
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scenarios.base import ADMIN_TOKEN, APP_URL, Run, Scenario  # noqa: E402
from scenarios.client import LabClient, datacenter, home  # noqa: E402

MAILPIT = "http://mail:8025"
admin = LabClient(APP_URL, "defence-test", admin_token=ADMIN_TOKEN)
run = Run(Scenario(name="defence-test", title="", summary="", goal="", signals="",
                   expected_alerts=[], countered_by=[]))
failures = 0


def check(label, cond, extra=""):
    global failures
    print(("ok    " if cond else "FAIL  ") + label + (f"   {extra}" if extra and not cond else ""))
    failures += 0 if cond else 1


def flags() -> dict:
    body = admin.get("/admin/defences").body
    return {f"{s}.{k}": v for s, vals in body.items() if isinstance(vals, dict) for k, v in vals.items()}


def set_flag(flag, value):
    r = admin.put("/admin/defences", {"flag": flag, "enabled": value})
    assert r.status == 200, r.body


class only:
    """with only("lockout.enabled"): ... -> that defence on, every other off."""
    def __init__(self, *names):
        self.names = names

    def __enter__(self):
        for f in flags():
            set_flag(f, f in self.names)

    def __exit__(self, *exc):
        for f in self.names:
            set_flag(f, False)


def latest_mail(to: str, subject_part: str, wait_s: float = 5) -> str:
    deadline = time.time() + wait_s
    while time.time() < deadline:
        q = urllib.parse.quote(f'to:"{to}"')
        with urllib.request.urlopen(f"{MAILPIT}/api/v1/search?query={q}", timeout=5) as r:
            msgs = json.load(r)["messages"]
        for m in msgs:
            if subject_part in m["Subject"]:
                with urllib.request.urlopen(f"{MAILPIT}/api/v1/message/{m['ID']}", timeout=5) as r:
                    return json.load(r)["Text"]
        time.sleep(0.3)
    return ""


original = flags()
try:
    with only("baseline.password_policy"):
        r = run.client(home()).post("/auth/signup", {"email": f"p-{secrets.token_hex(3)}@lab.test",
                                                     "password": "short", "display_name": "x"})
        check("password_policy rejects a short password", r.status == 400 and r.code == "weak_password", r.body)

    with only("breached_passwords.enabled"):
        r = run.client(home()).post("/auth/signup", {"email": f"b-{secrets.token_hex(3)}@lab.test",
                                                     "password": "password123", "display_name": "x"})
        check("breached_passwords rejects 'password123'", r.status == 400 and r.code == "weak_password", r.body)

    with only("baseline.generic_errors"):
        r = run.client(home()).post("/auth/login", {"email": f"nobody-{secrets.token_hex(3)}@lab.test",
                                                    "password": "whatever-123"})
        check("generic_errors hides unknown accounts", r.code == "invalid_credentials", r.body)

    with only("rate_limiting.per_account"):
        v = run.account()
        c = run.client(home())
        for i in range(5):
            c.post("/auth/login", {"email": v.email, "password": f"wrong-{i}"})
        r = c.post("/auth/login", {"email": v.email, "password": v.password})
        check("per_account: right password refused after 5 failures", r.status == 429, r.body)

    with only("rate_limiting.per_ip"):
        c = run.client(datacenter("NL"))
        for i in range(20):
            c.post("/auth/login", {"email": f"ghost-{i}-{run.short}@lab.test", "password": "x" * 12})
        v = run.account()
        r = c.post("/auth/login", {"email": v.email, "password": v.password})
        check("per_ip: IP blocked after 20 failures", r.status == 429, r.body)

    with only("lockout.enabled"):
        v = run.account()
        c = run.client(home())
        for i in range(10):
            c.post("/auth/login", {"email": v.email, "password": f"wrong-{i}"})
        r = c.post("/auth/login", {"email": v.email, "password": v.password})
        check("lockout: locked after 10 wrong passwords", r.status == 403 and r.code == "account_locked", r.body)

    with only("mfa.reauth_for_sensitive"):
        v = run.account()
        c = run.client(home())
        run.login(c, v)
        r = c.post("/account/email", {"new_email": f"re-{run.short}@lab.test", "current_password": v.password})
        check("reauth: email change refused without re-auth", r.status == 403 and r.code == "reauth_required", r.body)
        c.post("/account/reauth", {"password": v.password})
        r = c.post("/account/email", {"new_email": f"re-{run.short}@lab.test", "current_password": v.password})
        check("reauth: allowed after POST /account/reauth", r.ok, r.body)

    with only("session.secure_cookies"):
        v = run.account()
        c = run.client(home())
        run.login(c, v)
        cookie = " ".join(c.last_set_cookies).lower()
        check("secure_cookies: Secure + SameSite=Strict", "secure" in cookie and "samesite=strict" in cookie, cookie)

    with only("session.revoke_on_password_change"):
        v = run.account()
        laptop, phone = run.client(home("CA", "laptop")), run.client(home("CA", "phone"))
        run.login(laptop, v)
        run.login(phone, v)
        laptop.post("/account/password", {"current_password": v.password, "new_password": v.password + "-2"})
        check("revoke_on_password_change: other session ended", phone.get("/auth/me").status == 401)
        check("revoke_on_password_change: current session kept", laptop.get("/auth/me").ok)

    with only("session.bind_to_device"):
        v = run.account()
        owner = run.client(home("CA", "owner"))
        run.login(owner, v)
        thief = run.client(datacenter("RO", "thief"))
        thief.cookies = dict(owner.cookies)
        r = thief.get("/auth/me")
        check("bind_to_device: copied cookie refused", r.status == 401 and r.code == "session_revoked", r.body)

    with only("recovery.block_security_questions"):
        v = run.account(security_answer="paris")
        r = run.client(home()).post("/auth/recover/question/start", {"email": v.email})
        check("block_security_questions: recovery refused", r.status == 403, r.body)

    with only("recovery.notify_on_change"):
        v = run.account()
        c = run.client(home())
        run.login(c, v)
        c.post("/account/password", {"current_password": v.password, "new_password": v.password + "-2"})
        check("notify_on_change: owner emailed", "password was changed" in latest_mail(v.email, "security notice"))

    with only("recovery.trade_cooldown"):
        v, mule = run.account(items=2), run.account("mule")
        c = run.client(home())
        run.login(c, v)
        c.post("/account/email", {"new_email": f"cool-{run.short}@lab.test", "current_password": v.password})
        item = c.get("/inventory").body[0]
        r = c.post("/trades", {"item_id": item["item_id"], "to_email": mule.email})
        check("trade_cooldown: trade refused after email change", r.status == 403 and r.code == "trade_hold", r.body)

    with only("risk.step_up"):
        v = run.account()
        run.login(run.client(home("CA", "owner")), v)
        traveller = run.client(datacenter("RO", "hotel-pc"))
        r = traveller.post("/auth/login", {"email": v.email, "password": v.password})
        check("step_up: risky login asks for a code", r.body.get("status") == "step_up_required", r.body)
        code = re.search(r"\b(\d{6})\b", latest_mail(v.email, "sign-in code"))
        r = traveller.post("/auth/step-up/verify", {"code": code.group(1) if code else "000000"})
        check("step_up: emailed code completes sign-in", r.ok, r.body)
finally:
    for f, v in original.items():
        set_flag(f, v)
    print("Defence switches restored.")

print("PASS" if failures == 0 else f"{failures} FAILED")
sys.exit(1 if failures else 0)
