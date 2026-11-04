"""End-to-end check of the Phase 1 flows against the local app. Standard library only.

    python scripts/smoke_test.py            # from the host, stack running

Creates its own throwaway accounts (smoke-*@lab.test); does not touch seed data.
"""
import csv
import http.cookiejar
import json
import pathlib
import secrets
import sys
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8000"
RUN_ID = f"smoke-{secrets.token_hex(3)}"


class Client:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def call(self, method, path, body=None, headers=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(BASE + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("X-Lab-Run-Id", RUN_ID)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with self.opener.open(req, timeout=10) as r:
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null")


failures = 0


def check(label, cond, extra=""):
    global failures
    print(("ok    " if cond else "FAIL  ") + label + (f"  {extra}" if extra and not cond else ""))
    failures += 0 if cond else 1


a, b = Client(), Client()
tag = secrets.token_hex(3)
ea, eb = f"smoke-a-{tag}@lab.test", f"smoke-b-{tag}@lab.test"
pw = "correct horse battery staple"

s, r = a.call("GET", "/health"); check("health", s == 200, r)
s, r = a.call("POST", "/auth/signup", {"email": ea, "password": pw, "display_name": "Smoke A"})
check("signup A", s == 201, r)
s, r = b.call("POST", "/auth/signup", {"email": eb, "password": pw, "display_name": "Smoke B"})
check("signup B", s == 201, r)
s, r = a.call("POST", "/auth/signup", {"email": ea, "password": pw, "display_name": "dup"})
check("duplicate signup rejected", s == 409, r)

s, r = a.call("POST", "/auth/login", {"email": ea, "password": "wrong"})
check("bad password rejected", s == 401, r)
s, r = a.call("POST", "/auth/login", {"email": f"nobody-{tag}@lab.test", "password": "x"})
check("unknown account rejected", s == 401, r)

sim = {"X-Lab-Sim-IP": "203.0.113.10", "X-Lab-Sim-ASN": "64500",
       "X-Lab-Sim-IP-Type": "residential", "X-Lab-Sim-Geo": "FR;48.85;2.35",
       "X-Lab-Sim-Device": "smoke-laptop"}
s, r = a.call("POST", "/auth/login", {"email": ea, "password": pw}, sim); check("login A", s == 200, r)
s, r = a.call("GET", "/auth/me"); check("me A", s == 200 and r["email"] == ea, r)
s, r = b.call("GET", "/auth/me"); check("me without session rejected", s == 401, r)

s, r = a.call("POST", "/account/password", {"current_password": pw, "new_password": pw + "!"})
check("password change", s == 200, r)
pw = pw + "!"

# TOTP enrol + login with MFA (computes the code locally if pyotp is installed)
s, r = a.call("POST", "/account/mfa/totp/enroll"); check("totp enroll", s == 200, r)
try:
    import pyotp
    secret = r["secret"]
    s, r = a.call("POST", "/account/mfa/totp/confirm", {"code": pyotp.TOTP(secret).now()})
    check("totp confirm", s == 200, r)
    s, r = a.call("POST", "/auth/logout"); check("logout", s == 200, r)
    s, r = a.call("POST", "/auth/login", {"email": ea, "password": pw})
    check("login asks for MFA", s == 200 and r["status"] == "mfa_required", r)
    s, r = a.call("POST", "/auth/mfa/verify", {"code": "000000"}); check("wrong MFA code rejected", s == 401, r)
    s, r = a.call("POST", "/auth/mfa/verify", {"code": pyotp.TOTP(secret).now()})
    check("MFA verify", s == 200, r)
except ImportError:
    print("skip  TOTP confirm/login (pip install pyotp to include)")

# New accounts own nothing, so trade from a seeded account (if the seed has been run).
seed_csv = pathlib.Path(__file__).resolve().parent.parent / "data" / "out" / "seed_accounts.csv"
seeded = [r for r in csv.DictReader(seed_csv.open())] if seed_csv.exists() else []
donor = next((r for r in seeded if not r["totp_secret"]), None)
if donor:
    d = Client()
    s, r = d.call("POST", "/auth/login", {"email": donor["email"], "password": donor["password"]})
    check("login seeded account", s == 200, r)
    s, inv = d.call("GET", "/inventory"); check("inventory", s == 200, inv)
    if inv:
        s, r = d.call("POST", "/trades", {"item_id": inv[0]["item_id"], "to_email": eb})
        check("trade seeded item to B", s == 201, r)
else:
    print("skip  trade (run the seed first: docker compose run --rm seed)")
s, r = b.call("POST", "/auth/login", {"email": eb, "password": pw.rstrip("!")}); check("login B", s == 200, r)
s, inv = b.call("GET", "/inventory"); check("inventory B", s == 200, inv)
s, r = b.call("POST", "/trades", {"item_id": 2_000_000_000, "to_email": ea})
check("trade of an item you don't own rejected", s == 404, r)

s, r = b.call("POST", "/auth/reset/request", {"email": eb}); check("reset request", s == 202, r)
s, r = b.call("POST", "/auth/reset/confirm", {"token": "not-a-real-token-123", "new_password": "x" * 14})
check("bad reset token rejected", s == 400, r)

print(f"\nrun_id={RUN_ID}  (filter telemetry with: WHERE run_id = '{RUN_ID}')")
print("PASS" if failures == 0 else f"{failures} FAILED")
sys.exit(1 if failures else 0)
