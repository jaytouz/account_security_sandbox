"""The scenarios. Each one creates its own fake @lab.test accounts, plays the
legitimate owner first (so the account has a normal history), then replays a
suspicious pattern from a simulated origin. Everything stays inside the lab.
"""
import random
import secrets
import time

import pyotp

from data.lab_constants import CITIES

from .base import RP_ID, RP_ORIGIN, Run, scenario
from .client import datacenter, home, residential
from .softkey import SoftPasskey


def _trades(run: Run, c, to_email: str, limit: int) -> int:
    """Move up to `limit` items out of the logged-in account. Returns how many moved."""
    inv = c.get("/inventory")
    if not run.attacker(inv):
        return 0
    moved = 0
    for item in inv.body[:limit]:
        if run.attacker(c.post("/trades", {"item_id": item["item_id"], "to_email": to_email})):
            moved += 1
        else:
            break
    return moved


@scenario(
    name="credential_stuffing",
    title="Credential stuffing",
    summary="A list of email/password pairs from 'another site's breach' is tried against 16 accounts "
            "from two datacenter IPs. Four users reused their password there. Spreading the attempts "
            "over two IPs keeps each one under the per-IP rate limit.",
    goal="Get a session on any account",
    signals="Many failed logins from few IPs across many accounts; a few successes from new devices "
            "and countries.",
    expected_alerts=["stuffing_many_accounts_one_ip", "new_device_new_country", "impossible_travel"],
    countered_by=["risk.step_up"],
)
def credential_stuffing(run: Run):
    users = [run.account("user") for _ in range(16)]
    for i, u in enumerate(users):
        run.login(run.client(home("CA", f"home-pc-{i}")), u)
    run.note("16 users signed in normally from home (Montreal).")

    combos = [(u.email, u.password if i < 4 else f"old-{secrets.token_hex(4)}") for i, u in enumerate(users)]
    combos += [(f"ghost-{run.short}-{i}@lab.test", f"old-{secrets.token_hex(4)}") for i in range(4)]
    random.shuffle(combos)
    proxies = [datacenter("NL", "stuffer-1"), datacenter("RO", "stuffer-2")]

    sessions = 0
    for i, (email, password) in enumerate(combos):
        c = run.client(proxies[i % 2])
        r = c.post("/auth/login", {"email": email, "password": password})
        if run.attacker(r):
            sessions += 1
    run.note(f"Tried {len(combos)} leaked pairs from {proxies[0].ip} and {proxies[1].ip}.")
    run.goal(sessions > 0, f"{sessions} session(s) obtained")


@scenario(
    name="password_guessing",
    title="Password guessing",
    summary="Someone tries 12 wrong passwords on one account, then the right one.",
    goal="Sign in to the account",
    signals="A run of bad_password results on one account, then a success.",
    expected_alerts=["guessing_one_account", "success_after_failures"],
    countered_by=["rate_limiting.per_account", "lockout.enabled"],
)
def password_guessing(run: Run):
    victim = run.account()
    run.login(run.client(home("CA", "victim-laptop")), victim)
    run.note("Victim signed in normally from home.")

    c = run.client(residential("CA", "guesser-pc"))
    for i in range(12):
        run.attacker(c.post("/auth/login", {"email": victim.email, "password": f"guess-{i:02d}-{run.short}"}))
    ok = run.attacker(c.post("/auth/login", {"email": victim.email, "password": victim.password}))
    run.note("12 wrong guesses, then the real password.")
    run.goal(ok, "signed in" if ok else "final attempt refused")


@scenario(
    name="mfa_bruteforce",
    title="MFA code guessing",
    summary="The attacker has the password of an account protected by an authenticator app and "
            "tries 8 wrong codes.",
    goal="Get past the second step",
    signals="Password correct from a new place (mfa_required), then a burst of mfa_fail.",
    expected_alerts=["mfa_fail_burst", "new_device_new_country", "impossible_travel"],
    countered_by=["rate_limiting.per_account"],
    baseline_goal=False,
)
def mfa_bruteforce(run: Run):
    victim = run.account(totp=True)
    run.login(run.client(home("CA", "victim-phone")), victim)
    run.note("Victim signed in from home with password + authenticator code.")

    c = run.client(datacenter("RO"))
    r = c.post("/auth/login", {"email": victim.email, "password": victim.password})
    if r.code != "mfa_required":
        run.attacker(r)
        run.goal(False, f"password step refused ({r.code})")
        return
    totp = pyotp.TOTP(victim.totp_secret)
    now = time.time()
    valid = {totp.at(now + d * 30) for d in (-2, -1, 0, 1, 2)}   # never send a code that happens to be valid
    passed = False
    for _ in range(8):
        code = f"{random.randrange(10**6):06d}"
        while code in valid:
            code = f"{random.randrange(10**6):06d}"
        if run.attacker(c.post("/auth/mfa/verify", {"code": code})):
            passed = True
            break
    run.note("Password was right; 8 guessed codes.")
    run.goal(passed, "passed MFA" if passed else "MFA held")


@scenario(
    name="reset_flood",
    title="Password-reset flood",
    summary="One IP requests 6 password resets for a victim, then probes 8 other addresses.",
    goal="Flood the victim's inbox (5+ reset emails)",
    signals="A burst of reset requests on one account and from one IP.",
    expected_alerts=["reset_burst"],
    countered_by=["rate_limiting.per_account", "rate_limiting.per_ip"],
)
def reset_flood(run: Run):
    victim = run.account()
    others = [run.account("bystander") for _ in range(3)]
    c = run.client(datacenter("NL", "flooder"))
    sent = sum(run.attacker(c.post("/auth/reset/request", {"email": victim.email})) for _ in range(6))
    for i, email in enumerate([o.email for o in others] + [f"ghost-{run.short}-{i}@lab.test" for i in range(5)]):
        run.attacker(c.post("/auth/reset/request", {"email": email}))
    run.note(f"{sent} reset emails accepted for the victim; 8 other addresses probed.")
    run.goal(sent >= 5, f"{sent} reset emails sent to the victim")


@scenario(
    name="impossible_travel",
    title="Impossible travel",
    summary="The victim signs in from Montreal; seconds later their password is used from Bucharest.",
    goal="Sign in with a stolen password",
    signals="Two password-correct logins ~7,500 km apart within seconds; new device and country.",
    expected_alerts=["impossible_travel", "new_device_new_country"],
    countered_by=["risk.step_up"],
)
def impossible_travel(run: Run):
    victim = run.account()
    run.login(run.client(home("CA", "victim-laptop")), victim)
    run.note("Victim signed in from Montreal.")
    ok = run.attacker(run.client(datacenter("RO")).post("/auth/login",
                                                        {"email": victim.email, "password": victim.password}))
    run.note("Same password used from a Bucharest datacenter.")
    run.goal(ok, "signed in" if ok else "sign-in held back")


@scenario(
    name="session_hijack",
    title="Stolen session cookie",
    summary="The victim signs in; their session cookie is replayed from another device, which then "
            "moves items out.",
    goal="Move items out with the stolen session",
    signals="A session used from a device other than the one that created it, then transfers.",
    expected_alerts=["session_hijack_suspected", "asset_outflow_burst"],
    countered_by=["session.bind_to_device", "mfa.reauth_for_sensitive"],
)
def session_hijack(run: Run):
    victim = run.account(items=5)
    mule = run.account("mule")
    victim_client = run.client(home("CA", "victim-laptop"))
    run.login(victim_client, victim)
    run.note("Victim signed in from home.")

    thief = run.client(datacenter("RO", "thief-box"))
    thief.cookies = dict(victim_client.cookies)
    run.note("Session cookie copied to another device.")
    moved = _trades(run, thief, mule.email, 5) if run.attacker(thief.get("/auth/me")) else 0
    run.goal(moved > 0, f"{moved} item(s) moved")


@scenario(
    name="account_takeover",
    title="Account takeover and cash-out",
    summary="With a stolen password, the attacker signs in from abroad, changes the account email, "
            "then moves every item to a mule account.",
    goal="Move items out of the account",
    signals="Login from a new device and country, email change, then a burst of transfers.",
    expected_alerts=["new_device_new_country", "impossible_travel", "asset_outflow_burst"],
    countered_by=["risk.step_up", "recovery.trade_cooldown", "mfa.reauth_for_sensitive"],
)
def account_takeover(run: Run):
    victim = run.account(items=6)
    mule = run.account("mule")
    run.login(run.client(home("CA", "victim-laptop")), victim)
    run.note("Victim signed in from home.")

    c = run.client(datacenter("RO"))
    if not run.attacker(c.post("/auth/login", {"email": victim.email, "password": victim.password})):
        run.goal(False, "sign-in held back")
        return
    run.attacker(c.post("/account/email", {"new_email": f"taken-{run.short}@lab.test",
                                           "current_password": victim.password}))
    moved = _trades(run, c, mule.email, 6)
    run.note("Signed in from Bucharest, changed the email, then traded.")
    run.goal(moved > 0, f"{moved} item(s) moved")


@scenario(
    name="recovery_bypass",
    title="Passkey bypassed through weak recovery",
    summary="The victim uses a passkey only. The stolen password no longer works, so the attacker "
            "guesses the security-question answer, resets the password, and cashes out.",
    goal="Move items out despite the passkey",
    signals="password_disabled, wrong recovery answers, a security-question recovery, email change, "
            "then transfers.",
    expected_alerts=["password_on_passkey_account", "recovery_answer_guessing", "security_question_recovery",
                     "recovery_then_change", "asset_outflow_burst", "new_device_new_country", "impossible_travel"],
    countered_by=["recovery.block_security_questions", "rate_limiting.per_account", "recovery.trade_cooldown"],
)
def recovery_bypass(run: Run):
    answer = random.choice(CITIES[4:9])   # never one of the first few guesses
    victim = run.account(items=6, security_answer=answer)
    mule = run.account("mule")

    # The real owner: add a passkey, go passkey-only, sign in with it.
    owner = run.client(home("CA", "victim-phone"))
    run.login(owner, victim)
    owner.post("/account/reauth", {"password": victim.password})
    key = SoftPasskey(RP_ID, RP_ORIGIN)
    opts = owner.post("/account/passkeys/register/begin")
    reg = owner.post("/account/passkeys/register/finish", {"credential": key.register(opts.body), "label": "phone"})
    if reg.status != 201:
        raise RuntimeError(f"Passkey registration failed: {reg.status} {reg.body}")
    owner.post("/account/password-login", {"enabled": False})
    owner.post("/auth/logout")
    opts = owner.post("/auth/passkey/begin", {"email": victim.email})
    if not owner.post("/auth/passkey/finish", {"credential": key.sign_in(opts.body)}).ok:
        raise RuntimeError("Owner passkey sign-in failed")
    run.note("Victim added a passkey, turned password login off, and signed in with the passkey.")

    c = run.client(datacenter("RO"))
    r = c.post("/auth/login", {"email": victim.email, "password": victim.password})
    run.note(f"Stolen password tried: {r.code or r.status} (the passkey holds).")

    if not run.attacker(c.post("/auth/recover/question/start", {"email": victim.email})):
        run.goal(False, "security-question recovery refused")
        return
    new_password = secrets.token_urlsafe(12)
    recovered = False
    for guess in CITIES:
        r = c.post("/auth/recover/question", {"email": victim.email, "answer": guess, "new_password": new_password})
        if r.ok:
            recovered = True
            run.note(f"Answer guessed: '{guess}'. Password reset and password login turned back on.")
            break
        run.attacker(r)
        if r.status == 429:
            break
    if not recovered:
        run.goal(False, "recovery answer not found")
        return

    if not run.attacker(c.post("/auth/login", {"email": victim.email, "password": new_password})):
        run.goal(False, "sign-in after recovery held back")
        return
    run.attacker(c.post("/account/email", {"new_email": f"taken-{run.short}@lab.test",
                                           "current_password": new_password}))
    moved = _trades(run, c, mule.email, 6)
    run.goal(moved > 0, f"{moved} item(s) moved")
