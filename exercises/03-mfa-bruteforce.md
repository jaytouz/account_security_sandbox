# 3. MFA code guessing

**Scenario:** `mfa_bruteforce` · **Rule:** `mfa_fail_burst` · **Stopped by:** MFA itself, plus `rate_limiting.per_account`

## How it works
The attacker already has the password (phished, reused, guessed) but the account uses an authenticator app. They try codes, or keep sending prompts hoping the user gives in ("MFA fatigue").

## What the scenario does
A TOTP-protected victim signs in with password + code. The attacker uses the right password from Bucharest, reaches the code step (`mfa_required`), and sends 8 wrong codes.

## The signature
This is the important part: **`mfa_required` from a new place means the password is known.** Then a burst of `mfa_fail`.

```sql
SELECT to_char(ts, 'HH24:MI:SS') AS t, result, mfa_used, geo_country, ip_type, risk_score, risk_reasons
  FROM telemetry.login_event WHERE run_id = '<your run id>' ORDER BY ts;
```

## Detection
- `mfa_fail_burst` (high): 5+ wrong codes on one account.
- `new_device_new_country` and `impossible_travel`: they fire on the `mfa_required` login, because the password step succeeded.

## Defences
- With **no** defences the goal already fails: guessing a 6-digit code is hopeless when codes rotate every 30 s. The scorecard says *Attack blocked*.
- `rate_limiting.per_account` caps codes at 5 per challenge (then 429, and the attacker must log in again), which makes guessing even less practical.
- The real fix is a **response**: the password is compromised. Use **Force password reset** on the account (Accounts tab).

## Try it
1. Run it with monitoring on. Note *Attack blocked, and detected*.
2. Open the account and click **Force password reset**. Find the reset email in Mailpit.
3. With `rate_limiting.per_account` on, check the `rate_limited` result after 5 codes.

## Think about
- Which signal tells you to rotate the password: `mfa_fail_burst`, or the earlier `mfa_required` from a new country?
- How would push-notification MFA change this attack? (Look up "MFA fatigue" and number matching.)
