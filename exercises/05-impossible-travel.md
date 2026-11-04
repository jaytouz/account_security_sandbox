# 5. Impossible travel

**Scenario:** `impossible_travel` · **Rules:** `impossible_travel`, `new_device_new_country` · **Stopped by:** `risk.step_up`

## How it works
Someone has the password (phished or bought) and signs in from wherever they are. If the real user signed in from another continent shortly before, the two logins imply a speed no one can travel at.

## What the scenario does
The victim signs in from Montreal. Seconds later the same password is used from a Bucharest datacenter, about 7,500 km away.

## The signature
Two password-correct logins with coordinates far apart and timestamps close together. The app also stores a **risk score** on every password login:

```sql
SELECT to_char(ts, 'HH24:MI:SS') AS t, geo_country, ip_type, left(device_fp, 8) AS device,
       result, risk_score, risk_reasons
  FROM telemetry.login_event WHERE run_id = '<your run id>' ORDER BY ts;
```

The second login scores 8: new device (1), new country (2), datacenter IP (2) and impossible travel (3).

## Detection
- `impossible_travel` (high): over 500 km apart at over 900 km/h. The evidence shows km, seconds and km/h.
- `new_device_new_country` (medium).

## Defences
`risk.step_up`: any password login scoring 3+ needs a 6-digit code emailed to the account. The attacker gets `step_up_required` and stops there. The real owner, travelling, would find the code in their inbox (Mailpit) and finish with `POST /auth/step-up/verify`.

## Try it
1. Baseline, then monitoring on.
2. Turn on `risk.step_up` and run again: blocked, and the code email appears in Mailpit.
3. Play the real traveller in the API docs: sign in as a seeded user, then complete the step-up with the emailed code.

## Think about
- False positives: VPNs and mobile networks move people's apparent location. Which weights would you change?
- Why does the score start at 0 for an account's very first login (`first_login`)?
