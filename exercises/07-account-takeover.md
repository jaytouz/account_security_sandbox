# 7. Account takeover and cash-out

**Scenario:** `account_takeover` · **Rules:** `new_device_new_country`, `impossible_travel`, `asset_outflow_burst` · **Stopped by:** `risk.step_up`, `recovery.trade_cooldown`, `mfa.reauth_for_sensitive`

## How it works
The typical full takeover:
1. Get in with a stolen password.
2. Change the email so the real owner can't recover the account.
3. Move the valuable things out fast, to a "mule" account.

## What the scenario does
The victim signs in from home. The attacker signs in from Bucharest, changes the email to `taken-…@lab.test`, and trades all 6 items to a mule.

## The signature
A *sequence*, not a single event: login from a new place → `email_change` → several `asset_transfer` rows within a minute.

```sql
SELECT ts, 'login' AS step, result AS detail FROM telemetry.login_event WHERE run_id = '<run>'
UNION ALL SELECT ts, 'change', change_type FROM telemetry.account_change WHERE run_id = '<run>'
UNION ALL SELECT ts, 'transfer', '$' || asset_value_cents / 100 FROM telemetry.asset_transfer WHERE run_id = '<run>'
ORDER BY ts;
```

## Detection
`asset_outflow_burst` turns **critical** because the transfers follow a sensitive change (the email). The login alerts fire first.

## Defences: three layers
| Layer | Defence | Effect |
| --- | --- | --- |
| Front door | `risk.step_up` | The login itself is held back (emailed code). |
| Sensitive change | `mfa.reauth_for_sensitive` | Email change needs a fresh re-auth. Note: the attacker *has* the password, so this only helps if the account has TOTP. |
| Cash-out | `recovery.trade_cooldown` | After an email change, trades are paused 24 h, which leaves time to notice and respond. |
| Owner warning | `recovery.notify_on_change` | The **old** address gets "your sign-in email was changed": check Mailpit. |

## Try it
1. Baseline, then monitoring on.
2. Only `recovery.trade_cooldown` on: the attacker gets in and changes the email, but trades get `trade_hold`. Goal blocked.
3. Add `recovery.notify_on_change` and find the warning email in Mailpit.
4. Respond from the dashboard: **Lock account**, then **Force password reset**.

## Think about
- Which layer would you deploy first in a real product, and why?
- What should the email-change notice let the real owner do?
