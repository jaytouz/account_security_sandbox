# 2. Password guessing

**Scenario:** `password_guessing` · **Rules:** `guessing_one_account`, `success_after_failures` · **Stopped by:** `rate_limiting.per_account`, `lockout.enabled`

## How it works
The attacker targets one account and tries many passwords. This is slow and noisy, but it works against weak passwords when nothing limits attempts.

## What the scenario does
The victim signs in normally. Then someone in the same country, on a different device, tries 12 wrong passwords and finally the right one.

## The signature
A run of `bad_password` on one account, then a `success` from the same IP and device.

```sql
SELECT to_char(ts, 'HH24:MI:SS.MS') AS t, result, host(ip) AS ip, left(device_fp, 8) AS device
  FROM telemetry.login_event WHERE run_id = '<your run id>' ORDER BY ts;
```

## Detection
- `guessing_one_account` (medium): 8+ failed or blocked attempts on one account.
- `success_after_failures` (high): a correct password after 5+ wrong ones. This is the alert that matters: the guess worked.

## Defences
| Defence | Effect here | Trade-off |
| --- | --- | --- |
| `rate_limiting.per_account` | After 5 failures in 5 minutes, even the right password gets 429. The final attempt is refused. | Slows guessing to ~1 per minute. Doesn't punish the real user for long. |
| `lockout.enabled` | After 10 wrong passwords in a row, the account is locked for 15 minutes. | An attacker can **lock real users out** on purpose (a denial of service). That's why rate limiting is usually preferred. |

Both stop this scenario, in different ways. Compare the scorecards:
- **Rate limiting:** `bad_password ×5, rate_limited ×8`. Only 5 guesses were ever checked.
- **Lockout:** `bad_password ×10, account_locked ×3`. 10 guesses were checked, then the account (and its real owner) was locked out for 15 minutes.

## Try it
1. Baseline, then monitoring on: both alerts fire.
2. `rate_limiting.per_account` on: blocked. The scorecard shows `rate_limited`.
3. Off again; `lockout.enabled` on: compare. In **Accounts**, look at *Temp. locked until*, and use **Unlock account** to clear it.

## Think about
- What should the app tell a user whose account is being rate-limited?
- Rate-limit by account, by IP, or by the pair? What does each miss?
