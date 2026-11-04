# 4. Password-reset flood

**Scenario:** `reset_flood` · **Rule:** `reset_burst` · **Stopped by:** `rate_limiting.per_account`, `rate_limiting.per_ip`

## How it works
Reset endpoints are public. Abusing them can:
- flood a victim's inbox, to bury a real security email or to harass them
- probe which emails have accounts (enumeration)
- cost money in email or SMS sends

## What the scenario does
One datacenter IP requests 6 resets for the victim, then requests resets for 3 other real accounts and 5 addresses that don't exist.

## The signature
`telemetry.recovery_event` records every request, including unknown emails:

```sql
SELECT to_char(ts, 'HH24:MI:SS') AS t, email_attempted, result, host(ip) AS ip
  FROM telemetry.recovery_event WHERE run_id = '<your run id>' ORDER BY ts;
```

## Detection
`reset_burst` (medium): 5+ requests for one account, or 8+ from one IP.

## Defences
| Defence | Effect |
| --- | --- |
| `rate_limiting.per_account` | At most 3 reset emails per account per 10 minutes. The victim gets 3, not 6, so the goal (5) fails. |
| `rate_limiting.per_ip` | At most 5 reset requests per IP per 10 minutes. |
| `baseline.generic_errors` | Unknown emails get the same "if an account exists…" reply, so the attacker can't tell which addresses exist. With it off, they get a 404. |

## Try it
1. Baseline: count the reset emails in Mailpit (http://127.0.0.1:8025).
2. Turn on both rate limits: count again. The scorecard shows `rate_limited`.
3. With `generic_errors` off and then on, request a reset for `nobody@lab.test` in the API docs and compare the replies.

## Think about
- Should a rate-limited reset return 429, or pretend to succeed? What does each tell the attacker?
