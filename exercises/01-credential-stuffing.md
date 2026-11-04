# 1. Credential stuffing

**Scenario:** `credential_stuffing` · **Rule:** `stuffing_many_accounts_one_ip` · **Stopped by:** `risk.step_up`

## How it works
People reuse passwords. When another site leaks email/password pairs, attackers try those pairs everywhere else. Most pairs fail (different or changed password), but a few percent work. Attackers spread the attempts over many IPs, often cheap datacenter or proxy IPs, to stay under per-IP limits.

## What the scenario does
- Creates 16 users, and each signs in once from home (Montreal), so the accounts have a normal history.
- Builds a "leaked list": 4 users' real passwords (they reused them) plus 12 stale ones and 4 addresses that don't exist.
- Tries every pair once, alternating between two datacenter IPs (Amsterdam and Bucharest).

## The signature
Failures spread across many accounts from a few IPs, with `unknown_account` mixed in (the list holds people who never signed up here). Then a few successes on accounts that normally log in from somewhere else.

```sql
SELECT host(ip) AS ip, ip_type, count(DISTINCT email_attempted) AS accounts,
       count(*) FILTER (WHERE result = 'success') AS successes,
       count(*) FILTER (WHERE result IN ('bad_password', 'unknown_account')) AS failures
  FROM telemetry.login_event
 WHERE run_id = '<your run id>' AND ip_type = 'datacenter'
 GROUP BY 1, 2;
```

## Detection
- `stuffing_many_accounts_one_ip` (high): one IP failing on 6+ accounts in 10 minutes.
- `new_device_new_country` and `impossible_travel` fire on each account that was broken into.

## Defences
| Try | What happens |
| --- | --- |
| `rate_limiting.per_ip` alone | **Doesn't stop it.** Each IP stays under 20 failures. Real attackers rotate hundreds of IPs. |
| `rate_limiting.per_account` alone | Doesn't stop it either: each account sees only one attempt. |
| `risk.step_up` | **Stops it.** The successful logins score new device + new country + datacenter IP (+ impossible travel), so the app asks for an emailed code the attacker doesn't have. |
| `breached_passwords.enabled` | Prevention for the future: users can't pick passwords already on breach lists (it applies when passwords are set, so it doesn't fix existing ones). |

## Try it
1. Baseline run: the goal is reached ("4 session(s) obtained").
2. Monitoring on: same result, now detected.
3. Turn on only `rate_limiting.per_ip`: still reached. Note why.
4. Turn on `risk.step_up`: blocked. The scorecard shows `step_up_required x4`.
5. Look at `risk_reasons` on those four logins (Live feed, or the query in the guide).

## Think about
- If the attacker used residential proxies in the victims' own country, which risk factors would remain?
- What would a per-*device* or per-*ASN* limit add?
- Why does `unknown_account` matter for detection, and what does `baseline.generic_errors` change for the attacker?
