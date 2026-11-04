# Build: Account Security Lab (defensive training sandbox)

I'm building a local training lab for practicing how to detect and respond to account-takeover activity. I own everything and run it on my own machine. The lab has a fake account service, telemetry, defences that can be switched on and off, and a scenario runner. The runner replays synthetic suspicious activity against this app only, so I can compare the telemetry with defences off and on.

## Hard constraints
- Runs with docker-compose on an internal-only network (`internal: true`). Only the review dashboard is published, and only on 127.0.0.1.
- All accounts and data are synthetic and come from a seed script. No real credentials, real people or real breach data.
- The scenario runner has a fixed target allowlist (the account-service container) and refuses any other host.
- No phishing pages, lookalike login pages, proxies or evasion features. Phishing-style outcomes are modelled only by their telemetry signature, for example a valid session reused from a new device.
- Write-ups are framed as detection and hardening lessons.

## Stack
FastAPI, Postgres (schemas `app` and `telemetry`), and Dash or Streamlit for the review app. A local mail catcher (Mailpit) receives reset emails. Keycloak is optional and not part of v1.

## Repository layout
- `docker-compose.yml`: the whole isolated stack
- `app/`: the account service
- `app/security/`: defences as swappable modules
- `telemetry/`: event schema, migrations, write path
- `data/`: seed scripts for fake accounts and inventory
- `scenarios/`: the scenario runner and one file per scenario
- `review/`: the dashboard
- `exercises/`: one write-up per attack class
- `notes/`: my running log of findings
- `README.md`: setup, isolation rules, the order to work through

## Account service (`app/`)
- Sign-up, login, logout, TOTP MFA, and passkey (WebAuthn) login through a library such as `py_webauthn`.
- Password reset with emailed, single-use, expiring tokens.
- Profile and settings changes, plus fake inventory and trades between seeded accounts.
- Configurable recovery options: email link, backup codes, and a legacy "security question" fallback. The fallback can be enabled to demonstrate the weak-recovery lesson.

## Defences (`app/security/`)
Each defence is a module with an on/off flag in one config file, and the flags can be switched from the dashboard.
1. Baseline: argon2 hashing, password policy, generic error messages.
2. Rate limiting and lockout: per-account and per-IP throttling, backoff, lockout.
3. Breached-password check against a local hash list in HIBP format. Ship a small fake sample file.
4. TOTP MFA, with re-authentication for sensitive changes.
5. Session hardening: secure cookies, rotation on login, revoke-all on password change, binding sessions to device context.
6. Recovery hardening: security questions disabled, alerts on recovery changes, a cool-down before an account whose recovery changed can trade.
7. Risk scoring: new device, IP reputation from a local list, geovelocity. A high score triggers step-up auth.
8. Monitoring rules that write alerts.

## Telemetry (`telemetry/`)
| Table | Grain | Key columns |
| --- | --- | --- |
| login_event | one row per auth attempt | ts, account_id, ip, asn, ip_type, user_agent, mfa_used, result |
| session | one row per session | session_id, account_id, login_event_id, start/end, device_fp, ip |
| account_change | one row per security/profile change | account_id, session_id, change_type, channel, ts |
| asset_transfer | one row per trade/gift | account_id, counterparty, asset_value, ts |
| device_fingerprint | one row per distinct device | device_fp_id, component hashes, first/last seen |
| alert | one row per fired rule | rule_id, severity, account_id, run_id, ts, evidence |

- Timestamps are in milliseconds.
- Result codes are detailed: bad_password, mfa_fail, locked, rate_limited, step_up, success.
- IP, ASN and geo are synthetic. They are passed in a trusted header that only the scenario runner sets, on the internal network.
- Every event carries the `run_id` of the scenario that produced it.

## Scenario runner (`scenarios/`)
Scenarios run from a CLI or from a dashboard button. Each one uses seeded accounts only, declares the detections it expects, and tags every event with its run_id.
- Many failed logins across many seeded accounts from a few IPs (stuffing pattern).
- Repeated failures on one account (guessing pattern).
- A successful login from a new device in a distant location shortly after a normal login (geovelocity).
- A valid session token reused from a different device fingerprint (stolen-session signature).
- A burst of MFA failures.
- A burst of password-reset requests.
- Recovery through the security-question fallback succeeds while passkey login holds (weak-recovery lesson).
- A settings change followed by a burst of outgoing trades (asset outflow).

After each run, write a scorecard: which defences were on, what was blocked, which alerts fired and which expected alerts did not.

## Review dashboard (`review/`)
- Live event feed
- Per-account timeline
- Alerts by severity
- Defence toggles
- Run comparison: the same scenario with defences off vs on
- One-click responses: lock account, revoke sessions, force reset

## Exercises (`exercises/`)
One markdown file per attack class. Each covers:
- The concept in plain terms
- Its telemetry signature
- The detection rule
- The defence that counters it
- Before and after results

For hands-on study of the underlying vulnerabilities, link to OWASP Juice Shop and PortSwigger Web Security Academy instead of reimplementing exploits here.

## Build order
1. Compose stack, account-service auth, seed data, telemetry write path.
2. Review dashboard.
3. Scenario runner with the first three scenarios.
4. Defences one at a time, each with a before/after run.
5. Passkeys and the recovery lesson.

Build Phase 1 only, then stop so I can review it.
