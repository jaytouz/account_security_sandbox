# Account Security Lab

A local, isolated training sandbox for practicing how to detect and respond to account-takeover activity. It contains a fake account service, telemetry on every auth, session, change and transfer, and (in later phases) switchable defences, a scenario runner and a review dashboard.

All accounts and data are synthetic. The design is in [BUILD_PROMPT.md](BUILD_PROMPT.md).

## Isolation rules
- The database, app and mail catcher run only on an internal Docker network with no route out.
- A small nginx gateway is the only container with a host-facing network. It publishes the app (`:8000`) and the mail catcher UI (`:8025`) on `127.0.0.1` only, and strips the `X-Lab-Sim-*` headers from host requests.
- Run the isolation check after every `up`, before running any scenario:
  ```bash
  docker compose exec app python scripts/check_isolation.py
  ```
- Only fake accounts (`@lab.test`). Never real credentials, people or breach data. Never point anything at a host outside this stack.

## Setup
Requires Docker Desktop.

```bash
docker compose up -d --build
```

```bash
docker compose exec app python scripts/check_isolation.py
```

```bash
docker compose run --rm seed
```

The seed creates 20 fictional accounts (every 5th has TOTP on), each with 5 items. Test credentials go to `data/out/seed_accounts.csv`, which is git-ignored.

Then:
- API and interactive docs: http://127.0.0.1:8000/docs
- Caught emails (reset tokens): http://127.0.0.1:8025

```bash
docker compose exec app python scripts/smoke_test.py
```

## Account service (Phase 1)
| Route | What it does | Telemetry |
| --- | --- | --- |
| `POST /auth/signup` | Create an account | `account_change: account_created` |
| `POST /auth/login` | Password login; returns `mfa_required` if TOTP is on | `login_event`, `session` |
| `POST /auth/mfa/verify` | Second step with a TOTP code | `login_event (mfa_used)`, `session` |
| `POST /auth/logout` | End the session | `session.ended_at` |
| `GET /auth/me` | Current account and session | |
| `POST /auth/reset/request` | Email a single-use reset token (30 min) | `account_change: reset_requested` |
| `POST /auth/reset/confirm` | Set a new password with the token | `account_change: password_reset` |
| `POST /account/password` | Change password (needs current one) | `account_change: password_change` |
| `POST /account/email` | Change email (needs current password) | `account_change: email_change` |
| `POST /account/mfa/totp/enroll`, `/confirm`, `/disable` | Manage TOTP | `account_change: mfa_*` |
| `GET /account/sessions` | List own sessions | |
| `GET /inventory`, `POST /trades` | Fake items and transfers | `asset_transfer` |
| `GET /defences` | Current defence switches | |

Login result codes in `telemetry.login_event.result`: `success`, `bad_password`, `unknown_account`, `locked`, `mfa_required`, `mfa_fail`. Phase 4 adds `rate_limited` and `step_up`.

## Simulated origin headers
Inside Docker every client shares one IP. To give events a synthetic origin, send these headers from inside the lab network (the gateway removes them from host requests, and the app honours them only while `LAB_TRUST_SIM_HEADERS=true`):

| Header | Example |
| --- | --- |
| `X-Lab-Sim-IP` | `203.0.113.10` (use documentation ranges) |
| `X-Lab-Sim-ASN` | `64500` |
| `X-Lab-Sim-IP-Type` | `residential`, `datacenter`, `mobile` |
| `X-Lab-Sim-Geo` | `FR;48.85;2.35` |
| `X-Lab-Sim-Device` | any label; changes the device fingerprint |
| `X-Lab-Run-Id` | tags every event with a run id (always honoured) |

## Defence switches
`app/security/config.yaml`. Everything starts off so later scenarios record a baseline. The app re-reads the file on each request. Phase 1 has `baseline.password_policy` and `baseline.generic_errors`. Passwords are always argon2-hashed.

## Looking at telemetry
```bash
docker compose exec db psql -U lab lab
```

```sql
SELECT ts, email_attempted, host(ip), geo_country, device_fp, result
  FROM telemetry.login_event ORDER BY ts DESC LIMIT 20;
```

## Layout
- `docker-compose.yml`: the isolated stack
- `gateway/`: nginx config for the host-facing gateway
- `app/`: the account service (FastAPI)
- `app/security/`: defence switches and modules
- `telemetry/`: schema migrations and the event write path
- `data/`: seed script
- `scripts/`: isolation check and smoke test
- Coming next: `review/` (Phase 2), `scenarios/` (Phase 3), `exercises/`, `notes/`

## Reset everything
```bash
docker compose down -v
```
