# Account Security Lab

A local, isolated training sandbox for practicing how to detect and respond to account-takeover activity. It contains a fake account service, telemetry on every auth, session, change and transfer, a review dashboard, and switchable defences. A scenario runner (Phase 3) and more defences (Phase 4) come next.

All accounts and data are synthetic. The design is in [BUILD_PROMPT.md](BUILD_PROMPT.md).

## Isolation rules
- The database, app, mail catcher and dashboard run only on an internal Docker network with no route out.
- A small nginx gateway is the only container with a host-facing network. It publishes the app (`:8000`), the mail catcher UI (`:8025`) and the dashboard (`:8050`) on `127.0.0.1` only. It blocks `/admin` and strips the `X-Lab-Sim-*` headers from host requests.
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

The seed creates 20 fictional accounts (every 5th has TOTP on), each with 5 items. Test credentials go to `data/out/seed_accounts.csv`, which is git-ignored. The app applies database migrations on startup, so pulling a new phase never needs a reset.

Then:
- Review dashboard: http://127.0.0.1:8050
- API and interactive docs: http://127.0.0.1:8000/docs
- Caught emails (reset tokens): http://127.0.0.1:8025

```bash
docker compose exec app python scripts/smoke_test.py
```

## Review dashboard (Phase 2)
| Tab | What it shows | What you can do |
| --- | --- | --- |
| Live | Login attempts, failures, source IPs, transfers and alerts for the time window; login outcomes over time; most-failed accounts; a combined event feed. Refreshes every 5 s. | Filter by time window, run and event kind |
| Accounts | Status, MFA, live sessions, recent failures, last login, live sessions and a full timeline for one account. Most recently active accounts first. | Lock / unlock, revoke all sessions, force a password reset |
| Alerts | Alerts by severity. Empty until Phase 4 adds monitoring rules. | Filter by severity |
| Runs | Every tagged run with its counts; two runs side by side, including which defences were on at the start of each. | Compare runs |
| Defences | Current defence switches and their change history. | Flip a defence on or off |

How it's wired:
- It reads the database as `lab_review`, a read-only role that can't see password hashes, authenticator secrets or session and reset token hashes.
- Every action goes through the app's `/admin` API with a shared token (`LAB_ADMIN_TOKEN`). The gateway blocks `/admin` from the host, so only containers inside the lab can call it.
- Every admin action is logged to `telemetry.account_change` with channel `admin`. Every defence change is logged to `telemetry.defence_change`.

## Account service
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

Lab-internal admin routes (need `X-Lab-Admin-Token`, blocked at the gateway):

| Route | What it does | Telemetry |
| --- | --- | --- |
| `GET`, `PUT /admin/defences` | Read or flip a defence switch | `defence_change` |
| `POST /admin/accounts/{id}/lock`, `/unlock` | Lock (and end sessions) or unlock | `account_change: admin_lock / admin_unlock` |
| `POST /admin/accounts/{id}/revoke-sessions` | End every live session | `account_change: admin_revoke_sessions` |
| `POST /admin/accounts/{id}/force-reset` | Random password, end sessions, email a reset token | `account_change: admin_force_reset` |

Login result codes in `telemetry.login_event.result`: `success`, `bad_password`, `unknown_account`, `locked`, `mfa_required`, `mfa_fail`. Phase 4 adds `rate_limited` and `step_up`.

## Simulated origin headers
Inside Docker every client shares one IP. To give events a synthetic origin, send these headers from inside the lab network. The gateway removes them from host requests, and the app honours them only while `LAB_TRUST_SIM_HEADERS=true`.

| Header | Example |
| --- | --- |
| `X-Lab-Sim-IP` | `203.0.113.10` (use documentation ranges) |
| `X-Lab-Sim-ASN` | `64500` |
| `X-Lab-Sim-IP-Type` | `residential`, `datacenter`, `mobile` |
| `X-Lab-Sim-Geo` | `FR;48.85;2.35` |
| `X-Lab-Sim-Device` | any label; changes the device fingerprint |
| `X-Lab-Run-Id` | tags every event with a run id (always honoured) |

## Defence switches
Flip them from the dashboard's Defences tab so each change is logged. They live in `app/security/config.yaml`, which the app re-reads on each request. If you edit the file by hand, the change is only logged at the next app restart.

Everything starts off so later scenarios record a baseline. Current switches: `baseline.password_policy` and `baseline.generic_errors`. Passwords are always argon2-hashed.

## Looking at telemetry
```bash
docker compose exec db psql -U lab lab
```

```sql
SELECT ts, email_attempted, host(ip), geo_country, device_fp, result
  FROM telemetry.login_event ORDER BY ts DESC LIMIT 20;
```

## Dev-only secrets
`POSTGRES_PASSWORD`, `LAB_REVIEW_DB_PASSWORD` and `LAB_ADMIN_TOKEN` have defaults in `docker-compose.yml`. To change them, set them in a `.env` file next to it (git-ignored).

## Layout
- `docker-compose.yml`: the isolated stack
- `gateway/`: nginx config for the host-facing gateway
- `app/`: the account service (FastAPI), including the admin API
- `app/security/`: defence switches and modules
- `telemetry/`: migrations, migration runner and the event write path
- `review/`: the dashboard (Streamlit)
- `data/`: seed script
- `scripts/`: isolation check and smoke test
- Coming next: `scenarios/` (Phase 3), `exercises/`, `notes/`

## Reset everything
```bash
docker compose down -v
```
