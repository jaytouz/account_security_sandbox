# Account Security Lab

A local, isolated training sandbox for learning how account-takeover attacks look in telemetry, how to detect them, and which defences stop them. Everything runs in Docker on your machine, against fake accounts, with no route to the internet.

- **Fake account service:** sign-up, password login, TOTP, passkeys, password reset, security-question recovery, items and trades.
- **Telemetry:** every login, session, recovery attempt, change, transfer and alert, with millisecond timestamps and run ids.
- **8 scenarios:** credential stuffing, password guessing, MFA code guessing, reset flood, impossible travel, stolen session, takeover and cash-out, and a passkey bypassed through weak recovery.
- **15 defence switches:** rate limits, lockout, breached passwords, re-authentication, session hardening, recovery hardening, risk-based step-up, monitoring.
- **13 detection rules**, plus a dashboard to watch, compare runs, respond and flip defences.

> **Start here: [docs/GUIDE.md](docs/GUIDE.md)**. It covers setup, running scenarios, reading scorecards, defences, detection rules, looking at logs, testing and troubleshooting.
> Then work through the **[exercises](exercises/README.md)**, one per attack class.

## Quick start
Requires Docker Desktop (WSL 2 engine) with hardware virtualization on.

```bash
docker compose up -d --build
```

```bash
docker compose exec app python scripts/check_isolation.py
```

```bash
docker compose run --rm seed
```

Then open the dashboard at http://127.0.0.1:8050, go to **Scenarios**, and run one.

| Open | URL |
| --- | --- |
| Dashboard | http://127.0.0.1:8050 |
| API docs | http://127.0.0.1:8000/docs |
| Emails (Mailpit) | http://127.0.0.1:8025 |
| Passkey test page | http://localhost:8000/lab/passkeys |

## Safety
- All containers except a small gateway sit on an internal network with no route out. `check_isolation.py` proves it.
- The scenario runner only accepts the lab's own app as a target.
- Accounts are fake (`@lab.test`). Simulated IPs come from documentation ranges. Ports listen on `127.0.0.1` only.
- Never use real credentials, people or breach data, and never point any of this at a system you don't own.

## Tests
```bash
docker compose exec app python scripts/smoke_test.py
```

```bash
docker compose exec runner python scripts/defence_test.py
```

```bash
docker compose exec runner python -m scenarios check
```

## Layout
| Path | What |
| --- | --- |
| `docker-compose.yml` | The isolated stack: db, mail, app, monitor, runner, review, gateway |
| `gateway/` | nginx: the only host-facing container |
| `app/` | The account service (FastAPI): routes, sessions, admin API, passkey page |
| `app/security/` | Defence switches (`config.yaml`), limits, risk scoring, breached-password list |
| `telemetry/` | Migrations, migration runner, event writers, monitoring rules (`monitor.py`) |
| `scenarios/` | Scenario runner: the 8 scenarios, lab-only client, software passkey, CLI and API |
| `review/` | The dashboard (Streamlit) |
| `data/` | Seed script and shared fake data |
| `scripts/` | Isolation check, smoke test, per-defence test |
| `docs/GUIDE.md` | The user guide |
| `exercises/` | One write-up per attack class |
| `notes/` | Your own findings log |
| `BUILD_PROMPT.md` | The original design brief |

## Reset
```bash
docker compose down -v
```
