# Exercises

One write-up per attack class. Each one explains:
- how the attack works, in plain terms
- what it leaves in the telemetry, with a query to see it
- which rule detects it
- which defences stop it, and how to prove it with a before/after run

Work through them in order. The first ones teach the loop, the later ones combine ideas.

| # | Exercise | Scenario | Key lesson |
| --- | --- | --- | --- |
| 1 | [Credential stuffing](01-credential-stuffing.md) | `credential_stuffing` | Per-IP limits miss distributed attacks; risk-based step-up doesn't |
| 2 | [Password guessing](02-password-guessing.md) | `password_guessing` | Rate limits and lockout, and their trade-offs |
| 3 | [MFA code guessing](03-mfa-bruteforce.md) | `mfa_bruteforce` | MFA holds, but its failures reveal a stolen password |
| 4 | [Reset flood](04-reset-flood.md) | `reset_flood` | Abuse of recovery endpoints, and enumeration |
| 5 | [Impossible travel](05-impossible-travel.md) | `impossible_travel` | Geovelocity as a signal and as a step-up trigger |
| 6 | [Stolen session](06-session-hijack.md) | `session_hijack` | Sessions bypass login and MFA; bind them and re-authenticate |
| 7 | [Takeover and cash-out](07-account-takeover.md) | `account_takeover` | Chain of signals: new place → sensitive change → outflow |
| 8 | [Passkey bypass through recovery](08-recovery-bypass.md) | `recovery_bypass` | An account is only as strong as its weakest recovery path |

Before you start, follow the setup in the [user guide](../docs/GUIDE.md#3-start-the-lab) and make sure `check_isolation.py` prints `ISOLATED`. Keep notes on what you observe in [`notes/`](../notes/README.md).

Every exercise uses the same loop:

1. Run the scenario with everything off (the baseline).
2. Turn on `monitoring.enabled` and run it again. Read the alerts.
3. Turn on the defence(s) the exercise names and run it again.
4. Compare the runs in the dashboard's **Runs** tab.
