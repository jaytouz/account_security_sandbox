# 8. Passkey bypassed through weak recovery

**Scenario:** `recovery_bypass` · **Rules:** `password_on_passkey_account`, `recovery_answer_guessing`, `security_question_recovery`, `recovery_then_change`, `asset_outflow_burst` · **Stopped by:** `recovery.block_security_questions`

## How it works
Passkeys are phishing-resistant: the private key never leaves the device, and the browser only uses it on the real site. An attacker who can't beat the passkey goes around it, through **account recovery**. If recovery is weaker than the passkey (security questions, SMS), the account is only as strong as that weak path.

## What the scenario does
1. The real owner adds a passkey (a software authenticator stands in for their phone), turns password login **off**, and signs in with the passkey.
2. The attacker tries the stolen password: `password_disabled`. The passkey holds.
3. The attacker starts security-question recovery ("What city were you born in?") and guesses from a short list of cities.
4. The right answer resets the password **and turns password login back on**. That is the weakness.
5. The attacker signs in with the new password, changes the email, and cashes out.

## The signature
```sql
SELECT to_char(ts, 'HH24:MI:SS') AS t, kind, result, host(ip) AS ip
  FROM telemetry.recovery_event WHERE run_id = '<your run id>' ORDER BY ts;
```

Read it alongside the login events: `passkey` success (owner) → `password_disabled` (attacker) → `question_answer: wrong` ×N → `correct` → password `success` from abroad.

## Detection
- `password_on_passkey_account`: someone knows the old password.
- `recovery_answer_guessing`: wrong answers.
- `security_question_recovery`: the weak path was used.
- `recovery_then_change`: email changed right after recovery.
- `asset_outflow_burst`: critical.

## Defences
| Defence | Effect |
| --- | --- |
| `recovery.block_security_questions` | **The fix.** No weak path, so the passkey stays the only way in. |
| `rate_limiting.per_account` | Caps wrong answers at 5 per 10 minutes. It helps against a short list, but questions with guessable answers stay weak. |
| `recovery.trade_cooldown` | Recovery succeeds, but no cash-out for 24 h. |
| `recovery.notify_on_change` | The owner is told their password was reset with the security question. |

Compare with the **email reset** path (`/auth/reset/request`): it keeps a passkey-only account passkey-only. That's how a strong recovery path should behave.

## Try it
1. Baseline, then monitoring on: the richest alert set of all scenarios.
2. `recovery.block_security_questions` on: blocked at recovery start. Only `password_on_passkey_account` fires.
3. Do it by hand with a real passkey: follow [Passkeys with a real authenticator](../docs/GUIDE.md#passkeys-with-a-real-authenticator) in the guide.

## The lesson
> An account is only as strong as its weakest recovery path.

Prefer several enrolled passkeys (phone + security key) and verified recovery over knowledge questions or SMS fallbacks.
