# 6. Stolen session cookie

**Scenario:** `session_hijack` · **Rules:** `session_hijack_suspected`, `asset_outflow_burst` · **Stopped by:** `session.bind_to_device`, `mfa.reauth_for_sensitive`

## How it works
After login, the session cookie *is* the login. Malware ("infostealers") and adversary-in-the-middle phishing steal the cookie itself. The attacker then skips the password **and** MFA entirely.

## What the scenario does
The victim signs in from home. Their cookie is copied to another device in a datacenter, which then trades 5 items to a mule account.

## The signature
No login at all from the attacker: just requests on an existing session from a different device fingerprint.

```sql
SELECT to_char(ts, 'HH24:MI:SS') AS t, left(device_fp, 8) AS used_from,
       left(expected_device_fp, 8) AS created_on, host(ip) AS ip
  FROM telemetry.session_event WHERE run_id = '<your run id>' ORDER BY ts;
```

## Detection
- `session_hijack_suspected` (**critical**): a session used from a device other than its own.
- `asset_outflow_burst` (critical here, because of the session anomaly).

## Defences
| Defence | Effect |
| --- | --- |
| `session.bind_to_device` | The first request from the wrong device ends the session (`session_revoked`). |
| `mfa.reauth_for_sensitive` | Even if the session survives, trades need a fresh re-authentication (password, plus code if TOTP is on), which the thief can't provide. |
| `session.secure_cookies` | `Secure` + `SameSite=Strict` reduces theft over the network and cross-site use. It doesn't stop malware on the device. |

## Try it
1. Baseline, then monitoring on.
2. `session.bind_to_device` alone: blocked at the first request.
3. Off; `mfa.reauth_for_sensitive` alone: the thief gets in, but trades are refused (`reauth_required`). Compare both runs in **Runs**.

## Think about
- Device fingerprints are guessable or copyable. What would a stronger binding look like? (Look up DBSC, Device Bound Session Credentials.)
- Why is "re-authenticate for sensitive actions" useful even when sessions are bound?
