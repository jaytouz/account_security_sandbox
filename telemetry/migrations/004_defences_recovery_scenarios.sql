-- Phases 3-5: defences, passkeys, recovery, scenario runs, monitoring.

-- Account state used by the defences and the recovery flows.
ALTER TABLE app.account
    ADD COLUMN failed_streak           int NOT NULL DEFAULT 0,
    ADD COLUMN locked_until            timestamptz(3),      -- temporary lockout
    ADD COLUMN trade_hold_until        timestamptz(3),      -- set after reset / email change / recovery
    ADD COLUMN password_login_disabled boolean NOT NULL DEFAULT false,  -- passkey-only
    ADD COLUMN security_question       text,
    ADD COLUMN security_answer_hash    text;

ALTER TABLE app.web_session ADD COLUMN reauth_at timestamptz(3);

-- Second-step challenges: TOTP, or an emailed step-up code.
ALTER TABLE app.mfa_challenge
    ADD COLUMN kind      text NOT NULL DEFAULT 'totp' CHECK (kind IN ('totp', 'email')),
    ADD COLUMN code_hash bytea;

CREATE TABLE app.passkey (
    credential_id  bytea PRIMARY KEY,
    account_id     uuid NOT NULL REFERENCES app.account ON DELETE CASCADE,
    public_key     bytea NOT NULL,
    sign_count     bigint NOT NULL DEFAULT 0,
    label          text NOT NULL DEFAULT 'passkey',
    created_at     timestamptz(3) NOT NULL DEFAULT clock_timestamp(),
    last_used_at   timestamptz(3)
);
CREATE INDEX ON app.passkey (account_id);

CREATE TABLE app.webauthn_challenge (
    challenge   bytea PRIMARY KEY,
    account_id  uuid REFERENCES app.account ON DELETE CASCADE,
    purpose     text NOT NULL CHECK (purpose IN ('register', 'login')),
    created_at  timestamptz(3) NOT NULL DEFAULT clock_timestamp(),
    expires_at  timestamptz(3) NOT NULL,
    used_at     timestamptz(3)
);

-- How a login was attempted and how risky it looked.
ALTER TABLE telemetry.login_event
    ADD COLUMN method       text NOT NULL DEFAULT 'password',   -- password, passkey
    ADD COLUMN risk_score   int,
    ADD COLUMN risk_reasons text[];

-- A session used from a device other than the one that created it.
CREATE TABLE telemetry.session_event (
    event_id            bigserial PRIMARY KEY,
    ts                  timestamptz(3) NOT NULL DEFAULT clock_timestamp(),
    session_id          uuid NOT NULL,
    account_id          uuid NOT NULL,
    kind                text NOT NULL,              -- device_mismatch
    device_fp           text,
    expected_device_fp  text,
    ip                  inet,
    run_id              text
);
CREATE INDEX ON telemetry.session_event (ts);
CREATE INDEX ON telemetry.session_event (account_id, ts);

-- Every reset request and security-question attempt, including unknown emails.
CREATE TABLE telemetry.recovery_event (
    event_id         bigserial PRIMARY KEY,
    ts               timestamptz(3) NOT NULL DEFAULT clock_timestamp(),
    kind             text NOT NULL,                 -- reset_request, question_start, question_answer
    account_id       uuid,
    email_attempted  text NOT NULL,
    result           text NOT NULL,                 -- accepted, unknown_account, wrong, correct,
                                                    -- rate_limited, disabled, no_question
    ip               inet,
    device_fp        text,
    run_id           text
);
CREATE INDEX ON telemetry.recovery_event (ts);
CREATE INDEX ON telemetry.recovery_event (ip, ts);
CREATE INDEX ON telemetry.recovery_event (account_id, ts);

-- Alerts name what they are about (an account, an IP, a session) for dedup.
ALTER TABLE telemetry.alert ADD COLUMN subject text;
CREATE INDEX ON telemetry.alert (rule_id, subject, ts);

-- One row per scenario run, with the defences in force and the scorecard.
CREATE TABLE telemetry.scenario_run (
    run_id       text PRIMARY KEY,
    scenario     text NOT NULL,
    started_at   timestamptz(3) NOT NULL DEFAULT clock_timestamp(),
    finished_at  timestamptz(3),
    status       text NOT NULL DEFAULT 'running',   -- running, completed, error
    defences     jsonb,
    scorecard    jsonb
);

-- Heartbeat of the monitoring service.
CREATE TABLE telemetry.monitor_state (
    id            int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    last_eval_at  timestamptz(3),
    enabled       boolean NOT NULL DEFAULT false,
    alerts_raised bigint NOT NULL DEFAULT 0
);
INSERT INTO telemetry.monitor_state (id) VALUES (1);
