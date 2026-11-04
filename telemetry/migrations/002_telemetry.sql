-- Telemetry: what every auth, session, change and transfer leaves behind.
-- No foreign keys to app.*: telemetry must survive account deletion and re-seeding.
-- Timestamps are millisecond precision so sequences can be reconstructed.

CREATE TABLE telemetry.login_event (
    login_event_id   bigserial PRIMARY KEY,
    ts               timestamptz(3) NOT NULL DEFAULT clock_timestamp(),
    account_id       uuid,                       -- null when the email matched no account
    email_attempted  text NOT NULL,
    ip               inet,
    asn              int,
    ip_type          text,                       -- e.g. residential, datacenter, mobile (synthetic)
    geo_country      text,
    geo_lat          double precision,
    geo_lon          double precision,
    user_agent       text,
    device_fp        text,
    mfa_used         boolean NOT NULL DEFAULT false,
    result           text NOT NULL,              -- success, bad_password, unknown_account, locked,
                                                 -- mfa_required, mfa_fail, rate_limited, step_up
    run_id           text                        -- scenario run that produced it, if any
);
CREATE INDEX ON telemetry.login_event (ts);
CREATE INDEX ON telemetry.login_event (account_id, ts);
CREATE INDEX ON telemetry.login_event (ip, ts);
CREATE INDEX ON telemetry.login_event (run_id);

CREATE TABLE telemetry.session (
    session_id      uuid PRIMARY KEY,
    account_id      uuid NOT NULL,
    login_event_id  bigint REFERENCES telemetry.login_event,
    started_at      timestamptz(3) NOT NULL DEFAULT clock_timestamp(),
    ended_at        timestamptz(3),
    end_reason      text,                        -- logout, revoked, expired
    device_fp       text,
    ip              inet,
    run_id          text
);
CREATE INDEX ON telemetry.session (account_id, started_at);

CREATE TABLE telemetry.account_change (
    change_id    bigserial PRIMARY KEY,
    ts           timestamptz(3) NOT NULL DEFAULT clock_timestamp(),
    account_id   uuid NOT NULL,
    session_id   uuid,                           -- null for unauthenticated flows (reset)
    change_type  text NOT NULL,                  -- account_created, password_change, email_change,
                                                 -- reset_requested, password_reset, mfa_enabled, ...
    channel      text NOT NULL DEFAULT 'web',
    ip           inet,
    device_fp    text,
    detail       jsonb,
    run_id       text
);
CREATE INDEX ON telemetry.account_change (account_id, ts);

CREATE TABLE telemetry.asset_transfer (
    transfer_id        bigserial PRIMARY KEY,
    ts                 timestamptz(3) NOT NULL DEFAULT clock_timestamp(),
    account_id         uuid NOT NULL,            -- sender
    counterparty       uuid NOT NULL,            -- receiver
    item_id            int NOT NULL,
    asset_value_cents  int NOT NULL,
    session_id         uuid,
    ip                 inet,
    device_fp          text,
    run_id             text
);
CREATE INDEX ON telemetry.asset_transfer (account_id, ts);

CREATE TABLE telemetry.device_fingerprint (
    device_fp_id   text PRIMARY KEY,
    ua_hash        text,
    lang_hash      text,
    sim_hash       text,                         -- from the simulated device header, if any
    first_seen     timestamptz(3) NOT NULL DEFAULT clock_timestamp(),
    last_seen      timestamptz(3) NOT NULL DEFAULT clock_timestamp(),
    seen_count     int NOT NULL DEFAULT 1
);

-- Filled by monitoring rules from Phase 4 on.
CREATE TABLE telemetry.alert (
    alert_id    bigserial PRIMARY KEY,
    ts          timestamptz(3) NOT NULL DEFAULT clock_timestamp(),
    rule_id     text NOT NULL,
    severity    text NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    account_id  uuid,
    run_id      text,
    evidence    jsonb
);
CREATE INDEX ON telemetry.alert (ts);
