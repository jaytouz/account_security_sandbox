-- Operational tables for the fake account service.
CREATE SCHEMA IF NOT EXISTS app;
CREATE SCHEMA IF NOT EXISTS telemetry;

CREATE TABLE app.account (
    account_id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email               text NOT NULL UNIQUE,
    display_name        text NOT NULL,
    password_hash       text NOT NULL,          -- always argon2
    status              text NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'locked', 'disabled')),
    totp_secret         text,
    totp_enabled        boolean NOT NULL DEFAULT false,
    is_seed             boolean NOT NULL DEFAULT false,
    created_at          timestamptz(3) NOT NULL DEFAULT clock_timestamp(),
    password_changed_at timestamptz(3) NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE app.web_session (
    session_id  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash  bytea NOT NULL UNIQUE,          -- sha256 of the cookie value
    account_id  uuid NOT NULL REFERENCES app.account ON DELETE CASCADE,
    created_at  timestamptz(3) NOT NULL DEFAULT clock_timestamp(),
    expires_at  timestamptz(3) NOT NULL,
    revoked_at  timestamptz(3),
    device_fp   text,
    ip          inet
);
CREATE INDEX ON app.web_session (account_id);

CREATE TABLE app.mfa_challenge (
    challenge_id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash     bytea NOT NULL UNIQUE,
    account_id     uuid NOT NULL REFERENCES app.account ON DELETE CASCADE,
    created_at     timestamptz(3) NOT NULL DEFAULT clock_timestamp(),
    expires_at     timestamptz(3) NOT NULL,
    attempts       int NOT NULL DEFAULT 0,
    completed_at   timestamptz(3)
);

CREATE TABLE app.reset_token (
    token_hash  bytea PRIMARY KEY,
    account_id  uuid NOT NULL REFERENCES app.account ON DELETE CASCADE,
    created_at  timestamptz(3) NOT NULL DEFAULT clock_timestamp(),
    expires_at  timestamptz(3) NOT NULL,
    used_at     timestamptz(3)
);

CREATE TABLE app.item (
    item_id           serial PRIMARY KEY,
    owner_account_id  uuid NOT NULL REFERENCES app.account ON DELETE CASCADE,
    name              text NOT NULL,
    value_cents       int NOT NULL CHECK (value_cents >= 0),
    created_at        timestamptz(3) NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX ON app.item (owner_account_id);
