-- History of defence switches, so each run can be read against the
-- defences that were on at the time.
CREATE TABLE telemetry.defence_change (
    change_id  bigserial PRIMARY KEY,
    ts         timestamptz(3) NOT NULL DEFAULT clock_timestamp(),
    flag       text NOT NULL,                 -- e.g. baseline.generic_errors
    enabled    boolean NOT NULL,
    actor      text NOT NULL                  -- startup, admin_api
);
CREATE INDEX ON telemetry.defence_change (flag, ts);
