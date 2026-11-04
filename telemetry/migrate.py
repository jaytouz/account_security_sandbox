"""Applies telemetry/migrations/*.sql in order, once each, and keeps the
read-only review role in shape. Called by the app at startup and by the seed.

    python -m telemetry.migrate        # manual run, uses DATABASE_URL
"""
import os
import pathlib

import psycopg
from psycopg import sql

MIGRATIONS = pathlib.Path(__file__).parent / "migrations"
LOCK_ID = 727001  # any constant; serialises concurrent runs (app + seed)

# Written by the Phase 1 Postgres init scripts, before this runner existed.
_PHASE1 = ("001_app.sql", "002_telemetry.sql")

# Columns the dashboard may read from app tables. Password hashes, TOTP
# secrets and session/reset token hashes are deliberately left out.
_REVIEW_COLUMNS = {
    "app.account": ["account_id", "email", "display_name", "status", "totp_enabled",
                    "is_seed", "created_at", "password_changed_at"],
    "app.web_session": ["session_id", "account_id", "created_at", "expires_at",
                        "revoked_at", "device_fp", "ip"],
    "app.item": ["item_id", "owner_account_id", "name", "value_cents"],
}


def run(database_url: str, review_password: str | None = None) -> list[str]:
    applied_now = []
    with psycopg.connect(database_url) as conn:
        conn.execute("SELECT pg_advisory_lock(%s)", (LOCK_ID,))
        try:
            conn.execute("""CREATE TABLE IF NOT EXISTS public.schema_migration (
                                name text PRIMARY KEY,
                                applied_at timestamptz NOT NULL DEFAULT now())""")
            applied = {r[0] for r in conn.execute("SELECT name FROM public.schema_migration")}

            if not applied and conn.execute("SELECT to_regclass('app.account')").fetchone()[0]:
                for name in _PHASE1:
                    conn.execute("INSERT INTO public.schema_migration (name) VALUES (%s)", (name,))
                applied.update(_PHASE1)

            for f in sorted(MIGRATIONS.glob("*.sql")):
                if f.name in applied:
                    continue
                conn.execute(f.read_text(encoding="utf-8"))
                conn.execute("INSERT INTO public.schema_migration (name) VALUES (%s)", (f.name,))
                applied_now.append(f.name)

            if review_password:
                _ensure_review_role(conn, review_password)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.execute("SELECT pg_advisory_unlock(%s)", (LOCK_ID,))
            conn.commit()
    return applied_now


def _ensure_review_role(conn: psycopg.Connection, password: str) -> None:
    exists = conn.execute("SELECT 1 FROM pg_roles WHERE rolname = 'lab_review'").fetchone()
    verb = "ALTER" if exists else "CREATE"
    conn.execute(sql.SQL(verb + " ROLE lab_review LOGIN PASSWORD {}").format(sql.Literal(password)))
    conn.execute("GRANT USAGE ON SCHEMA app, telemetry TO lab_review")
    conn.execute("GRANT SELECT ON ALL TABLES IN SCHEMA telemetry TO lab_review")
    conn.execute("ALTER DEFAULT PRIVILEGES IN SCHEMA telemetry GRANT SELECT ON TABLES TO lab_review")
    for table, cols in _REVIEW_COLUMNS.items():
        schema, name = table.split(".")
        conn.execute(sql.SQL("GRANT SELECT ({}) ON {} TO lab_review").format(
            sql.SQL(", ").join(map(sql.Identifier, cols)), sql.Identifier(schema, name)))


if __name__ == "__main__":
    done = run(os.environ["DATABASE_URL"], os.environ.get("LAB_REVIEW_DB_PASSWORD"))
    print("applied:", ", ".join(done) if done else "nothing new")
