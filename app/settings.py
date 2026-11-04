import os
from dataclasses import dataclass


def _bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    database_url: str = os.environ.get(
        "DATABASE_URL", "postgresql://lab:lab-dev-only@localhost:5432/lab"
    )
    smtp_host: str = os.environ.get("SMTP_HOST", "localhost")
    smtp_port: int = int(os.environ.get("SMTP_PORT", "1025"))
    mail_from: str = os.environ.get("MAIL_FROM", "no-reply@lab.test")
    base_url: str = os.environ.get("APP_BASE_URL", "http://127.0.0.1:8000")
    # When true, X-Lab-Sim-* headers override the observed IP / geo / device.
    # Only for the scenario runner inside the sandbox.
    trust_sim_headers: bool = _bool("LAB_TRUST_SIM_HEADERS", False)
    security_config: str = os.environ.get(
        "SECURITY_CONFIG", os.path.join(os.path.dirname(__file__), "security", "config.yaml")
    )
    # Shared secret for /admin (used by the review dashboard). Empty = admin API off.
    admin_token: str = os.environ.get("LAB_ADMIN_TOKEN", "")
    # Password for the read-only lab_review database role. Empty = role not managed.
    review_db_password: str = os.environ.get("LAB_REVIEW_DB_PASSWORD", "")
    session_ttl_minutes: int = int(os.environ.get("SESSION_TTL_MINUTES", "720"))
    mfa_challenge_ttl_seconds: int = 300
    reset_token_ttl_minutes: int = 30


settings = Settings()
