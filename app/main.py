import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from telemetry import events, migrate

from .db import pool
from .routes import account, admin, assets, auth, recovery
from .security import flags
from .settings import settings

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("lab.app")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    applied = migrate.run(settings.database_url, settings.review_db_password or None)
    if applied:
        log.info("Applied migrations: %s", ", ".join(applied))
    pool.open(wait=True, timeout=30)
    with pool.connection() as conn:
        changed = events.record_defence_state(conn, flags.flatten(), actor="startup")
        if changed:
            log.info("Defence state logged at startup: %s", ", ".join(changed))
    yield
    pool.close()


app = FastAPI(
    title="Account Security Lab — account service",
    description="Fake account service for a local, isolated training sandbox. "
                "All accounts and data are synthetic.",
    version="0.2.0",
    lifespan=lifespan,
)

app.include_router(auth.router)
app.include_router(recovery.router)
app.include_router(account.router)
app.include_router(assets.router)
app.include_router(admin.router)


@app.get("/health", tags=["meta"])
def health():
    with pool.connection() as conn:
        conn.execute("SELECT 1")
    return {"status": "ok"}


@app.get("/defences", tags=["meta"])
def defences():
    """Current defence switches from app/security/config.yaml."""
    return flags.snapshot()
