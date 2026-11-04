import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .db import pool
from .routes import account, assets, auth, recovery
from .security import flags

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    pool.open(wait=True, timeout=30)
    yield
    pool.close()


app = FastAPI(
    title="Account Security Lab — account service",
    description="Fake account service for a local, isolated training sandbox. "
                "All accounts and data are synthetic.",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(auth.router)
app.include_router(recovery.router)
app.include_router(account.router)
app.include_router(assets.router)


@app.get("/health", tags=["meta"])
def health():
    with pool.connection() as conn:
        conn.execute("SELECT 1")
    return {"status": "ok"}


@app.get("/defences", tags=["meta"])
def defences():
    """Current defence switches from app/security/config.yaml."""
    return flags.snapshot()
