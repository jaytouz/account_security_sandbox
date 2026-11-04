from fastapi import HTTPException
from psycopg import Connection
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from .settings import settings

pool = ConnectionPool(
    settings.database_url,
    min_size=1,
    max_size=10,
    kwargs={"row_factory": dict_row},
    open=False,
)


def connection():
    """Pooled connection; commits on clean exit, rolls back on exception."""
    return pool.connection()


def deny(conn: Connection, status: int, code: str, message: str | None = None):
    """Commit what was written so far (telemetry included), then fail the request.

    Without the commit, raising inside `with connection()` would roll back the
    very events that record the failure.
    """
    conn.commit()
    raise HTTPException(status_code=status, detail={"code": code, "message": message or code})
