"""Read-only access to the lab database (role lab_review)."""
import os

import pandas as pd
import streamlit as st
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

DSN = os.environ.get("REVIEW_DATABASE_URL",
                     "postgresql://lab_review:review-dev-only@localhost:5432/lab")


@st.cache_resource
def _pool() -> ConnectionPool:
    return ConnectionPool(DSN, min_size=1, max_size=4, kwargs={"autocommit": True}, open=True)


def query(sql: str, params: dict | None = None) -> pd.DataFrame:
    with _pool().connection() as conn:
        cur = conn.execute(sql, params or {})
        cols = [d.name for d in cur.description]
        return pd.DataFrame(cur.fetchall(), columns=cols)


def one(sql: str, params: dict | None = None) -> dict:
    """First row as a plain dict (Python ints/strings, not numpy types)."""
    with _pool().connection() as conn:
        cur = conn.cursor(row_factory=dict_row)
        return cur.execute(sql, params or {}).fetchone() or {}
