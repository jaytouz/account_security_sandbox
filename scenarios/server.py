"""Internal API for the dashboard's Scenarios tab. Only reachable on the lab network."""
import threading

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from . import library  # noqa: F401 - registers the scenarios
from .base import REGISTRY, run_scenario

app = FastAPI(title="Lab scenario runner (internal)")
_busy = threading.Lock()


class RunIn(BaseModel):
    scenario: str


@app.get("/health")
def health():
    return {"status": "ok", "busy": _busy.locked()}


@app.get("/scenarios")
def scenarios():
    return [sc.meta() for sc in REGISTRY.values()]


@app.post("/runs")
def run(body: RunIn):
    if body.scenario not in REGISTRY:
        raise HTTPException(404, f"Unknown scenario {body.scenario}")
    if not _busy.acquire(blocking=False):
        raise HTTPException(409, "Another scenario is running.")
    try:
        return run_scenario(body.scenario, log=lambda *_: None)
    finally:
        _busy.release()
