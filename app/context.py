"""Who/where/what-device a request came from, as recorded in telemetry.

Inside the sandbox every client shares one Docker IP, so the scenario runner
can describe a synthetic origin through X-Lab-Sim-* headers. They are honoured
only when LAB_TRUST_SIM_HEADERS is on.
"""
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field

from fastapi import Request

from .settings import settings

_RUN_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def _h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


@dataclass
class RequestContext:
    ip: str | None
    asn: int | None = None
    ip_type: str | None = None
    geo_country: str | None = None
    geo_lat: float | None = None
    geo_lon: float | None = None
    user_agent: str | None = None
    device_fp: str = ""
    device_components: dict = field(default_factory=dict)
    run_id: str | None = None


def _valid_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def get_context(request: Request) -> RequestContext:
    h = request.headers
    ctx = RequestContext(ip=request.client.host if request.client else None)
    ctx.user_agent = (h.get("user-agent") or "")[:512]

    sim_device = ""
    if settings.trust_sim_headers:
        ctx.ip = _valid_ip(h.get("x-lab-sim-ip")) or ctx.ip
        asn = h.get("x-lab-sim-asn", "")
        ctx.asn = int(asn) if asn.isdigit() else None
        ctx.ip_type = (h.get("x-lab-sim-ip-type") or "")[:32] or None
        # Format: "FR;48.85;2.35"
        geo = (h.get("x-lab-sim-geo") or "").split(";")
        if len(geo) == 3:
            try:
                ctx.geo_country = geo[0][:2].upper() or None
                ctx.geo_lat, ctx.geo_lon = float(geo[1]), float(geo[2])
            except ValueError:
                ctx.geo_country = ctx.geo_lat = ctx.geo_lon = None
        sim_device = (h.get("x-lab-sim-device") or "")[:128]

    run_id = h.get("x-lab-run-id")
    ctx.run_id = run_id if run_id and _RUN_ID.match(run_id) else None

    ctx.device_components = {
        "ua_hash": _h(ctx.user_agent),
        "lang_hash": _h(h.get("accept-language") or ""),
        "sim_hash": _h(sim_device) if sim_device else None,
    }
    ctx.device_fp = hashlib.sha256(
        json.dumps(ctx.device_components, sort_keys=True).encode()
    ).hexdigest()[:24]
    return ctx
