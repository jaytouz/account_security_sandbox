"""Login risk score. Always computed and logged; only enforced when risk.step_up is on."""
import math

from psycopg import Connection

IMPOSSIBLE_KMH = 900
MIN_DISTANCE_KM = 500


def distance_km(lat1, lon1, lat2, lon2) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 6371 * 2 * math.asin(math.sqrt(a))


def assess(conn: Connection, ctx, account_id) -> tuple[int, list[str]]:
    hist = conn.execute(
        """SELECT count(*) AS n,
                  coalesce(bool_or(device_fp = %(fp)s), false) AS known_device,
                  coalesce(bool_or(geo_country = %(country)s), false) AS known_country
             FROM telemetry.login_event
            WHERE account_id = %(id)s AND result = 'success'""",
        {"id": account_id, "fp": ctx.device_fp, "country": ctx.geo_country},
    ).fetchone()
    if hist["n"] == 0:
        return 0, ["first_login"]

    score, reasons = 0, []
    if not hist["known_device"]:
        score, reasons = score + 1, reasons + ["new_device"]
    if ctx.geo_country and not hist["known_country"]:
        score, reasons = score + 2, reasons + ["new_country"]
    if ctx.ip_type == "datacenter":
        score, reasons = score + 2, reasons + ["datacenter_ip"]

    if ctx.geo_lat is not None:
        last = conn.execute(
            """SELECT geo_lat, geo_lon, extract(epoch FROM clock_timestamp() - ts) AS age_s
                 FROM telemetry.login_event
                WHERE account_id = %s AND result = 'success' AND geo_lat IS NOT NULL
                ORDER BY ts DESC LIMIT 1""",
            (account_id,),
        ).fetchone()
        if last:
            km = distance_km(last["geo_lat"], last["geo_lon"], ctx.geo_lat, ctx.geo_lon)
            hours = max(float(last["age_s"]), 1.0) / 3600
            if km > MIN_DISTANCE_KM and km / hours > IMPOSSIBLE_KMH:
                score, reasons = score + 3, reasons + ["impossible_travel"]
    return score, reasons
