"""Run inside the app container to confirm the sandbox has no route out.

    docker compose exec app python scripts/check_isolation.py

Passes when outbound connections fail and the database is reachable.
"""
import socket
import sys

OUTBOUND = [("1.1.1.1", 443), ("8.8.8.8", 53), ("example.com", 443)]
INSIDE = [("db", 5432), ("mail", 1025)]


def reachable(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=3):
            return True
    except OSError:
        return False


ok = True
for host, port in OUTBOUND:
    if reachable(host, port):
        print(f"FAIL  outbound {host}:{port} is reachable")
        ok = False
    else:
        print(f"ok    outbound {host}:{port} blocked")
for host, port in INSIDE:
    if reachable(host, port):
        print(f"ok    internal {host}:{port} reachable")
    else:
        print(f"FAIL  internal {host}:{port} not reachable")
        ok = False

print("ISOLATED" if ok else "NOT ISOLATED — do not run scenarios until this passes")
sys.exit(0 if ok else 1)
