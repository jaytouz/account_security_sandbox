"""Seed fictional accounts and inventory.

    docker compose run --rm seed            # --reset is the compose default

Writes the generated test credentials to data/out/seed_accounts.csv
(git-ignored). Every account is fake and uses the reserved .test domain.
"""
import argparse
import csv
import os
import random
import secrets

import psycopg
import pyotp

from app.security.passwords import hash_password
from telemetry import migrate

FIRST = ["Ada", "Bram", "Cleo", "Dov", "Esme", "Finn", "Greta", "Hugo", "Ines", "Jory",
         "Kaia", "Lior", "Mira", "Nils", "Odile", "Pax", "Quinn", "Rosa", "Sami", "Tove"]
LAST = ["Fenwick", "Oakridge", "Marlow", "Thistle", "Vane", "Harrow", "Quill", "Ashby",
        "Brook", "Calder", "Dunmore", "Ellery", "Frost", "Gale", "Hollis", "Ivers",
        "Kestrel", "Lark", "Moss", "Nettle"]
ITEMS = ["Copper Lantern", "Glass Compass", "Silver Key", "Amber Charm", "Iron Gauntlet",
         "Velvet Cloak", "Jade Token", "Brass Telescope", "Opal Ring", "Oak Staff"]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--accounts", type=int, default=20)
    ap.add_argument("--items-per-account", type=int, default=5)
    ap.add_argument("--totp-every", type=int, default=5, help="every Nth account gets TOTP on")
    ap.add_argument("--reset", action="store_true", help="delete existing seed accounts first")
    ap.add_argument("--wipe-telemetry", action="store_true", help="also empty all telemetry tables")
    ap.add_argument("--rng-seed", type=int, default=7, help="names and items are reproducible")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "out", "seed_accounts.csv"))
    args = ap.parse_args()

    if args.accounts > len(FIRST) * len(LAST):
        raise SystemExit("Too many accounts for the name list.")

    rng = random.Random(args.rng_seed)
    names = [(f, l) for f in FIRST for l in LAST]
    rng.shuffle(names)

    migrate.run(os.environ["DATABASE_URL"], os.environ.get("LAB_REVIEW_DB_PASSWORD"))

    rows = []
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        if args.reset:
            conn.execute("DELETE FROM app.account WHERE is_seed")
        if args.wipe_telemetry:
            conn.execute("TRUNCATE telemetry.login_event, telemetry.session, telemetry.account_change, "
                         "telemetry.asset_transfer, telemetry.device_fingerprint, telemetry.alert")
            # defence_change is kept: it describes the lab, not the run.

        for i, (first, last) in enumerate(names[: args.accounts], start=1):
            email = f"{first}.{last}@lab.test".lower()
            password = secrets.token_urlsafe(12)
            totp_secret = pyotp.random_base32() if args.totp_every and i % args.totp_every == 0 else None
            (account_id,) = conn.execute(
                """INSERT INTO app.account (email, display_name, password_hash, totp_secret,
                                            totp_enabled, is_seed)
                   VALUES (%s, %s, %s, %s, %s, true) RETURNING account_id""",
                (email, f"{first} {last}", hash_password(password), totp_secret, totp_secret is not None),
            ).fetchone()
            for _ in range(args.items_per_account):
                conn.execute(
                    "INSERT INTO app.item (owner_account_id, name, value_cents) VALUES (%s, %s, %s)",
                    (account_id, rng.choice(ITEMS), rng.randrange(100, 50_000, 25)),
                )
            rows.append({"email": email, "password": password, "totp_secret": totp_secret or "",
                         "account_id": str(account_id)})

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["email", "password", "totp_secret", "account_id"])
        w.writeheader()
        w.writerows(rows)
    print(f"Seeded {len(rows)} accounts ({sum(1 for r in rows if r['totp_secret'])} with TOTP). "
          f"Test credentials: {args.out}")


if __name__ == "__main__":
    main()
