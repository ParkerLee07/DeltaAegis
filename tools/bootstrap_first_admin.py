#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import os
import sqlite3
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

import deltaaegis as da


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create the first DeltaAegis dashboard ADMIN account when no local accounts exist."
    )
    parser.add_argument(
        "--db",
        default=str(REPO_ROOT / "data" / "deltaaegis.db"),
        help="DeltaAegis SQLite database path. Default: %(default)s",
    )
    parser.add_argument("--username", default=None, help="Admin username.")
    parser.add_argument("--password", default=None, help="Admin password. Prefer the prompt over this flag.")
    parser.add_argument("--display-name", default=None, help="Admin display name.")
    parser.add_argument("--non-interactive", action="store_true", help="Do not prompt.")
    return parser.parse_args()


def access_user_count(connection: sqlite3.Connection) -> int:
    row = connection.execute("SELECT COUNT(*) AS count FROM access_users").fetchone()
    return int(row["count"] if "count" in row.keys() else row[0])


def initialized_access_user_count(db_path: Path) -> int:
    # The public connection path owns v1 schema initialization. Bypassing it
    # here would create an unledgered database during installation.
    with da.connect(db_path) as connection:
        return access_user_count(connection)


def main() -> int:
    args = parse_args()

    db_path = Path(args.db).expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    count = initialized_access_user_count(db_path)
    if count > 0:
        print(
            "[SKIP] Dashboard account setup skipped. "
            f"Existing local dashboard accounts: {count}"
        )
        return 0

    username = args.username or os.environ.get("DELTAAEGIS_ADMIN_USERNAME")
    password = args.password or os.environ.get("DELTAAEGIS_ADMIN_PASSWORD")
    display_name = (
        args.display_name
        or os.environ.get("DELTAAEGIS_ADMIN_DISPLAY_NAME")
    )

    if not args.non_interactive:
        if not username:
            username = (
                input("Create DeltaAegis admin username [admin]: ").strip()
                or "admin"
            )
        if not display_name:
            display_name = (
                input(f"Display name [{username}]: ").strip()
                or username
            )
        if not password:
            password = getpass.getpass(
                "Create DeltaAegis admin password, minimum 8 characters: "
            )
            confirm = getpass.getpass(
                "Confirm DeltaAegis admin password: "
            )
            if password != confirm:
                raise SystemExit("[FAIL] Passwords do not match.")

    if not username:
        raise SystemExit("[FAIL] Admin username is required.")

    if not password:
        raise SystemExit("[FAIL] Admin password is required.")

    if len(password) < 8:
        raise SystemExit(
            "[FAIL] Admin password must be at least 8 characters."
        )

    with da.connect(db_path) as connection:
        # Recheck after collecting credentials so a concurrent first-admin
        # creation cannot result in a second account.
        connection.execute("BEGIN IMMEDIATE")
        try:
            count = access_user_count(connection)
            if count > 0:
                connection.commit()
                print(
                    "[SKIP] Dashboard account setup skipped. "
                    f"Existing local dashboard accounts: {count}"
                )
                return 0

            da.create_access_user(
                connection,
                username,
                display_name=display_name or username,
                role="ADMIN",
                password=password,
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        print(
            f"[PASS] Created first DeltaAegis ADMIN account: {username}"
        )
        print(
            "[INFO] Start dashboard with the same DB path used during install."
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
