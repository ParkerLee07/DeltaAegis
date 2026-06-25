#!/usr/bin/env python3
"""Reset or create a local DeltaAegis dashboard ADMIN account."""
from __future__ import annotations

from datetime import datetime, timezone
import getpass
import sqlite3
import sys

import deltaaegis as da


def main() -> int:
    db_path = input("DeltaAegis DB path [deltaaegis.db]: ").strip() or "deltaaegis.db"
    username = input("Admin username [parker.admin]: ").strip() or "parker.admin"
    password = getpass.getpass("New admin password, minimum 8 characters: ")

    if len(password) < 8:
        print("[FAIL] Password must be at least 8 characters.", file=sys.stderr)
        return 1

    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row

    try:
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(access_users)").fetchall()
        }

        if "username" not in columns:
            print("[FAIL] access_users table not found or schema is missing username column.", file=sys.stderr)
            return 1

        existing = connection.execute(
            "SELECT * FROM access_users WHERE username = ?",
            (username,),
        ).fetchone()

        if existing is None:
            da.create_access_user(
                connection,
                username,
                display_name=username,
                role="ADMIN",
                password=password,
            )
            print(f"[PASS] Created ADMIN user: {username}")
        else:
            updates = []
            values = []

            if "password_hash" in columns:
                updates.append("password_hash = ?")
                values.append(da.hash_access_password(password))

            if "role" in columns:
                updates.append("role = ?")
                values.append("ADMIN")

            if "is_enabled" in columns:
                updates.append("is_enabled = ?")
                values.append(1)

            if "enabled" in columns:
                updates.append("enabled = ?")
                values.append(1)

            if "updated_at" in columns:
                updates.append("updated_at = ?")
                values.append(datetime.now(timezone.utc).isoformat())

            if not updates:
                print("[FAIL] No compatible columns found to update access user.", file=sys.stderr)
                return 1

            values.append(username)
            connection.execute(
                f"UPDATE access_users SET {', '.join(updates)} WHERE username = ?",
                values,
            )
            print(f"[PASS] Reset password, enabled user, and set role ADMIN for: {username}")

        connection.commit()
        return 0
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
