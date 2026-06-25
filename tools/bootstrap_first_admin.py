#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import inspect
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

import deltaaegis as da


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create the first DeltaAegis dashboard ADMIN account when no local accounts exist."
    )
    parser.add_argument("--db", default="deltaaegis.db", help="DeltaAegis SQLite database path.")
    parser.add_argument("--username", default=None, help="Admin username.")
    parser.add_argument("--password", default=None, help="Admin password. Prefer the prompt over this flag.")
    parser.add_argument("--display-name", default=None, help="Admin display name.")
    parser.add_argument("--non-interactive", action="store_true", help="Do not prompt.")
    return parser.parse_args()


def table_exists(connection: sqlite3.Connection, table_name: str) -> bool:
    row = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name = ?",
        (table_name,),
    ).fetchone()
    return row is not None


def call_schema_candidate(name: str, connection: sqlite3.Connection, db_path: Path) -> bool:
    obj = getattr(da, name, None)
    if not callable(obj):
        return False

    try:
        source = inspect.getsource(obj)
    except Exception:
        source = ""

    name_l = name.lower()
    source_l = source.lower()

    looks_relevant = (
        "access_users" in source_l
        or "create table" in source_l
        or "schema" in name_l
        or "migration" in name_l
        or ("database" in name_l and ("init" in name_l or "ensure" in name_l or "create" in name_l))
    )

    if not looks_relevant:
        return False

    attempts = [
        (connection,),
        (db_path,),
        (str(db_path),),
        (),
    ]

    for args in attempts:
        try:
            obj(*args)
            return True
        except TypeError:
            continue
        except Exception:
            continue

    return False


def initialize_access_schema(connection: sqlite3.Connection, db_path: Path) -> None:
    if table_exists(connection, "access_users"):
        return

    preferred_names = [
        "ensure_database_schema",
        "ensure_access_schema",
        "ensure_schema",
        "initialize_database",
        "init_database",
        "init_db",
        "create_schema",
        "create_tables",
        "migrate_database",
        "run_migrations",
    ]

    tried = set()

    for name in preferred_names:
        tried.add(name)
        call_schema_candidate(name, connection, db_path)
        if table_exists(connection, "access_users"):
            return

    for name in dir(da):
        if name in tried:
            continue
        lower = name.lower()
        if not any(word in lower for word in ("schema", "database", "migrat", "table", "init")):
            continue

        call_schema_candidate(name, connection, db_path)
        if table_exists(connection, "access_users"):
            return

    # Last resort: start the dashboard briefly against the DB. The dashboard
    # startup path creates/migrates the DB schema in current DeltaAegis builds.
    port = "18765"
    process = subprocess.Popen(
        [
            sys.executable,
            str(REPO_ROOT / "deltaaegis.py"),
            "--db",
            str(db_path),
            "dashboard",
            "--host",
            "127.0.0.1",
            "--port",
            port,
            "--require-login",
        ],
        cwd=str(REPO_ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    try:
        import time
        deadline = time.time() + 4
        while time.time() < deadline:
            if table_exists(connection, "access_users"):
                return
            time.sleep(0.1)
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)

    if not table_exists(connection, "access_users"):
        raise SystemExit(
            "[FAIL] access_users table is missing and the bootstrap helper could not initialize the schema."
        )


def access_user_count(connection: sqlite3.Connection) -> int:
    row = connection.execute("SELECT COUNT(*) AS count FROM access_users").fetchone()
    return int(row["count"] if "count" in row.keys() else row[0])


def main() -> int:
    args = parse_args()

    username = args.username or os.environ.get("DELTAAEGIS_ADMIN_USERNAME")
    password = args.password or os.environ.get("DELTAAEGIS_ADMIN_PASSWORD")
    display_name = args.display_name or os.environ.get("DELTAAEGIS_ADMIN_DISPLAY_NAME")

    if not args.non_interactive:
        if not username:
            username = input("Create DeltaAegis admin username [admin]: ").strip() or "admin"
        if not display_name:
            display_name = input(f"Display name [{username}]: ").strip() or username
        if not password:
            password = getpass.getpass("Create DeltaAegis admin password, minimum 8 characters: ")
            confirm = getpass.getpass("Confirm DeltaAegis admin password: ")
            if password != confirm:
                raise SystemExit("[FAIL] Passwords do not match.")

    if not username:
        raise SystemExit("[FAIL] Admin username is required.")

    if not password:
        raise SystemExit("[FAIL] Admin password is required.")

    if len(password) < 8:
        raise SystemExit("[FAIL] Admin password must be at least 8 characters.")

    db_path = Path(args.db).expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row

    try:
        initialize_access_schema(connection, db_path)
        connection.commit()

        count = access_user_count(connection)

        if count > 0:
            print(f"[SKIP] Dashboard account setup skipped. Existing local dashboard accounts: {count}")
            return 0

        da.create_access_user(
            connection,
            username,
            display_name=display_name or username,
            role="ADMIN",
            password=password,
        )
        connection.commit()
        print(f"[PASS] Created first DeltaAegis ADMIN account: {username}")
        print("[INFO] Start dashboard with the same DB path used during install.")
        return 0
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
