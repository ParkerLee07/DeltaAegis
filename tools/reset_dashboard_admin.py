#!/usr/bin/env python3
"""Reset or create a DeltaAegis dashboard ADMIN account.

This recovery helper intentionally defaults to the same database path used by
normal local installs: <repo>/data/deltaaegis.db.

It supports interactive use for humans and environment-based password input for
validators/automation. It does not require PYTHONPATH when run from the repo.
"""

from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path
import sqlite3
import sys
import uuid

REPO_ROOT = Path(__file__).resolve().parents[1]

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import deltaaegis as da


DEFAULT_DB_PATH = REPO_ROOT / "data" / "deltaaegis.db"


def prompt_text(label: str, default: str | None = None) -> str:
    if default:
        value = input(f"{label} [{default}]: ").strip()
        return value or default
    return input(f"{label}: ").strip()


def password_from_args(args: argparse.Namespace) -> str:
    if args.password_env:
        value = os.environ.get(args.password_env, "")
        if not value:
            raise SystemExit(f"[FAIL] Environment variable is empty or unset: {args.password_env}")
        return value

    if args.password_stdin:
        value = sys.stdin.read().strip()
        if not value:
            raise SystemExit("[FAIL] No password provided on stdin.")
        return value

    first = getpass.getpass("New admin password, minimum 8 characters: ")
    second = getpass.getpass("Confirm new admin password: ")

    if first != second:
        raise SystemExit("[FAIL] Passwords did not match.")

    return first


def first_admin_username(connection: sqlite3.Connection) -> str | None:
    da.ensure_enterprise_access_schema(connection)

    row = connection.execute(
        """
        SELECT username
        FROM access_users
        WHERE role = 'ADMIN'
        ORDER BY created_at ASC, username ASC
        LIMIT 1
        """
    ).fetchone()

    return str(row["username"]) if row else None


def reset_or_create_admin(
    db_path: Path,
    username: str,
    password: str,
    display_name: str | None = None,
) -> dict[str, str]:
    db_path = Path(db_path).expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    if len(password) < 8:
        raise SystemExit("[FAIL] Password must be at least 8 characters.")

    username = str(username or "").strip()

    if not username:
        raise SystemExit("[FAIL] Username is required.")

    with da.connect(db_path) as connection:
        da.ensure_enterprise_access_schema(connection)
        user = da.access_user_by_username(connection, username)
        now = da.utc_now_text()
        password_hash = da.hash_access_password(password)

        if user:
            connection.execute(
                """
                UPDATE access_users
                SET password_hash = ?,
                    role = 'ADMIN',
                    is_active = 1,
                    display_name = COALESCE(NULLIF(?, ''), display_name, username),
                    updated_at = ?
                WHERE user_id = ?
                """,
                (
                    password_hash,
                    display_name or "",
                    now,
                    user["user_id"],
                ),
            )
            action = "reset"
        else:
            user_id = str(uuid.uuid4())
            connection.execute(
                """
                INSERT INTO access_users (
                    user_id,
                    username,
                    display_name,
                    role,
                    password_hash,
                    is_active,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, 'ADMIN', ?, 1, ?, ?)
                """,
                (
                    user_id,
                    username,
                    display_name or username,
                    password_hash,
                    now,
                    now,
                ),
            )
            action = "created"

        connection.commit()

    return {
        "action": action,
        "username": username,
        "db_path": str(db_path),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Reset or create a DeltaAegis dashboard ADMIN account."
    )

    parser.add_argument(
        "--db",
        default=str(DEFAULT_DB_PATH),
        help="DeltaAegis SQLite database path. Default: %(default)s",
    )
    parser.add_argument(
        "--username",
        help="Admin username to reset or create. If omitted interactively, the first existing ADMIN is used when available.",
    )
    parser.add_argument(
        "--display-name",
        help="Display name to set when creating or updating the admin user.",
    )
    parser.add_argument(
        "--password-env",
        help="Read the new password from the named environment variable.",
    )
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read the new password from stdin.",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Fail instead of prompting for missing username or password.",
    )

    return parser


def main() -> int:
    args = build_parser().parse_args()

    db_path = Path(args.db).expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    username = args.username

    if not username:
        with da.connect(db_path) as connection:
            username = first_admin_username(connection)

    if not username:
        if args.non_interactive:
            raise SystemExit("[FAIL] --username is required in non-interactive mode when no ADMIN exists.")
        username = prompt_text("Admin username", "admin")

    if not (args.password_env or args.password_stdin):
        if args.non_interactive:
            raise SystemExit("[FAIL] Use --password-env or --password-stdin in non-interactive mode.")

    password = password_from_args(args)

    result = reset_or_create_admin(
        db_path=db_path,
        username=username,
        password=password,
        display_name=args.display_name,
    )

    print(
        f"[PASS] {result['action'].capitalize()} ADMIN login for {result['username']} "
        f"using database {result['db_path']}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
