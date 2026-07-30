#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import concurrent.futures
import json
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request(url: str, token: str | None = None, timeout: float = 5.0):
    headers = {}
    if token:
        headers["X-DeltaAegis-Token"] = token
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.status, response.read(), dict(response.headers)


def static_checks(repo: Path) -> list[str]:
    delta = (repo / "deltaaegis.py").read_text(encoding="utf-8")
    web = (repo / "deltaaegis_core/web.py").read_text(encoding="utf-8")
    ast.parse(delta)
    ast.parse(web)
    require(delta.count("def connect_runtime(db_path: Path) -> sqlite3.Connection:") == 1,
            "connect_runtime definition is missing or duplicated")
    runtime_block = delta.split("def connect_runtime", 1)[1].split("def load_json", 1)[0]
    require("run_migrations" not in runtime_block,
            "connect_runtime re-enters migrations")
    require("return open_database_connection(Path(db_path).expanduser())" in runtime_block,
            "connect_runtime does not use the low-level connection helper")
    require(delta.count("connection = connect_runtime(db_path)") == 3,
            "dashboard worker runtime-connection inventory differs")
    require("dashboard_migration_connection = connect(db_path)" in web,
            "dashboard startup migration boundary is missing")
    require("dashboard_migration_connection.close()" in web,
            "dashboard startup migration connection is not closed")
    require("return connect_runtime(db_path)" in web,
            "request handler does not use runtime connections")
    require("startup_watchdog_connection = connect_runtime(db_path)" in web,
            "startup watchdog does not use a runtime connection")
    require('if route == "/favicon.ico":' in web,
            "public favicon route is missing")
    require('dashboard_text_response(self, "", status=204)' in web,
            "favicon route does not return 204")
    favicon_index = web.index('if route == "/favicon.ico":')
    permission_index = web.index('if not self.require_permission("dashboard.read"):', favicon_index)
    require(favicon_index < permission_index,
            "favicon route is still behind dashboard authentication")
    return [
        "runtime connection is migration-free",
        "three background worker connections are migration-free",
        "dashboard migrates once before threaded service",
        "request and watchdog connections are runtime-only",
        "favicon route is public and returns 204",
    ]


def dynamic_module_checks(repo: Path, root: Path) -> list[str]:
    sys.path.insert(0, str(repo))
    import deltaaegis as module

    db = root / "module.db"
    connection = module.connect(db)
    connection.close()

    calls = []
    original = module._migrations.run_migrations

    def counted(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    module._migrations.run_migrations = counted
    try:
        for _ in range(8):
            connection = module.connect_runtime(db)
            try:
                connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()
            finally:
                connection.close()
    finally:
        module._migrations.run_migrations = original

    require(not calls, "runtime connections invoked the migration runner")

    blocker = sqlite3.connect(db, timeout=1.0, check_same_thread=False)
    blocker.execute("BEGIN IMMEDIATE")

    def read_under_reservation(index: int):
        connection = module.connect_runtime(db)
        try:
            value = connection.execute(
                "SELECT COUNT(*) FROM schema_migrations"
            ).fetchone()[0]
            return index, int(value)
        finally:
            connection.close()

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(read_under_reservation, range(32)))
    finally:
        blocker.rollback()
        blocker.close()

    require(len(results) == 32, "not all runtime readers completed")
    expected_migration_count = len(module.deltaaegis_schema_migrations())
    require(
        all(value == expected_migration_count for _, value in results),
        "runtime readers returned an unexpected migration ledger",
    )

    connection = sqlite3.connect(db)
    try:
        quick = [row[0] for row in connection.execute("PRAGMA quick_check")]
    finally:
        connection.close()
    require(quick == ["ok"], "temporary database failed quick_check")

    return [
        "eight runtime opens invoked zero migrations",
        "32 concurrent runtime reads succeeded under a reserved writer lock",
        "temporary database integrity remained healthy",
    ]


def dashboard_checks(repo: Path, root: Path) -> list[str]:
    db = root / "dashboard.db"
    events = root / "events.jsonl"
    token = "deltaaegis-hotfix-validator-token"
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    stdout_path = root / "dashboard.stdout.log"
    stderr_path = root / "dashboard.stderr.log"

    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        process = subprocess.Popen(
            [
                sys.executable,
                str(repo / "deltaaegis.py"),
                "--db", str(db),
                "--events", str(events),
                "dashboard",
                "--host", "127.0.0.1",
                "--port", str(port),
                "--token", token,
                "--no-enable-scheduled-scans",
                "--quiet",
            ],
            cwd=repo,
            env=env,
            stdout=stdout,
            stderr=stderr,
        )

    try:
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            try:
                status, body, _ = request(base + "/healthz", timeout=1.0)
                if status == 200 and body == b"ok":
                    break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("dashboard did not become ready")

        require(process.poll() is None,
                "dashboard exited before readiness validation")

        status, body, _ = request(base + "/favicon.ico", timeout=3.0)
        require(status == 204, f"favicon returned HTTP {status}, not 204")
        require(body == b"", "favicon 204 response contains a body")

        blocker = sqlite3.connect(db, timeout=1.0, check_same_thread=False)
        blocker.execute("BEGIN IMMEDIATE")

        def fetch_summary(index: int):
            status, body, _ = request(
                base + "/api/summary",
                token=token,
                timeout=10.0,
            )
            payload = json.loads(body.decode("utf-8"))
            return index, status, payload

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
                results = list(pool.map(fetch_summary, range(48)))
        finally:
            blocker.rollback()
            blocker.close()

        require(len(results) == 48, "not all dashboard requests completed")
        require(all(status == 200 for _, status, _ in results),
                "one or more dashboard summary requests failed")
        require(all(isinstance(payload, dict) for _, _, payload in results),
                "one or more dashboard responses were not JSON objects")

    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

    stdout_text = stdout_path.read_text(encoding="utf-8", errors="replace")
    stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
    combined = stdout_text + "\n" + stderr_text
    require("database is locked" not in combined.lower(),
            "dashboard emitted database-is-locked after the fix")
    require("traceback (most recent call last)" not in combined.lower(),
            "dashboard emitted a traceback during concurrency validation")
    require(process.returncode in {0, -signal.SIGINT},
            f"dashboard exited unexpectedly with {process.returncode}")

    connection = sqlite3.connect(db)
    try:
        quick = [row[0] for row in connection.execute("PRAGMA quick_check")]
    finally:
        connection.close()
    require(quick == ["ok"], "dashboard test database failed quick_check")

    return [
        "live dashboard favicon returned public HTTP 204",
        "48 concurrent summary requests passed under a reserved writer lock",
        "dashboard emitted no lock errors or tracebacks",
        "dashboard test database integrity remained healthy",
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    repo = args.repo.expanduser().resolve()
    checks = []
    with tempfile.TemporaryDirectory(prefix="deltaaegis-v1-lock-hotfix-") as tmp:
        root = Path(tmp)
        checks.extend(static_checks(repo))
        checks.extend(dynamic_module_checks(repo, root))
        checks.extend(dashboard_checks(repo, root))
    record = {"assessment": "PASS", "checks": checks, "check_count": len(checks)}
    if args.output:
        args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    for check in checks:
        print(f"PASS: {check}")
    print(f"PASS: {len(checks)} DeltaAegis dashboard-lock hotfix checks")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
