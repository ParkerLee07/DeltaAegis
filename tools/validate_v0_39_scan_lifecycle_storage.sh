#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

printf '%s\n' \
  "DeltaAegis v0.39 Scan Lifecycle Storage Validator" \
  "================================================="

python3 -m py_compile deltaaegis.py

python3 - <<'PY'
from pathlib import Path
import sqlite3
import tempfile

import deltaaegis


EXPECTED_COLUMNS = {
    "process_pid",
    "heartbeat_at",
}


def table_columns(connection, table):
    return {
        row[1]
        for row in connection.execute(f"PRAGMA table_info({table})")
    }


def require_columns(connection, table, expected, context):
    missing = expected - table_columns(connection, table)

    if missing:
        raise AssertionError(
            f"{context} missing columns: {sorted(missing)}"
        )


with tempfile.TemporaryDirectory(
    prefix="deltaaegis-v039-storage-"
) as temp_dir:
    temp = Path(temp_dir)

    # Fresh-database schema.
    fresh_db = temp / "fresh.db"
    connection = deltaaegis.connect(fresh_db)

    require_columns(
        connection,
        "scan_jobs",
        EXPECTED_COLUMNS,
        "fresh scan_jobs schema",
    )

    job = deltaaegis.create_scan_job(
        connection,
        "192.168.50.0/24",
        Path("/tmp/fake-netsniper.sh"),
        Path("/tmp/fake-netsniper-runs"),
        scan_profile="balanced",
    )
    connection.commit()

    assert job["status"] == "QUEUED"
    assert job["process_pid"] is None
    assert job["heartbeat_at"] is None

    heartbeat = "2026-07-06T16:30:00+00:00"

    deltaaegis.update_scan_job(
        connection,
        job["job_id"],
        process_pid=43210,
        heartbeat_at=heartbeat,
    )
    connection.commit()

    row = connection.execute(
        "SELECT * FROM scan_jobs WHERE job_id = ?",
        (job["job_id"],),
    ).fetchone()

    assert row is not None

    serialized = deltaaegis.scan_job_to_dict(row)

    assert serialized["process_pid"] == 43210
    assert serialized["heartbeat_at"] == heartbeat

    queried_rows = deltaaegis.query_scan_jobs(
        connection,
        limit=10,
    )

    queried_job = next(
        deltaaegis.scan_job_to_dict(item)
        for item in queried_rows
        if item["job_id"] == job["job_id"]
    )

    assert queried_job["process_pid"] == 43210
    assert queried_job["heartbeat_at"] == heartbeat

    connection.close()

    # Simulated pre-v0.39 database.
    legacy_db = temp / "legacy.db"
    legacy = sqlite3.connect(legacy_db)

    legacy.executescript(
        """
        CREATE TABLE scan_jobs (
            job_id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            network_scope TEXT NOT NULL DEFAULT '',
            schedule_id TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            netsniper_path TEXT NOT NULL DEFAULT '',
            runs_dir TEXT NOT NULL DEFAULT '',
            bundle_path TEXT,
            exit_code INTEGER,
            auto_ingest INTEGER NOT NULL DEFAULT 0,
            stdout_log TEXT,
            stderr_log TEXT,
            status_json TEXT NOT NULL DEFAULT '{}',
            message TEXT NOT NULL DEFAULT ''
        );
        """
    )
    legacy.commit()
    legacy.close()

    upgraded = deltaaegis.connect(legacy_db)

    require_columns(
        upgraded,
        "scan_jobs",
        EXPECTED_COLUMNS,
        "upgraded scan_jobs schema",
    )

    upgraded.close()

    # Reopening verifies that migrations are idempotent.
    reopened = deltaaegis.connect(legacy_db)

    require_columns(
        reopened,
        "scan_jobs",
        EXPECTED_COLUMNS,
        "reopened scan_jobs schema",
    )

    reopened.close()

    # Serializer normalization.
    normalized = deltaaegis.scan_job_to_dict(
        {
            "auto_ingest": 0,
            "scan_profile": "",
            "schedule_id": "",
            "process_pid": "",
            "heartbeat_at": "",
            "status_json": "{}",
        }
    )

    assert normalized["process_pid"] is None
    assert normalized["heartbeat_at"] is None
    assert normalized["scan_profile"] == "balanced"

print("PASS: fresh scan_jobs schema")
print("PASS: legacy scan_jobs migration")
print("PASS: migration idempotence")
print("PASS: lifecycle field defaults")
print("PASS: lifecycle field updates")
print("PASS: lifecycle field serialization")
print("PASS: explicit scan-job query coverage")
PY

git diff --check

printf '%s\n' \
  "PASS: DeltaAegis v0.39 scan lifecycle storage validator"
