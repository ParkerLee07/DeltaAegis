#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "[v0.38 checkpoint 1] syntax check"
python3 -m py_compile deltaaegis.py

echo "[v0.38 checkpoint 1] static contract checks"
python3 - <<'PY'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")

required = [
    "run_trueaegis_after_ingest INTEGER NOT NULL DEFAULT 0",
    'ensure_column(connection, "scan_schedules", "run_trueaegis_after_ingest"',
    'item["run_trueaegis_after_ingest"] = bool(item.get("run_trueaegis_after_ingest"))',
    "run_trueaegis_after_ingest: bool = False",
    "1 if run_trueaegis_after_ingest else 0",
    'payload.get("run_trueaegis_after_ingest")',
    "--trueaegis-after-ingest",
    "trueaegis_after_ingest=",
    "v0.38.0-dev",
]

for needle in required:
    if needle not in text:
        raise SystemExit(f"missing v0.38 intent marker: {needle}")

start = text.find("def run_due_scan_schedules(")
if start < 0:
    raise SystemExit("could not locate run_due_scan_schedules")

end = text.find("\ndef ", start + 1)
if end < 0:
    raise SystemExit("could not locate end of run_due_scan_schedules")

run_due_block = text[start:end]

for forbidden in [
    "dashboard_trueaegis_validation_start_payload",
    "create_trueaegis_job(",
    "execute_trueaegis_job(",
    "dashboard_start_trueaegis_job_thread",
]:
    if forbidden in run_due_block:
        raise SystemExit(f"checkpoint 1 must not execute TrueAegis from schedules yet: {forbidden}")

print("static checks passed")
PY

echo "[v0.38 checkpoint 1] functional schedule intent smoke test"
python3 - <<'PY'
from pathlib import Path
import tempfile
import deltaaegis

with tempfile.TemporaryDirectory() as tmp:
    db = Path(tmp) / "deltaaegis-v0.38-cp1.db"
    conn = deltaaegis.connect(db)

    default_schedule = deltaaegis.create_scan_schedule(
        conn,
        name="default no trueaegis",
        target="192.168.40.0/24",
        cadence_minutes=120,
        auto_ingest=True,
        scan_profile="accurate",
        enabled=True,
    )

    if default_schedule["run_trueaegis_after_ingest"] is not False:
        raise SystemExit("default schedule should not enable TrueAegis follow-up intent")

    enabled_schedule = deltaaegis.create_scan_schedule(
        conn,
        name="intent trueaegis",
        target="192.168.41.0/24",
        cadence_minutes=120,
        auto_ingest=True,
        scan_profile="accurate",
        enabled=True,
        run_trueaegis_after_ingest=True,
    )

    if enabled_schedule["run_trueaegis_after_ingest"] is not True:
        raise SystemExit("schedule did not preserve TrueAegis follow-up intent")

    rows = deltaaegis.query_scan_schedules(conn)
    mapped = {row["schedule_id"]: deltaaegis.scan_schedule_to_dict(row) for row in rows}

    if mapped[default_schedule["schedule_id"]]["run_trueaegis_after_ingest"] is not False:
        raise SystemExit("query_scan_schedules default intent should be false")

    if mapped[enabled_schedule["schedule_id"]]["run_trueaegis_after_ingest"] is not True:
        raise SystemExit("query_scan_schedules enabled intent should be true")

    payload = deltaaegis.dashboard_netsniper_schedule_create_payload(
        conn,
        {
            "name": "dashboard intent",
            "target": "192.168.42.0/24",
            "cadence_minutes": 120,
            "scan_profile": "accurate",
            "auto_ingest": True,
            "run_trueaegis_after_ingest": True,
        },
    )

    if payload["schedule"]["run_trueaegis_after_ingest"] is not True:
        raise SystemExit("dashboard schedule-create did not preserve TrueAegis follow-up intent")

    conn.close()

print("functional smoke test passed")
PY

echo "[v0.38 checkpoint 1] legacy schema migration smoke test"
python3 - <<'PY'
from pathlib import Path
import sqlite3
import tempfile
import deltaaegis

with tempfile.TemporaryDirectory() as tmp:
    db = Path(tmp) / "legacy-v0.37-schedules.db"

    raw = sqlite3.connect(db)
    raw.execute(
        "CREATE TABLE scan_schedules ("
        "schedule_id TEXT PRIMARY KEY,"
        "name TEXT NOT NULL,"
        "target TEXT NOT NULL,"
        "network_scope TEXT NOT NULL,"
        "scan_profile TEXT NOT NULL DEFAULT 'balanced',"
        "cadence_minutes INTEGER NOT NULL,"
        "enabled INTEGER NOT NULL DEFAULT 1,"
        "auto_ingest INTEGER NOT NULL DEFAULT 1,"
        "last_run_at TEXT,"
        "next_run_at TEXT,"
        "last_job_id TEXT,"
        "last_status TEXT,"
        "failure_count INTEGER NOT NULL DEFAULT 0,"
        "skip_count INTEGER NOT NULL DEFAULT 0,"
        "created_at TEXT NOT NULL,"
        "updated_at TEXT NOT NULL,"
        "message TEXT NOT NULL DEFAULT ''"
        ")"
    )
    raw.commit()
    raw.close()

    conn = deltaaegis.connect(db)

    columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(scan_schedules)").fetchall()
    }

    if "run_trueaegis_after_ingest" not in columns:
        raise SystemExit("legacy scan_schedules migration did not add run_trueaegis_after_ingest")

    schedule = deltaaegis.create_scan_schedule(
        conn,
        name="post migration default",
        target="192.168.43.0/24",
        cadence_minutes=120,
        auto_ingest=True,
        scan_profile="accurate",
        enabled=True,
    )

    if schedule["run_trueaegis_after_ingest"] is not False:
        raise SystemExit("post-migration default should be false")

    conn.close()

print("legacy migration smoke test passed")
PY

echo "[v0.38 checkpoint 1] PASS"
