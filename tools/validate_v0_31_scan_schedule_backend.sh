#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

pass() {
    echo "[PASS] $1"
}

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

grep -Fq 'CREATE TABLE IF NOT EXISTS scan_schedules' deltaaegis.py \
    || fail "missing scan_schedules schema"

grep -Fq 'ALLOWED_SCAN_SCHEDULE_CADENCE_MINUTES = {60, 120, 360, 720, 1440}' deltaaegis.py \
    || fail "missing safe schedule cadence allowlist"

grep -Fq 'def create_scan_schedule(' deltaaegis.py \
    || fail "missing create_scan_schedule helper"

grep -Fq 'def query_scan_schedules(' deltaaegis.py \
    || fail "missing query_scan_schedules helper"

grep -Fq 'def set_scan_schedule_enabled(' deltaaegis.py \
    || fail "missing set_scan_schedule_enabled helper"

grep -Fq 'def delete_scan_schedule(' deltaaegis.py \
    || fail "missing delete_scan_schedule helper"

grep -Fq 'sub.add_parser("schedule-create"' deltaaegis.py \
    || fail "missing schedule-create CLI command"

grep -Fq 'sub.add_parser("schedule-list"' deltaaegis.py \
    || fail "missing schedule-list CLI command"

grep -Fq 'sub.add_parser("schedule-enable"' deltaaegis.py \
    || fail "missing schedule-enable CLI command"

grep -Fq 'sub.add_parser("schedule-disable"' deltaaegis.py \
    || fail "missing schedule-disable CLI command"

grep -Fq 'sub.add_parser("schedule-delete"' deltaaegis.py \
    || fail "missing schedule-delete CLI command"

python3 - <<'PY'
from pathlib import Path
import importlib.util
import sqlite3
import sys
import tempfile

spec = importlib.util.spec_from_file_location("deltaaegis", "deltaaegis.py")
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = module
spec.loader.exec_module(module)

with tempfile.TemporaryDirectory() as tmp:
    db_path = Path(tmp) / "deltaaegis.db"
    connection = module.connect(db_path)

    schedule = module.create_scan_schedule(
        connection,
        name="Hourly Balanced Monitoring",
        target="192.168.5.0/24",
        scan_profile="balanced",
        cadence_minutes=60,
        enabled=True,
        auto_ingest=True,
    )
    connection.commit()

    assert schedule["schedule_id"].startswith("sched-")
    assert schedule["name"] == "Hourly Balanced Monitoring"
    assert schedule["target"] == "192.168.5.0/24"
    assert schedule["network_scope"] == "192.168.5.0/24"
    assert schedule["scan_profile"] == "balanced"
    assert schedule["cadence_minutes"] == 60
    assert schedule["enabled"] is True
    assert schedule["auto_ingest"] is True
    assert schedule["next_run_at"]

    rows = module.query_scan_schedules(connection, limit=10)
    assert len(rows) == 1

    disabled = module.set_scan_schedule_enabled(connection, schedule["schedule_id"], False)
    connection.commit()
    assert disabled["enabled"] is False
    assert disabled["next_run_at"] is None

    enabled = module.set_scan_schedule_enabled(connection, schedule["schedule_id"], True)
    connection.commit()
    assert enabled["enabled"] is True
    assert enabled["next_run_at"]

    try:
        module.create_scan_schedule(
            connection,
            name="Public Bad",
            target="8.8.8.0/24",
            scan_profile="balanced",
            cadence_minutes=60,
        )
    except module.DeltaAegisError:
        pass
    else:
        raise AssertionError("public CIDR schedule was accepted")

    try:
        module.create_scan_schedule(
            connection,
            name="Deep Bad",
            target="192.168.5.0/24",
            scan_profile="deep",
            cadence_minutes=60,
        )
    except module.DeltaAegisError:
        pass
    else:
        raise AssertionError("deep schedule profile was accepted")

    try:
        module.create_scan_schedule(
            connection,
            name="Too Frequent",
            target="192.168.5.0/24",
            scan_profile="quick",
            cadence_minutes=30,
        )
    except module.DeltaAegisError:
        pass
    else:
        raise AssertionError("unsafe cadence was accepted")

    module.delete_scan_schedule(connection, schedule["schedule_id"])
    connection.commit()

    rows = module.query_scan_schedules(connection, limit=10)
    assert len(rows) == 0

print("[PASS] v0.31 scan schedule backend python checks passed")
PY

python3 - <<'PY'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")
start = text.find("def command_scan_start(args: argparse.Namespace) -> int:")
end = text.find("\ndef decode_json_field", start)

if start == -1 or end == -1:
    raise SystemExit("[FAIL] could not locate command_scan_start for profile handoff check")

section = text[start:end]

if section.count("scan_profile=safe_profile") < 2:
    raise SystemExit("[FAIL] CLI scan-start does not pass safe_profile into both create_scan_job and execute_scan_job")

print("[PASS] CLI scan-start profile handoff check passed")
PY

pass "DeltaAegis v0.31 scan schedule backend validation passed"
