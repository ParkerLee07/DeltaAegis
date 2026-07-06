#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "[v0.38 checkpoint 7] checkpoint 6 dependency"
tools/validate_v0_38_trueaegis_execution_modes.sh

echo "[v0.38 checkpoint 7] syntax check"
python3 -m py_compile deltaaegis.py

echo "[v0.38 checkpoint 7] static due-schedule query checks"
python3 - <<'PY'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")

start = text.find("def query_due_scan_schedules(")
end = text.find("\ndef mark_scan_schedule_skipped(", start)

if start < 0 or end < 0:
    raise SystemExit("could not isolate query_due_scan_schedules")

block = text[start:end]

if "run_trueaegis_after_ingest" not in block:
    raise SystemExit(
        "query_due_scan_schedules does not select run_trueaegis_after_ingest"
    )

if block.count("run_trueaegis_after_ingest") != 1:
    raise SystemExit(
        "query_due_scan_schedules should select "
        "run_trueaegis_after_ingest exactly once"
    )

print("static due-schedule query checks passed")
PY

echo "[v0.38 checkpoint 7] functional due-schedule intent smoke test"
python3 - <<'PY'
from pathlib import Path
import tempfile
import deltaaegis

with tempfile.TemporaryDirectory() as tmp:
    db = Path(tmp) / "due-intent.db"
    connection = deltaaegis.connect(db)

    enabled = deltaaegis.create_scan_schedule(
        connection,
        name="follow-up enabled",
        target="192.168.44.0/24",
        scan_profile="balanced",
        cadence_minutes=60,
        enabled=True,
        auto_ingest=True,
        run_trueaegis_after_ingest=True,
    )

    disabled = deltaaegis.create_scan_schedule(
        connection,
        name="follow-up disabled",
        target="192.168.45.0/24",
        scan_profile="balanced",
        cadence_minutes=60,
        enabled=True,
        auto_ingest=True,
        run_trueaegis_after_ingest=False,
    )

    connection.execute(
        """
        UPDATE scan_schedules
        SET next_run_at = '2000-01-01T00:00:00+00:00'
        WHERE schedule_id IN (?, ?)
        """,
        (enabled["schedule_id"], disabled["schedule_id"]),
    )
    connection.commit()

    rows = deltaaegis.query_due_scan_schedules(
        connection,
        limit=10,
        now_text="2030-01-01T00:00:00+00:00",
    )
    items = {
        item["schedule_id"]: item
        for item in map(deltaaegis.scan_schedule_to_dict, rows)
    }

    if items[enabled["schedule_id"]]["run_trueaegis_after_ingest"] is not True:
        raise SystemExit(
            f"enabled follow-up intent was lost: {items[enabled['schedule_id']]}"
        )

    if items[disabled["schedule_id"]]["run_trueaegis_after_ingest"] is not False:
        raise SystemExit(
            f"disabled follow-up intent changed: {items[disabled['schedule_id']]}"
        )

    connection.close()

print("functional due-schedule intent smoke test passed")
PY

echo "[v0.38 checkpoint 7] PASS"
