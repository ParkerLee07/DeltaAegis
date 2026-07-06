#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "[v0.38 checkpoint 5] checkpoint 4 dependency"
tools/validate_v0_38_trueaegis_followup_execution.sh

echo "[v0.38 checkpoint 5] syntax check"
python3 -m py_compile deltaaegis.py

echo "[v0.38 checkpoint 5] static contract checks"
python3 - <<'PY'
from pathlib import Path
text = Path("deltaaegis.py").read_text(encoding="utf-8")
required = [
    "scan_job_id TEXT NOT NULL DEFAULT ''",
    "schedule_id TEXT NOT NULL DEFAULT ''",
    "trigger_source TEXT NOT NULL DEFAULT 'manual_dashboard'",
    'ensure_column(connection, "trueaegis_jobs", "scan_job_id"',
    'ensure_column(connection, "trueaegis_jobs", "schedule_id"',
    'ensure_column(connection, "trueaegis_jobs", "trigger_source"',
    "def scan_job_auto_ingest_evidence(",
    "deltaaegis-scan-auto-ingest-evidence-v1",
    'status_json["auto_ingest"] = auto_ingest_evidence',
    '"ingest_not_recorded"',
    '"ingest_manifest_mismatch"',
    'trigger_source="scheduled_followup"',
]
for needle in required:
    if needle not in text:
        raise SystemExit(f"missing checkpoint 5 marker: {needle}")
print("static contract checks passed")
PY

echo "[v0.38 checkpoint 5] legacy provenance migration smoke test"
python3 - <<'PY'
from pathlib import Path
import sqlite3
import tempfile
import deltaaegis

with tempfile.TemporaryDirectory() as tmp:
    db = Path(tmp) / "legacy.db"
    raw = sqlite3.connect(db)
    raw.execute(
        """
        CREATE TABLE trueaegis_jobs (
            job_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            scan_id TEXT,
            network_scope TEXT NOT NULL DEFAULT '',
            manifest_path TEXT NOT NULL,
            trueaegis_path TEXT NOT NULL DEFAULT '',
            validation_results_path TEXT,
            validation_run_id TEXT,
            imported_observations INTEGER NOT NULL DEFAULT 0,
            correlation_count INTEGER NOT NULL DEFAULT 0,
            stdout_log_path TEXT,
            stderr_log_path TEXT,
            exit_code INTEGER,
            message TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT
        )
        """
    )
    raw.commit()
    raw.close()

    conn = deltaaegis.connect(db)
    columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(trueaegis_jobs)").fetchall()
    }
    for expected in {"scan_job_id", "schedule_id", "trigger_source"}:
        if expected not in columns:
            raise SystemExit(f"legacy migration missing {expected}")
    conn.close()
print("legacy provenance migration smoke test passed")
PY

echo "[v0.38 checkpoint 5] provenance persistence smoke test"
python3 - <<'PY'
from pathlib import Path
import tempfile
import deltaaegis

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    conn = deltaaegis.connect(root / "provenance.db")
    manifest = root / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    trueaegis_path = root / "trueaegis.py"
    trueaegis_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

    scheduled = deltaaegis.create_trueaegis_job(
        conn,
        scan_id="scan-telemetry",
        network_scope="192.168.44.0/24",
        manifest_path=manifest,
        trueaegis_path=trueaegis_path,
        scan_job_id="scan-job-123",
        schedule_id="schedule-456",
        trigger_source="scheduled_followup",
    )
    conn.commit()

    assert scheduled["scan_job_id"] == "scan-job-123", scheduled
    assert scheduled["schedule_id"] == "schedule-456", scheduled
    assert scheduled["trigger_source"] == "scheduled_followup", scheduled

    try:
        deltaaegis.create_trueaegis_job(
            conn,
            scan_id="bad",
            network_scope="scope",
            manifest_path=manifest,
            trueaegis_path=trueaegis_path,
            trigger_source="untrusted_source",
        )
    except deltaaegis.DeltaAegisError:
        pass
    else:
        raise SystemExit("invalid trigger source was accepted")
    conn.close()
print("provenance persistence smoke test passed")
PY

echo "[v0.38 checkpoint 5] strict planner gate smoke test"
python3 - <<'PY'
from pathlib import Path
import tempfile
import deltaaegis

original_active = deltaaegis.active_trueaegis_job_exists
try:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        manifest = root / "manifest.json"
        manifest.write_text('{"scan_id":"scan-strict"}', encoding="utf-8")
        trueaegis_path = root / "trueaegis.py"
        trueaegis_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

        class FakeCursor:
            def __init__(self, row): self.row = row
            def fetchone(self): return self.row

        class FakeConnection:
            def __init__(self, row): self.row = row
            def execute(self, sql, params=()):
                if "FROM snapshots" in sql:
                    return FakeCursor(self.row)
                raise RuntimeError(f"unexpected SQL: {sql}")

        schedule = {
            "schedule_id": "schedule-strict",
            "target": "192.168.44.0/24",
            "network_scope": "192.168.44.0/24",
            "auto_ingest": True,
            "run_trueaegis_after_ingest": True,
        }
        base_job = {
            "job_id": "scan-job-strict",
            "status": "COMPLETED",
            "network_scope": "192.168.44.0/24",
            "auto_ingest": True,
            "bundle_path": str(root),
        }
        deltaaegis.active_trueaegis_job_exists = lambda connection: False

        missing = dict(base_job)
        missing["status_json"] = {}
        plan = deltaaegis.trueaegis_followup_plan_for_schedule(
            FakeConnection(None), schedule, missing, trueaegis_path=trueaegis_path
        )
        assert plan["outcome"] == "ingest_not_recorded", plan

        rejected = dict(base_job)
        rejected["status_json"] = {
            "auto_ingest": {
                "performed": True,
                "accepted": False,
                "quality_status": "SKIPPED",
                "scan_id": "scan-strict",
            }
        }
        plan = deltaaegis.trueaegis_followup_plan_for_schedule(
            FakeConnection(None), schedule, rejected, trueaegis_path=trueaegis_path
        )
        assert plan["outcome"] == "ingest_not_accepted", plan

        accepted = dict(base_job)
        accepted["status_json"] = {
            "auto_ingest": {
                "performed": True,
                "accepted": True,
                "quality_status": "ACCEPTED",
                "scan_id": "scan-strict",
            }
        }
        snapshot_row = {
            "scan_id": "scan-strict",
            "quality_status": "ACCEPTED",
            "manifest_path": str(manifest),
        }
        plan = deltaaegis.trueaegis_followup_plan_for_schedule(
            FakeConnection(snapshot_row), schedule, accepted, trueaegis_path=trueaegis_path
        )
        assert plan["outcome"] == "eligible", plan
finally:
    deltaaegis.active_trueaegis_job_exists = original_active
print("strict planner gate smoke test passed")
PY

echo "[v0.38 checkpoint 5] auto-ingest evidence helper smoke test"
python3 - <<'PY'
from pathlib import Path
import tempfile
import deltaaegis

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    manifest = root / "manifest.json"
    manifest.write_text('{"scan_id":"scan-evidence"}', encoding="utf-8")

    class FakeCursor:
        def fetchone(self):
            return {
                "scan_id": "scan-evidence",
                "quality_status": "ACCEPTED",
                "manifest_path": str(manifest),
                "network_scope": "192.168.44.0/24",
            }

    class FakeConnection:
        def execute(self, sql, params=()):
            return FakeCursor()

    evidence = deltaaegis.scan_job_auto_ingest_evidence(
        FakeConnection(), manifest, "IMPORTED", status_json={}
    )
    assert evidence["performed"] is True, evidence
    assert evidence["accepted"] is True, evidence
    assert evidence["quality_status"] == "ACCEPTED", evidence
    assert evidence["scan_id"] == "scan-evidence", evidence
print("auto-ingest evidence helper smoke test passed")
PY

echo "[v0.38 checkpoint 5] PASS"
