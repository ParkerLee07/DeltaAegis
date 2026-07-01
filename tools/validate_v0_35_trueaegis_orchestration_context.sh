#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py

grep -Fq 'DEFAULT_TRUEAEGIS = Path.home() / "TrueAegis" / "trueaegis.py"' deltaaegis.py
grep -Fq 'DEFAULT_TRUEAEGIS_LOGS = Path.home() / "DeltaAegis" / "trueaegis-logs"' deltaaegis.py
grep -Fq '("GET", "/api/trueaegis/context", "dashboard.read")' deltaaegis.py
grep -Fq 'def latest_trueaegis_candidate_scan(' deltaaegis.py
grep -Fq 'def resolve_trueaegis_executable(' deltaaegis.py
grep -Fq 'def build_trueaegis_validation_command(' deltaaegis.py
grep -Fq 'def dashboard_trueaegis_orchestration_context_payload(' deltaaegis.py
grep -Fq 'elif route == "/api/trueaegis/context":' deltaaegis.py
grep -Fq 'command_preview' deltaaegis.py
grep -Fq 'ready_to_start' deltaaegis.py

python3 - <<'PY'
from pathlib import Path
import importlib.util
import json
import sys
import tempfile

module_path = Path("deltaaegis.py")
spec = importlib.util.spec_from_file_location("deltaaegis_v035_context", module_path)
delta = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = delta
spec.loader.exec_module(delta)

with tempfile.TemporaryDirectory() as tmp:
    tmp_path = Path(tmp)
    db_path = tmp_path / "deltaaegis.db"
    manifest_path = tmp_path / "run-001" / "manifest.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(
        json.dumps({
            "schema_version": "netsniper-run-v3",
            "status": "COMPLETE",
            "scan_id": "scan-001",
            "target": "192.168.1.0/24"
        }),
        encoding="utf-8",
    )
    trueaegis_path = tmp_path / "TrueAegis" / "trueaegis.py"
    trueaegis_path.parent.mkdir(parents=True)
    trueaegis_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

    connection = delta.connect(db_path)
    try:
        snapshot_values = {
            "scan_id": "scan-001",
            "manifest_path": str(manifest_path),
            "target": "192.168.1.0/24",
            "network_scope": "192.168.1.0/24",
            "scanner_version": "netsniper-test",
            "telemetry_contract": "netsniper-run-v3",
            "schema_version": "netsniper-run-v3",
            "manifest_schema_version": "netsniper-run-v3",
            "scan_profile": "balanced",
            "created_at": "2026-07-01T00:00:00Z",
            "imported_at": "2026-07-01T00:00:01Z",
            "quality_status": "ACCEPTED",
            "quality_reason": "fixture",
            "xml_exit_status": "ok",
            "hosts_up": 1,
            "hosts_total": 1,
            "identity_coverage": 1.0,
            "is_accepted_baseline": 1,
        }

        snapshot_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(snapshots)").fetchall()
        }
        insert_values = {
            key: value
            for key, value in snapshot_values.items()
            if key in snapshot_columns
        }

        def snapshot_fixture_default(column_name: str, column_type: str) -> object:
            lower_name = str(column_name or "").lower()
            lower_type = str(column_type or "").lower()

            if lower_name == "bundle_status":
                return "COMPLETE"
            if lower_name == "quality_status":
                return "ACCEPTED"
            if lower_name == "quality_reason":
                return "fixture"
            if lower_name == "xml_exit_status":
                return "ok"
            if lower_name == "identity_coverage":
                return 1.0
            if lower_name.endswith("_json"):
                return "{}"
            if lower_name.endswith("_at"):
                return "2026-07-01T00:00:00Z"
            if lower_name.startswith("is_"):
                return 1
            if "count" in lower_name or lower_name.startswith("hosts_"):
                return 0
            if "int" in lower_type:
                return 0
            if "real" in lower_type or "float" in lower_type or "double" in lower_type:
                return 0.0
            return ""

        table_info = connection.execute("PRAGMA table_info(snapshots)").fetchall()
        for row in table_info:
            name = row["name"]
            if name in insert_values:
                continue
            if row["pk"]:
                continue
            if row["notnull"] and row["dflt_value"] is None:
                insert_values[name] = snapshot_fixture_default(name, row["type"])

        required = {"scan_id", "manifest_path"}
        missing = required - set(insert_values)
        assert not missing, f"snapshots table missing required fixture columns: {sorted(missing)}"

        columns_sql = ", ".join(insert_values)
        placeholders = ", ".join("?" for _ in insert_values)

        connection.execute(
            f"INSERT INTO snapshots ({columns_sql}) VALUES ({placeholders})",
            tuple(insert_values.values()),
        )
        connection.commit()

        latest = delta.latest_trueaegis_candidate_scan(connection)
        assert latest is not None, "latest accepted scan was not found"
        assert latest["scan_id"] == "scan-001"
        assert latest["manifest_path"] == str(manifest_path)

        command = delta.build_trueaegis_validation_command(
            trueaegis_path=trueaegis_path,
            manifest_path=manifest_path,
        )
        assert isinstance(command, list), "TrueAegis command must be argv list"
        assert "--validate" in command
        assert "--quiet" in command
        assert str(trueaegis_path) in command
        assert str(manifest_path) in command
        assert all(";" not in part for part in command), "command preview should not be shell text"

        context = delta.dashboard_trueaegis_orchestration_context_payload(
            connection,
            scope="192.168.1.0/24",
            trueaegis_path=trueaegis_path,
        )
        assert context["ready_to_start"] is True, context
        assert context["latest_scan"]["scan_id"] == "scan-001"
        assert context["manifest_exists"] is True
        assert context["trueaegis_exists"] is True
        assert context["command_preview"] == command
        assert context["validation_results_dir"].endswith("validation_results")
    finally:
        connection.close()

print("[PASS] v0.35 TrueAegis orchestration context python checks passed")
PY

echo "[PASS] DeltaAegis v0.35 TrueAegis orchestration context validation passed"
