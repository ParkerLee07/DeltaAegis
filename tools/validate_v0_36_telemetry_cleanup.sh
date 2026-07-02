#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py

python3 - <<'PY'
from pathlib import Path
import importlib.util
import sqlite3
import sys
import tempfile

module_path = Path("deltaaegis.py")
spec = importlib.util.spec_from_file_location("deltaaegis_under_test", module_path)
delta = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = delta
spec.loader.exec_module(delta)

text = module_path.read_text(encoding="utf-8")

required = [
    'TELEMETRY_CLEANUP_CONFIRMATION = "DELETE TELEMETRY"',
    "TELEMETRY_CLEANUP_PROTECTED_TABLES",
    "TELEMETRY_CLEANUP_TABLES",
    "def telemetry_cleanup_preview(",
    "def telemetry_cleanup_clear_all(",
    "telemetry cleanup requires confirmation phrase",
    "protected_tables_preserved",
]

for needle in required:
    if needle not in text:
        raise SystemExit(f"[FAIL] missing telemetry cleanup requirement: {needle}")

required_protected = [
    "access_users",
    "access_api_tokens",
    "access_sessions",
    "access_audit_log",
    "scan_schedules",
    "asset_annotations",
]

for protected in required_protected:
    if protected not in delta.TELEMETRY_CLEANUP_PROTECTED_TABLES:
        raise SystemExit(f"[FAIL] protected table missing from cleanup guardrail: {protected}")

for forbidden in delta.TELEMETRY_CLEANUP_PROTECTED_TABLES:
    if forbidden in delta.TELEMETRY_CLEANUP_TABLES:
        raise SystemExit(f"[FAIL] protected table appears in delete list: {forbidden}")

expected_delete_tables = [
    "snapshots",
    "asset_observations",
    "service_observations",
    "finding_observations",
    "delta_events",
    "alerts",
    "alert_notes",
    "asset_lifecycle",
    "scan_jobs",
    "trueaegis_jobs",
    "netsniper_intelligence_hosts",
    "netsniper_intelligence_summaries",
    "validation_runs",
    "validation_observations",
    "validation_correlations",
]

for table in expected_delete_tables:
    if table not in delta.TELEMETRY_CLEANUP_TABLES:
        raise SystemExit(f"[FAIL] expected telemetry table missing from delete list: {table}")


def table_exists(connection, table_name: str) -> bool:
    row = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    return row is not None


def table_columns(connection, table_name: str) -> list[sqlite3.Row]:
    return list(connection.execute(f"PRAGMA table_info({table_name})"))


def generated_value(table_name: str, column_name: str, column_type: str, now: str):
    col = column_name.lower()
    typ = (column_type or "").upper()

    text_values = {
        "scan_id": "scan-cleanup",
        "baseline_scan_id": None,
        "source_path": "/tmp/manifest.json",
        "source_filename": "validation.json",
        "source_format": "trueaegis-json",
        "manifest_path": "/tmp/manifest.json",
        "manifest_schema_version": "netsniper-run-v3",
        "network_scope": "192.168.56.0/24",
        "asset_key": "mac:aa:bb:cc:dd:ee:ff",
        "subject_key": "mac:aa:bb:cc:dd:ee:ff",
        "current_ip": "192.168.56.10",
        "ip_address": "192.168.56.10",
        "host": "192.168.56.10",
        "host_id": "host-cleanup",
        "mac_address": "aa:bb:cc:dd:ee:ff",
        "hostname": "cleanup-host",
        "protocol": "tcp",
        "service_protocol": "tcp",
        "service_name": "http",
        "service": "http",
        "state": "OBSERVED",
        "status": "COMPLETED",
        "quality_status": "ACCEPTED",
        "quality_reason": "validator",
        "bundle_status": "COMPLETE",
        "event_type": "MONITORED_SERVICE_OPENED",
        "severity": "LOW",
        "summary": "cleanup validator row",
        "dedup_key": "cleanup-alert",
        "finding_id": "finding-1",
        "name": "cleanup finding",
        "action": "ACK",
        "reason": "cleanup validator note",
        "validation_run_id": "validation-cleanup",
        "validation_status": "CONFIRMED",
        "validation_results_path": "/tmp/validation.json",
        "trueaegis_path": "/tmp/trueaegis.py",
        "netsniper_path": "/tmp/netsniper.sh",
        "runs_dir": "/tmp/runs",
        "logs_path": "/tmp/logs",
        "scan_profile": "balanced",
        "requested_profile": "balanced",
        "effective_profile": "balanced",
        "profile_fingerprint": "fingerprint",
        "profile_contract": "balanced",
        "device_type": "Workstation",
        "classification_type": "Workstation",
        "classification_primary_type": "Workstation",
        "classification_confidence_label": "high",
        "classification_decision": "classified",
        "classification_method": "validator",
        "classification_confidence_band": "high",
        "classification_calibrated_decision": "classified",
        "classification_siem_action": "none",
        "classification_calibration_reason": "validator",
        "classification_validation_state": "not_applicable",
        "primary_type": "Workstation",
        "decision": "classified",
        "confidence_band": "high",
        "siem_action": "none",
        "product": "test",
        "version": "1",
        "evidence": "validator evidence",
        "message": "cleanup validator message",
    }

    if col in text_values:
        return text_values[col]

    if col.endswith("_at") or col in {"created_at", "updated_at", "imported_at", "opened_at", "last_seen_at", "first_seen_at", "finished_at", "started_at"}:
        return now

    if col.endswith("_json") or col in {
        "previous_value",
        "current_value",
        "raw_json",
        "bundle_quality_json",
        "status_counts_json",
    }:
        if "counts" in col or "quality" in col:
            return "{}"
        return "[]"

    if col in {"port", "row_index", "score", "confidence", "hosts_up", "hosts_total", "host_count", "classified_count"}:
        return 1 if col != "port" else 80

    if (
        "count" in col
        or "total" in col
        or "exit_status" in col
        or "duration" in col
        or "budget" in col
        or "timeout" in col
        or "enabled" in col
        or "ingest" in col
        or "accepted" in col
        or "validated" in col
        or "coverage" in col
        or "is_" in col
    ):
        return 1

    if "INT" in typ:
        return 1

    if "REAL" in typ or "FLOAT" in typ or "DOUBLE" in typ:
        return 1.0

    return f"{table_name}-{column_name}-validator"


def insert_dynamic_row(connection, table_name: str, now: str) -> None:
    if not table_exists(connection, table_name):
        return False

    columns = table_columns(connection, table_name)
    pk_columns = [info for info in columns if int(info["pk"] or 0) > 0]
    single_integer_pk = (
        len(pk_columns) == 1
        and "INT" in (pk_columns[0]["type"] or "").upper()
    )

    insert_columns = []
    values = []

    for info in columns:
        name = info["name"]
        column_type = info["type"]
        is_pk = int(info["pk"] or 0) > 0

        # Let SQLite assign only a single-column integer primary key.
        # Composite primary-key columns such as service_observations.port are
        # still required and must be populated by the validator fixture.
        if single_integer_pk and is_pk:
            continue

        insert_columns.append(name)
        values.append(generated_value(table_name, name, column_type, now))

    placeholders = ", ".join("?" for _ in insert_columns)
    column_sql = ", ".join(insert_columns)
    connection.execute(
        f"INSERT OR REPLACE INTO {table_name} ({column_sql}) VALUES ({placeholders})",
        values,
    )
    return True


with tempfile.TemporaryDirectory() as tmp:
    db_path = Path(tmp) / "cleanup.sqlite3"
    connection = delta.connect(db_path)

    for ensure_name in [
        "ensure_netsniper_intelligence_schema",
        "ensure_netsniper_intelligence_host_schema",
        "ensure_validation_correlation_schema",
    ]:
        ensure = getattr(delta, ensure_name, None)
        if callable(ensure):
            ensure(connection)

    # The cleanup validator is about delete boundaries, not FK behavior.
    # Some older fixture schemas vary, so synthetic rows are inserted with FK checks off.
    connection.execute("PRAGMA foreign_keys = OFF")

    user = delta.create_access_user(
        connection,
        username="cleanup.admin",
        display_name="Cleanup Admin",
        role="ADMIN",
        password="temporary-password-123",
    )
    delta.create_access_api_token(
        connection,
        user_id=user["user_id"],
        token_name="cleanup-token",
        role="ADMIN",
    )
    delta.create_dashboard_session(
        connection,
        user,
        source_ip="127.0.0.1",
        user_agent="validator",
    )
    delta.create_scan_schedule(
        connection,
        name="cleanup schedule",
        target="192.168.56.0/24",
        cadence_minutes=60,
        enabled=True,
        auto_ingest=True,
        scan_profile="balanced",
    )

    now = delta.utc_now()

    # Dynamic protected operator context row; schema differs across older v0.x migrations.
    insert_dynamic_row(connection, "asset_annotations", now)

    # Dynamic telemetry rows; this avoids brittle assumptions such as source_path/created_at
    # existing in every migration-era schema.
    for table_name in reversed(delta.TELEMETRY_CLEANUP_TABLES):
        insert_dynamic_row(connection, table_name, now)

    connection.commit()

    preview = delta.telemetry_cleanup_preview(connection)
    if not preview["dry_run"] or preview["total_rows"] <= 0:
        raise SystemExit("[FAIL] dry-run preview did not detect telemetry rows")

    protected_before = delta.telemetry_cleanup_protected_counts(connection)
    telemetry_before = delta.telemetry_cleanup_counts(connection)

    try:
        delta.telemetry_cleanup_clear_all(connection, confirmation="WRONG", dry_run=False)
    except delta.DeltaAegisError:
        pass
    else:
        raise SystemExit("[FAIL] cleanup allowed deletion without confirmation phrase")

    if delta.telemetry_cleanup_counts(connection) != telemetry_before:
        raise SystemExit("[FAIL] failed confirmation mutated telemetry rows")

    dry_run = delta.telemetry_cleanup_clear_all(connection, confirmation="", dry_run=True)
    if not dry_run["dry_run"]:
        raise SystemExit("[FAIL] dry_run=True did not return dry-run payload")
    if delta.telemetry_cleanup_counts(connection) != telemetry_before:
        raise SystemExit("[FAIL] dry-run mutated telemetry rows")

    result = delta.telemetry_cleanup_clear_all(
        connection,
        confirmation=delta.TELEMETRY_CLEANUP_CONFIRMATION,
        dry_run=False,
    )
    connection.commit()

    if result["total_deleted_rows"] <= 0:
        raise SystemExit("[FAIL] cleanup did not delete telemetry rows")

    for table, count in delta.telemetry_cleanup_counts(connection).items():
        if count != 0:
            raise SystemExit(f"[FAIL] telemetry table still has rows after cleanup: {table}={count}")

    protected_after = delta.telemetry_cleanup_protected_counts(connection)
    if protected_before != protected_after:
        raise SystemExit(
            f"[FAIL] protected table counts changed: before={protected_before} after={protected_after}"
        )

    if not result["protected_tables_preserved"]:
        raise SystemExit("[FAIL] cleanup result did not report protected tables preserved")

    for table in [
        "access_users",
        "access_api_tokens",
        "access_sessions",
        "access_audit_log",
        "scan_schedules",
        "asset_annotations",
    ]:
        count = delta.telemetry_cleanup_table_count(connection, table)
        if count <= 0:
            raise SystemExit(f"[FAIL] protected table was emptied: {table}")

    connection.close()

delete_list_text = "\n".join(delta.TELEMETRY_CLEANUP_TABLES)
for forbidden in [
    "access_users",
    "access_api_tokens",
    "access_sessions",
    "access_audit_log",
    "scan_schedules",
    "asset_annotations",
]:
    if forbidden in delete_list_text:
        raise SystemExit(f"[FAIL] protected table appears in delete list text: {forbidden}")

cleanup_start = text.find("def telemetry_cleanup_clear_all(")
if cleanup_start < 0:
    raise SystemExit("[FAIL] could not locate telemetry_cleanup_clear_all for scoped delete check")

cleanup_end = text.find("\ndef ", cleanup_start + 1)
cleanup_block = text[cleanup_start:cleanup_end if cleanup_end > cleanup_start else len(text)]

for forbidden_sql in [
    "DELETE FROM access_users",
    "DELETE FROM access_sessions",
    "DELETE FROM access_api_tokens",
    "DELETE FROM scan_schedules",
    "DELETE FROM asset_annotations",
]:
    if forbidden_sql in cleanup_block:
        raise SystemExit(
            f"[FAIL] telemetry cleanup function directly deletes protected table: {forbidden_sql}"
        )

print("[PASS] v0.36 telemetry cleanup python checks passed")
PY

echo "[PASS] DeltaAegis v0.36 telemetry cleanup validation passed"
