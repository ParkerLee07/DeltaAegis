#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "[v0.37 checkpoint 2] syntax check"
python3 -m py_compile deltaaegis.py

echo "[v0.37 checkpoint 2] static contract checks"
python3 - <<'PY'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")

required = {
    "route permission": '("GET", "/api/telemetry-cleanup/audit-events", "admin.telemetry.cleanup")',
    "audit action constant": 'TELEMETRY_CLEANUP_AUDIT_ACTION = "TELEMETRY_CLEANUP_CLEAR_ALL"',
    "query audit events": "def query_telemetry_cleanup_audit_events(",
    "dashboard audit payload": "def dashboard_telemetry_cleanup_audit_events_payload(",
    "GET audit route": 'if route == "/api/telemetry-cleanup/audit-events":',
    "reset page heading": "Recent Telemetry Reset Audit Events",
    "reset page body id": 'id="telemetry-cleanup-audit-body"',
    "reset page refresh id": 'id="telemetry-cleanup-audit-refresh"',
    "audit JS loader": "async function loadTelemetryResetAuditEvents()",
    "audit JS renderer": "function renderTelemetryResetAuditEvents(payload)",
    "filtered audit action": 'String(event.action || "") === "TELEMETRY_CLEANUP_CLEAR_ALL"',
}

missing = [name for name, needle in required.items() if needle not in text]
if missing:
    raise SystemExit("Missing reset-audit visibility markers: " + ", ".join(missing))

if text.count("/api/telemetry-cleanup/audit-events") < 3:
    raise SystemExit("reset audit API is not represented in route, link, and fetch path")

print("static checks passed")
PY

echo "[v0.37 checkpoint 2] functional reset-audit smoke test"
python3 - <<'PY'
import json
import tempfile
from pathlib import Path

import deltaaegis

with tempfile.TemporaryDirectory() as tmp:
    db_path = Path(tmp) / "deltaaegis.db"
    conn = deltaaegis.connect(db_path)

    columns_info = conn.execute("PRAGMA table_info(access_audit_log)").fetchall()
    insert_columns = []
    insert_values = []

    def value_for_column(name, col_type):
        lower = name.lower()
        type_text = str(col_type or "").upper()

        if name == "audit_id":
            raise AssertionError("audit_id should not be inserted explicitly")
        if "created" in lower or "timestamp" in lower or "time" in lower:
            return deltaaegis.utc_now_text()
        if lower == "action":
            return "TELEMETRY_CLEANUP_CLEAR_ALL"
        if lower in {"actor_user_id", "user_id"} or (lower.endswith("_id") and "actor" in lower):
            # access_audit_log.actor_user_id is foreign-keyed to access_users.
            # Use NULL for the synthetic smoke-test row so the test validates
            # audit filtering/redaction without needing to create a dashboard user.
            return None
        if "actor" in lower and "role" in lower:
            return "ADMIN"
        if "actor" in lower and ("username" in lower or "name" in lower):
            return "admin"
        if lower == "username":
            return "admin"
        if "auth" in lower:
            return "dashboard_session"
        if "target" in lower or "resource" in lower:
            return "telemetry_cleanup"
        if "result" in lower or "status" in lower:
            return "SUCCESS"
        if "details" in lower or "metadata" in lower:
            return json.dumps(
                {
                    "actor": {
                        "username": "admin",
                        "role": "ADMIN",
                        "auth_type": "dashboard_session",
                    },
                    "deleted_rows": {"snapshots": 2},
                    "password_hash": "should-not-leak",
                    "api_token": "should-not-leak",
                    "secret_value": "should-not-leak",
                },
                sort_keys=True,
            )
        if "INTEGER" in type_text:
            return 0
        return ""

    for _, name, col_type, notnull, default, pk in columns_info:
        if name == "audit_id":
            continue
        insert_columns.append(name)
        insert_values.append(value_for_column(name, col_type))

    placeholders = ", ".join("?" for _ in insert_columns)
    sql = f"INSERT INTO access_audit_log ({', '.join(insert_columns)}) VALUES ({placeholders})"
    conn.execute(sql, insert_values)

    non_reset_values = list(insert_values)
    if "action" in insert_columns:
        non_reset_values[insert_columns.index("action")] = "ACCESS_USER_DASHBOARD_LOGIN"
    conn.execute(sql, non_reset_values)
    conn.commit()

    payload = deltaaegis.dashboard_telemetry_cleanup_audit_events_payload(conn, limit=20)

    if not payload.get("ok"):
        raise SystemExit("reset audit payload did not return ok=true")

    if payload.get("audit_action") != "TELEMETRY_CLEANUP_CLEAR_ALL":
        raise SystemExit("reset audit payload action filter is wrong")

    events = payload.get("events") or []
    if len(events) != 1:
        raise SystemExit(f"expected exactly one reset audit event, found {len(events)}")

    event = events[0]
    if event.get("action") != "TELEMETRY_CLEANUP_CLEAR_ALL":
        raise SystemExit("payload returned a non-reset audit event")

    serialized = json.dumps(event, sort_keys=True)
    if "should-not-leak" in serialized:
        raise SystemExit("sensitive audit detail value leaked through reset audit payload")

    synthetic_event = deltaaegis.telemetry_cleanup_audit_event_to_dict(
        {
            "audit_id": 999,
            "action": "TELEMETRY_CLEANUP_CLEAR_ALL",
            "created_at": deltaaegis.utc_now_text(),
            "details": {
                "safe_value": "visible",
                "password_hash": "should-not-leak",
                "api_token": "should-not-leak",
                "nested": {
                    "secret_value": "should-not-leak",
                },
            },
        }
    )

    synthetic_serialized = json.dumps(synthetic_event, sort_keys=True)

    if "should-not-leak" in synthetic_serialized:
        raise SystemExit("synthetic sensitive audit detail value leaked through reset audit serializer")

    if synthetic_serialized.count("[redacted]") < 3:
        raise SystemExit("reset audit serializer did not redact nested sensitive fields")

    if "visible" not in synthetic_serialized:
        raise SystemExit("reset audit serializer removed safe audit detail fields")

    html = deltaaegis.dashboard_operator_reset_shell_html()
    for marker in (
        "Recent Telemetry Reset Audit Events",
        "telemetry-cleanup-audit-body",
        "/api/telemetry-cleanup/audit-events?limit=20",
        "loadTelemetryResetAuditEvents",
        "TELEMETRY_CLEANUP_CLEAR_ALL",
    ):
        if marker not in html:
            raise SystemExit(f"reset page missing marker: {marker}")

print("functional smoke test passed")
PY

echo "[v0.37 checkpoint 2] PASS"
