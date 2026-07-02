#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "[v0.37 checkpoint 3] syntax check"
python3 -m py_compile deltaaegis.py

echo "[v0.37 checkpoint 3] static contract checks"
python3 - <<'PY'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")

required = {
    "permission route": '("GET", "/api/latest-network-changes", "dashboard.read")',
    "payload helper": "def dashboard_latest_network_changes_payload(",
    "event query helper": "def query_latest_network_change_events(",
    "count helper": "def latest_network_change_count_rows(",
    "API dispatcher": 'elif route == "/api/latest-network-changes":',
    "dashboard wrapper base": "_deltaaegis_dashboard_index_html_v037_latest_changes_base",
    "dashboard heading": "Latest Network Changes",
    "dashboard container": 'id="latest-network-changes"',
    "dashboard body": 'id="latest-network-changes-body"',
    "dashboard JS loader": "async function loadLatestNetworkChanges()",
    "dashboard JS route": "/api/latest-network-changes",
    "no risk scoring mutation wording": "This does not change event generation, alert state, or risk scoring.",
}

missing = [name for name, needle in required.items() if needle not in text]
if missing:
    raise SystemExit("Missing latest-change summary markers: " + ", ".join(missing))

latest_block = text[text.find("def dashboard_latest_network_changes_payload("):text.find("def dashboard_events_payload(")]
for forbidden in (
    "UPDATE alerts SET",
    "UPDATE delta_events SET",
    "INSERT INTO alerts",
    "INSERT INTO delta_events",
    "DELETE FROM alerts",
    "DELETE FROM delta_events",
):
    if forbidden in latest_block:
        raise SystemExit(f"latest-change payload must remain read-only; found {forbidden}")

print("static checks passed")
PY

echo "[v0.37 checkpoint 3] functional latest-change summary smoke test"
python3 - <<'PY'
import json
import tempfile
from pathlib import Path

import deltaaegis


def table_columns(conn, table):
    return conn.execute(f"PRAGMA table_info({table})").fetchall()


def default_value_for_column(name, col_type, overrides):
    if name in overrides:
        return overrides[name]

    lower = name.lower()
    type_text = str(col_type or "").upper()

    if lower.endswith("_json"):
        return "{}"

    if "created" in lower or "updated" in lower or "imported" in lower or "timestamp" in lower or lower.endswith("_at"):
        return deltaaegis.utc_now_text()

    if lower in {"quality_status"}:
        return "ACCEPTED"

    if lower in {"quality_reason"}:
        return "Synthetic accepted snapshot for latest-change validator."

    if lower in {"target", "network_scope"}:
        return "192.168.5.0/24"

    if lower in {"scan_id", "baseline_scan_id"}:
        return ""

    if lower in {"event_type"}:
        return "MONITORED_SERVICE_OPENED"

    if lower in {"severity"}:
        return "MEDIUM"

    if lower in {"subject_key"}:
        return "asset:synthetic"

    if lower in {"summary", "message", "description"}:
        return "Synthetic latest network change."

    if lower in {"previous_value", "current_value"}:
        return json.dumps({})

    if "coverage" in lower:
        return 1.0

    if "count" in lower or lower.startswith("is_") or "enabled" in lower or "hosts" in lower or "ready" in lower:
        return 1

    if "INTEGER" in type_text:
        return 0

    if "REAL" in type_text or "FLOAT" in type_text or "DOUBLE" in type_text:
        return 0.0

    return ""


def insert_dynamic(conn, table, overrides):
    columns = table_columns(conn, table)
    names = []
    values = []

    for _, name, col_type, notnull, default, pk in columns:
        if pk and name not in overrides:
            continue

        names.append(name)
        values.append(default_value_for_column(name, col_type, overrides))

    placeholders = ", ".join("?" for _ in names)
    conn.execute(
        f"INSERT INTO {table} ({', '.join(names)}) VALUES ({placeholders})",
        values,
    )


with tempfile.TemporaryDirectory() as tmp:
    db_path = Path(tmp) / "deltaaegis.db"
    conn = deltaaegis.connect(db_path)

    older_time = "2026-07-02T00:00:00Z"
    latest_time = "2026-07-02T01:00:00Z"

    insert_dynamic(
        conn,
        "snapshots",
        {
            "scan_id": "scan-old",
            "target": "192.168.5.0/24",
            "network_scope": "192.168.5.0/24",
            "quality_status": "ACCEPTED",
            "is_accepted_baseline": 1,
            "created_at": older_time,
            "imported_at": older_time,
            "hosts_up": 1,
            "identity_coverage": 1.0,
        },
    )

    insert_dynamic(
        conn,
        "snapshots",
        {
            "scan_id": "scan-latest",
            "target": "192.168.5.0/24",
            "network_scope": "192.168.5.0/24",
            "quality_status": "ACCEPTED",
            "is_accepted_baseline": 1,
            "created_at": latest_time,
            "imported_at": latest_time,
            "hosts_up": 2,
            "identity_coverage": 1.0,
        },
    )

    insert_dynamic(
        conn,
        "delta_events",
        {
            "scan_id": "scan-old",
            "baseline_scan_id": "",
            "event_type": "ASSET_FIRST_OBSERVED",
            "severity": "LOW",
            "subject_key": "asset:old",
            "previous_value": json.dumps(None),
            "current_value": json.dumps({"ip": "192.168.5.10"}),
            "summary": "Old scan event that must not appear.",
            "created_at": older_time,
        },
    )

    for event_type, severity, subject, summary in (
        ("MONITORED_SERVICE_OPENED", "HIGH", "asset:latest:22", "SSH opened on latest accepted scan."),
        ("MONITORED_SERVICE_OPENED", "MEDIUM", "asset:latest:80", "HTTP opened on latest accepted scan."),
        ("ASSET_NOT_OBSERVED", "LOW", "asset:missing", "Asset missing from latest accepted scan."),
    ):
        insert_dynamic(
            conn,
            "delta_events",
            {
                "scan_id": "scan-latest",
                "baseline_scan_id": "scan-old",
                "event_type": event_type,
                "severity": severity,
                "subject_key": subject,
                "previous_value": json.dumps({"state": "before"}),
                "current_value": json.dumps({"state": "after"}),
                "summary": summary,
                "created_at": latest_time,
            },
        )

    conn.commit()

    payload = deltaaegis.dashboard_latest_network_changes_payload(
        conn,
        limit=10,
        scope="192.168.5.0/24",
    )

    if not payload.get("ok"):
        raise SystemExit("latest network changes payload did not return ok=true")

    if not payload.get("has_latest_accepted_scan"):
        raise SystemExit("latest network changes payload did not detect accepted scan")

    snapshot = payload.get("latest_snapshot") or {}
    if snapshot.get("scan_id") != "scan-latest":
        raise SystemExit(f"expected scan-latest, got {snapshot.get('scan_id')}")

    summary = payload.get("summary") or {}
    if summary.get("total_changes") != 3:
        raise SystemExit(f"expected 3 latest changes, got {summary.get('total_changes')}")

    event_types = {row["key"]: row["count"] for row in summary.get("event_type_counts") or []}
    severities = {row["key"]: row["count"] for row in summary.get("severity_counts") or []}

    if event_types.get("MONITORED_SERVICE_OPENED") != 2:
        raise SystemExit("event type counts did not include two MONITORED_SERVICE_OPENED events")

    if severities.get("HIGH") != 1 or severities.get("MEDIUM") != 1 or severities.get("LOW") != 1:
        raise SystemExit(f"unexpected severity counts: {severities}")

    events = payload.get("events") or []
    if len(events) != 3:
        raise SystemExit(f"expected 3 event rows, got {len(events)}")

    serialized = json.dumps(payload, sort_keys=True)
    if "Old scan event that must not appear" in serialized:
        raise SystemExit("latest change payload leaked non-latest scan event")

    if "SSH opened on latest accepted scan." not in serialized:
        raise SystemExit("latest accepted scan event was missing")

    empty_payload = deltaaegis.dashboard_latest_network_changes_payload(
        conn,
        limit=10,
        scope="10.99.0.0/24",
    )

    if empty_payload.get("has_latest_accepted_scan"):
        raise SystemExit("empty-scope payload incorrectly reported an accepted scan")

    html = deltaaegis.dashboard_index_html()
    for marker in (
        "Latest Network Changes",
        "latest-network-changes-body",
        "/api/latest-network-changes",
        "loadLatestNetworkChanges",
        "This does not change event generation, alert state, or risk scoring.",
    ):
        if marker not in html:
            raise SystemExit(f"dashboard HTML missing marker: {marker}")

print("functional smoke test passed")
PY

echo "[v0.37 checkpoint 3] PASS"
