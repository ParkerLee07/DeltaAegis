#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "[v0.37 checkpoint 4] syntax check"
python3 -m py_compile deltaaegis.py

echo "[v0.37 checkpoint 4] static contract checks"
python3 - <<'PY'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")

required = {
    "permission route": '("GET", "/api/scan-freshness", "dashboard.read")',
    "fresh constant": "SCAN_FRESHNESS_FRESH_HOURS = 6",
    "stale constant": "SCAN_FRESHNESS_STALE_HOURS = 24",
    "payload helper": "def dashboard_scan_freshness_payload(",
    "state helper": "def scan_freshness_state_for_age(",
    "timestamp helper": "def scan_freshness_snapshot_timestamp(",
    "API dispatcher": 'elif route == "/api/scan-freshness":',
    "dashboard wrapper base": "_deltaaegis_dashboard_index_html_v037_scan_freshness_base",
    "dashboard heading": "Scan Freshness",
    "dashboard container": 'id="scan-freshness"',
    "dashboard status": 'id="scan-freshness-status"',
    "dashboard JS loader": "async function loadScanFreshness()",
    "dashboard JS route": "/api/scan-freshness",
    "fresh state": '"FRESH"',
    "aging state": '"AGING"',
    "stale state": '"STALE"',
    "no accepted state": '"NO_ACCEPTED_SCAN"',
}

missing = [name for name, needle in required.items() if needle not in text]
if missing:
    raise SystemExit("Missing scan-freshness markers: " + ", ".join(missing))

freshness_block = text[text.find("def dashboard_scan_freshness_payload("):text.find("def dashboard_latest_network_changes_payload(")]

for forbidden in (
    "UPDATE ",
    "INSERT ",
    "DELETE ",
    "DROP ",
):
    if forbidden in freshness_block:
        raise SystemExit(f"scan freshness payload must remain read-only; found {forbidden.strip()}")

print("static checks passed")
PY

echo "[v0.37 checkpoint 4] functional scan-freshness smoke test"
python3 - <<'PY'
import tempfile
from pathlib import Path
from datetime import datetime, timezone, timedelta

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
        if "__timestamp__" in overrides:
            return overrides["__timestamp__"]
        return deltaaegis.utc_now_text()

    if lower in {"quality_status"}:
        return "ACCEPTED"

    if lower in {"quality_reason"}:
        return "Synthetic accepted snapshot for scan-freshness validator."

    if lower in {"target", "network_scope"}:
        return "192.168.5.0/24"

    if lower in {"scan_id"}:
        return ""

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

    now = datetime(2026, 7, 2, 18, 0, 0, tzinfo=timezone.utc)

    cases = [
        ("scan-fresh", "fresh-scope", now - timedelta(hours=2), "FRESH"),
        ("scan-aging", "aging-scope", now - timedelta(hours=12), "AGING"),
        ("scan-stale", "stale-scope", now - timedelta(hours=30), "STALE"),
    ]

    for scan_id, scope, timestamp, expected_state in cases:
        insert_dynamic(
            conn,
            "snapshots",
            {
                "__timestamp__": timestamp.isoformat(),
                "scan_id": scan_id,
                "target": scope,
                "network_scope": scope,
                "quality_status": "ACCEPTED",
                "is_accepted_baseline": 1,
                "created_at": timestamp.isoformat(),
                "imported_at": timestamp.isoformat(),
                "hosts_up": 1,
                "identity_coverage": 1.0,
            },
        )

    # A rejected/latest-looking scan must not be treated as accepted freshness.
    insert_dynamic(
        conn,
        "snapshots",
        {
            "__timestamp__": now.isoformat(),
            "scan_id": "scan-rejected",
            "target": "rejected-scope",
            "network_scope": "rejected-scope",
            "quality_status": "SKIPPED",
            "is_accepted_baseline": 0,
            "created_at": now.isoformat(),
            "imported_at": now.isoformat(),
            "hosts_up": 1,
            "identity_coverage": 1.0,
        },
    )

    conn.commit()

    for scan_id, scope, timestamp, expected_state in cases:
        payload = deltaaegis.dashboard_scan_freshness_payload(
            conn,
            scope=scope,
            now=now,
        )

        if not payload.get("ok"):
            raise SystemExit(f"{scope}: scan freshness payload did not return ok=true")

        if payload.get("state") != expected_state:
            raise SystemExit(f"{scope}: expected {expected_state}, got {payload.get('state')}")

        if not payload.get("has_latest_accepted_scan"):
            raise SystemExit(f"{scope}: accepted scan was not detected")

        snapshot = payload.get("latest_snapshot") or {}
        if snapshot.get("scan_id") != scan_id:
            raise SystemExit(f"{scope}: expected latest scan {scan_id}, got {snapshot.get('scan_id')}")

        if payload.get("age_hours") is None:
            raise SystemExit(f"{scope}: age_hours was not calculated")

    no_scan_payload = deltaaegis.dashboard_scan_freshness_payload(
        conn,
        scope="missing-scope",
        now=now,
    )

    if no_scan_payload.get("state") != "NO_ACCEPTED_SCAN":
        raise SystemExit(f"missing scope expected NO_ACCEPTED_SCAN, got {no_scan_payload.get('state')}")

    if no_scan_payload.get("has_latest_accepted_scan"):
        raise SystemExit("missing scope incorrectly reported an accepted scan")

    rejected_payload = deltaaegis.dashboard_scan_freshness_payload(
        conn,
        scope="rejected-scope",
        now=now,
    )

    if rejected_payload.get("state") != "NO_ACCEPTED_SCAN":
        raise SystemExit("rejected scope incorrectly counted a skipped scan as accepted")

    html = deltaaegis.dashboard_index_html()

    for marker in (
        "Scan Freshness",
        "scan-freshness-status",
        "/api/scan-freshness",
        "loadScanFreshness",
        "FRESH",
        "AGING",
        "STALE",
        "NO_ACCEPTED_SCAN",
    ):
        if marker not in html:
            raise SystemExit(f"dashboard HTML missing marker: {marker}")

print("functional smoke test passed")
PY

echo "[v0.37 checkpoint 4] PASS"
