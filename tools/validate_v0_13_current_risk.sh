#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BUNDLE_DIR="${1:-/home/parker/NetSniper/runs/20260623-123007}"

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

pass() {
    echo "[PASS] $*"
}

[ -d "$BUNDLE_DIR" ] || fail "Bundle directory not found: $BUNDLE_DIR"

grep -q 'def dashboard_current_risk_payload' deltaaegis.py \
    || fail "dashboard_current_risk_payload is missing"

grep -q '"/api/current-risk"' deltaaegis.py \
    || fail "/api/current-risk route is missing"

grep -q 'Historical Risk Context' deltaaegis.py \
    || fail "Historical Risk Context section is missing"

grep -q 'api(scopedPath("/api/current-risk?limit=10"))' deltaaegis.py \
    || fail "Dashboard does not fetch /api/current-risk"

grep -q 'renderHistoricalRisk(historicalRisk)' deltaaegis.py \
    || fail "Dashboard does not render historical risk separately"

scan_id="$(jq -r '.scan_id' "$BUNDLE_DIR/manifest.json")"
target="$(jq -r '.target' "$BUNDLE_DIR/manifest.json")"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

mkdir -p "$tmpdir/runs"
ln -s "$BUNDLE_DIR" "$tmpdir/runs/$scan_id"

tmpdb="$tmpdir/deltaaegis.db"
tmpevents="$tmpdir/events.jsonl"

python3 deltaaegis.py \
    --db "$tmpdb" \
    --runs-dir "$tmpdir/runs" \
    --events "$tmpevents" \
    ingest >/tmp/deltaaegis_v0_13_current_risk_ingest.out

python3 - "$tmpdb" "$scan_id" "$target" <<'PY'
import sqlite3
import sys

import deltaaegis

db_path, scan_id, target = sys.argv[1:4]

con = sqlite3.connect(db_path)
con.row_factory = sqlite3.Row

current_assets = {
    row["asset_key"]
    for row in con.execute(
        "SELECT asset_key FROM asset_observations WHERE scan_id = ?",
        (scan_id,),
    ).fetchall()
}

rows = deltaaegis.dashboard_current_risk_payload(con, 200, scope=target)

if not isinstance(rows, list):
    raise SystemExit("current risk payload did not return a list")

for row in rows:
    subject = row.get("subject_key")
    if subject not in current_assets:
        raise SystemExit(
            f"current risk subject {subject!r} is not in latest asset_observations"
        )

    if row.get("risk_scope") != "current":
        raise SystemExit(f"current risk row {subject!r} missing risk_scope=current")

    if int(row.get("event_count") or 0) != 0:
        raise SystemExit(
            f"current risk row {subject!r} should not be event-history driven"
        )

hundred_count = sum(1 for row in rows if int(row.get("score") or 0) >= 100)

if rows and hundred_count >= min(10, len(rows)):
    raise SystemExit(
        "current risk calibration failed: all top current-risk rows are saturated at 100"
    )

expected_only_printer_ports = {"tcp/80", "tcp/443", "tcp/631", "tcp/9100"}

for row in rows:
    open_ports = set(row.get("open_ports") or [])
    high_signal_ports = set(row.get("high_signal_ports") or [])
    classification = str(row.get("classification") or "")

    if (
        "Printer" in classification
        and open_ports
        and open_ports.issubset(expected_only_printer_ports)
        and not high_signal_ports
        and int(row.get("open_alerts") or 0) == 0
        and int(row.get("score") or 0) >= 75
    ):
        raise SystemExit(
            f"expected-service-only printer row {row.get('subject_key')} should not be CRITICAL"
        )

print(f"[PASS] current risk rows={len(rows)}")
print(f"[PASS] current risk saturated rows={hundred_count}")
print("[PASS] all current risk subjects are present in latest accepted snapshot")
print("[PASS] current risk rows are not historical-event driven")
print("[PASS] current risk scoring is calibrated against all-100 saturation")
PY

pass "DeltaAegis v0.13 current-risk validation passed"
