#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/DeltaAegis}" || {
  echo "[-] Could not enter DeltaAegis repo."
  exit 1
}

DB_PATH="/tmp/deltaaegis-v0.8-visibility.db"
EVENTS_PATH="/tmp/deltaaegis-v0.8-visibility-events.jsonl"
REPORT_PATH="/tmp/deltaaegis-v0.8-visibility-report.md"

rm -f "$DB_PATH" "$EVENTS_PATH" "$REPORT_PATH"

echo "[*] Running syntax check..."
python3 -m py_compile deltaaegis.py

echo "[*] Running live tests..."
pytest -q

echo "[*] Building temporary database from NetSniper runs..."
python3 deltaaegis.py \
  --db "$DB_PATH" \
  --runs-dir "$HOME/NetSniper/runs" \
  --events "$EVENTS_PATH" \
  ingest >/tmp/deltaaegis-v0.8-visibility-ingest.log

cat /tmp/deltaaegis-v0.8-visibility-ingest.log

echo
echo "[*] Validating dashboard/report classification visibility..."

python3 - "$DB_PATH" "$REPORT_PATH" <<'PY'
import sys
from pathlib import Path

import deltaaegis as da

db_path = Path(sys.argv[1])
report_path = Path(sys.argv[2])

conn = da.connect(db_path)

assets = da.dashboard_assets_payload(conn, limit=200, scope="192.168.4.0/24")

if not assets:
    raise SystemExit("[-] dashboard_assets_payload returned no assets.")

classified_assets = [
    row for row in assets
    if row.get("classification_display_type")
    and row.get("classification_display_type") != "Unknown"
    and int(row.get("classification_display_confidence") or 0) > 0
]

if not classified_assets:
    raise SystemExit("[-] Dashboard asset payload did not expose classification data.")

asset = classified_assets[0]

for field in [
    "classification_display_type",
    "classification_display_decision",
    "classification_display_confidence",
    "classification_evidence_count",
    "classification_contradiction_count",
]:
    if field not in asset:
        raise SystemExit(f"[-] Missing dashboard asset field: {field}")

detail = da.dashboard_asset_detail_payload(
    conn,
    asset["asset_key"],
    scope=asset["network_scope"],
)

if not detail.get("found"):
    raise SystemExit("[-] dashboard_asset_detail_payload did not find selected asset.")

observation = (
    detail.get("latest_observation")
    or detail.get("observation")
    or {}
)

for field in [
    "classification_display_type",
    "classification_display_decision",
    "classification_display_confidence",
    "classification_evidence_count",
    "classification_contradictions",
    "classification_evidence",
]:
    if field not in observation:
        raise SystemExit(f"[-] Missing asset detail observation field: {field}")

report_rows = da.report_asset_inventory_rows(conn, limit=50, scope="192.168.4.0/24")

if not report_rows:
    raise SystemExit("[-] report_asset_inventory_rows returned no rows.")

if not any(row.get("classification_display_type") for row in report_rows):
    raise SystemExit("[-] Report inventory rows do not include classification display data.")

lines = []
da.append_report_asset_inventory_section(lines, report_rows, 50)
report_text = "\\n".join(lines)
report_path.write_text(report_text, encoding="utf-8")

for phrase in [
    "Classification",
    "Decision",
    "Confidence",
    "Evidence",
    "Contradictions",
]:
    if phrase not in report_text:
        raise SystemExit(f"[-] Report inventory section missing: {phrase}")

html = da.dashboard_index_html()
for phrase in [
    "Classification",
    "NetSniper Intelligence",
    "Classification Evidence",
    "Classification Contradictions",
]:
    if phrase not in html:
        raise SystemExit(f"[-] Dashboard HTML missing: {phrase}")

print("[+] PASS: v0.8 dashboard/report classification visibility is present.")
print()
print("[*] Example dashboard row:")
print(f"    asset:          {asset['asset_key']}")
print(f"    ip:             {asset['current_ip']}")
print(f"    classification: {asset['classification_display_type']}")
print(f"    decision:       {asset['classification_display_decision']}")
print(f"    confidence:     {asset['classification_display_confidence']}")
print(f"    evidence:       {asset['classification_evidence_count']}")
print(f"    contradictions: {asset['classification_contradiction_count']}")
print()
print(f"[*] Wrote report section preview: {report_path}")
PY

echo
echo "[+] PASS: DeltaAegis v0.8 visibility validation succeeded."
