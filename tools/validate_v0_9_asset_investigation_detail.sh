#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/DeltaAegis}" || {
  echo "[-] Could not enter DeltaAegis repo."
  exit 1
}

DB_PATH="/tmp/deltaaegis-v0.9-asset-investigation.db"
EVENTS_PATH="/tmp/deltaaegis-v0.9-asset-investigation-events.jsonl"
INGEST_LOG="/tmp/deltaaegis-v0.9-asset-investigation-ingest.log"

rm -f "$DB_PATH" "$EVENTS_PATH" "$INGEST_LOG"

echo "[*] Running syntax check..."
python3 -m py_compile deltaaegis.py

echo "[*] Running live tests..."
pytest -q

echo "[*] Building temporary database from NetSniper runs..."
python3 deltaaegis.py \
  --db "$DB_PATH" \
  --runs-dir "$HOME/NetSniper/runs" \
  --events "$EVENTS_PATH" \
  ingest >"$INGEST_LOG"

tail -20 "$INGEST_LOG"

echo
echo "[*] Validating v0.9 asset investigation detail payload..."

python3 - "$DB_PATH" <<'PY'
import sys
from pathlib import Path

import deltaaegis as da

db_path = Path(sys.argv[1])
conn = da.connect(db_path)

assets = da.dashboard_assets_payload(conn, limit=200)

if not assets:
    raise SystemExit("[-] dashboard_assets_payload returned no assets.")

selected = None

for asset in assets:
    if asset.get("classification_has_intelligence") or asset.get("classification_evidence_count"):
        selected = asset
        break

if selected is None:
    selected = assets[0]

identifier = selected.get("asset_key") or selected.get("current_ip")

detail = da.dashboard_asset_detail_payload(conn, identifier, scope=selected.get("network_scope"))

if not detail.get("found"):
    raise SystemExit(f"[-] Asset detail lookup failed for {identifier}: {detail}")

investigation = detail.get("investigation")

if not isinstance(investigation, dict):
    raise SystemExit("[-] Asset detail payload is missing investigation object.")

allowed_statuses = {
    "NEW",
    "REVIEWING",
    "EXPECTED",
    "FALSE_POSITIVE",
    "MONITORING",
    "RESOLVED",
}

if investigation.get("status") not in allowed_statuses:
    raise SystemExit(f"[-] Unexpected investigation status: {investigation.get('status')}")

steps = investigation.get("recommended_next_steps")

if not isinstance(steps, list) or not steps:
    raise SystemExit("[-] recommended_next_steps must be a non-empty list.")

context = investigation.get("review_context")

if not isinstance(context, dict):
    raise SystemExit("[-] investigation.review_context is missing.")

required_context = [
    "classification_type",
    "classification_decision",
    "classification_confidence",
    "service_count",
    "finding_count",
    "event_count",
    "alert_count",
    "alert_note_count",
    "has_annotation",
]

missing = [key for key in required_context if key not in context]

if missing:
    raise SystemExit(f"[-] investigation.review_context missing keys: {missing}")

timeline = investigation.get("timeline")

if not isinstance(timeline, list):
    raise SystemExit("[-] investigation.timeline must be a list.")

html = da.dashboard_index_html()

required_html = [
    "Investigation Summary",
    "Recommended Next Steps",
    "Investigation Timeline",
    "Alert Review Notes",
    "payload.investigation",
    "recommended_next_steps",
]

missing_html = [item for item in required_html if item not in html]

if missing_html:
    raise SystemExit(f"[-] Dashboard HTML missing investigation markers: {missing_html}")

print("[+] PASS: v0.9 asset investigation detail payload is present.")
print(f"[*] Selected asset: {identifier}")
print(f"[*] Status: {investigation.get('status')}")
print(f"[*] Steps: {len(steps)}")
print(f"[*] Timeline items: {len(timeline)}")
PY

echo
echo "[+] PASS: DeltaAegis v0.9 asset investigation detail validation succeeded."
