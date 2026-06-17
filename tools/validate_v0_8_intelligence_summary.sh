#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/DeltaAegis}" || {
  echo "[-] Could not enter DeltaAegis repo."
  exit 1
}

DB_PATH="/tmp/deltaaegis-v0.8-intelligence-summary.db"
EVENTS_PATH="/tmp/deltaaegis-v0.8-intelligence-summary-events.jsonl"

rm -f "$DB_PATH" "$EVENTS_PATH"

echo "[*] Running syntax check..."
python3 -m py_compile deltaaegis.py

echo "[*] Running live tests..."
pytest -q

echo "[*] Running existing v0.8 visibility validator..."
./tools/validate_v0_8_visibility.sh

echo
echo "[*] Building temporary database for intelligence summary validation..."
python3 deltaaegis.py \
  --db "$DB_PATH" \
  --runs-dir "$HOME/NetSniper/runs" \
  --events "$EVENTS_PATH" \
  ingest >/tmp/deltaaegis-v0.8-intelligence-summary-ingest.log

cat /tmp/deltaaegis-v0.8-intelligence-summary-ingest.log

echo
echo "[*] Validating NetSniper Intelligence Summary payload and dashboard HTML..."

python3 - "$DB_PATH" <<'PY'
import sys
from pathlib import Path

import deltaaegis as da

db_path = Path(sys.argv[1])
conn = da.connect(db_path)

summary = da.dashboard_summary_payload(conn, scope="192.168.4.0/24")
intel = summary.get("classification_summary")

if not isinstance(intel, dict):
    raise SystemExit("[-] /api/summary missing classification_summary object.")

required = [
    "total_assets",
    "classified_assets",
    "possible_assets",
    "unknown_assets",
    "evidence_backed_assets",
    "contradiction_assets",
    "high_confidence_assets",
    "classified_percent",
    "top_classifications",
    "review_queue",
]

missing = [field for field in required if field not in intel]

if missing:
    raise SystemExit(f"[-] classification_summary missing fields: {missing}")

if int(intel["total_assets"]) <= 0:
    raise SystemExit("[-] classification_summary total_assets is zero.")

if int(intel["classified_assets"]) <= 0:
    raise SystemExit("[-] classification_summary classified_assets is zero.")

if not isinstance(intel["top_classifications"], list):
    raise SystemExit("[-] top_classifications is not a list.")

if not intel["top_classifications"]:
    raise SystemExit("[-] top_classifications is empty.")

if not isinstance(intel["review_queue"], list):
    raise SystemExit("[-] review_queue is not a list.")

html = da.dashboard_index_html()

for phrase in [
    "NetSniper Intelligence Summary",
    "Classified Assets",
    "Possible / Weak",
    "Unknown Assets",
    "Evidence-backed",
    "Classification Review Queue",
    "renderClassificationSummary",
]:
    if phrase not in html:
        raise SystemExit(f"[-] dashboard HTML missing: {phrase}")

print("[+] PASS: v0.8 intelligence summary payload and dashboard renderer are present.")
print()
print("[*] Intelligence summary:")
print(f"    total assets:       {intel['total_assets']}")
print(f"    classified:         {intel['classified_assets']}")
print(f"    possible / weak:    {intel['possible_assets']}")
print(f"    unknown:            {intel['unknown_assets']}")
print(f"    evidence-backed:    {intel['evidence_backed_assets']}")
print(f"    contradictions:     {intel['contradiction_assets']}")
print(f"    high confidence:    {intel['high_confidence_assets']}")
print(f"    classified percent: {intel['classified_percent']}%")
print()
print("[*] Top classifications:")
for row in intel["top_classifications"][:5]:
    print(f"    {row['classification']}: {row['count']}")
print()
print("[*] Review queue preview:")
if not intel["review_queue"]:
    print("    no review items")
else:
    for row in intel["review_queue"][:5]:
        print(
            f"    {row['asset_key']} {row['ip_address']} "
            f"{row['classification']} {row['decision']} "
            f"conf={row['confidence']} reason={row['reason']}"
        )
PY

echo
echo "[+] PASS: DeltaAegis v0.8 intelligence summary validation succeeded."
