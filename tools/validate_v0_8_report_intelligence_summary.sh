#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/DeltaAegis}" || {
  echo "[-] Could not enter DeltaAegis repo."
  exit 1
}

DB_PATH="/tmp/deltaaegis-v0.8-report-intelligence-summary.db"
EVENTS_PATH="/tmp/deltaaegis-v0.8-report-intelligence-summary-events.jsonl"
REPORT_PATH="/tmp/deltaaegis-v0.8-report-intelligence-summary.md"

rm -f "$DB_PATH" "$EVENTS_PATH" "$REPORT_PATH"

echo "[*] Running syntax check..."
python3 -m py_compile deltaaegis.py

echo "[*] Running live tests..."
pytest -q

echo "[*] Running existing v0.8 intelligence summary validator..."
./tools/validate_v0_8_intelligence_summary.sh

echo
echo "[*] Building temporary database..."
python3 deltaaegis.py \
  --db "$DB_PATH" \
  --runs-dir "$HOME/NetSniper/runs" \
  --events "$EVENTS_PATH" \
  ingest >/tmp/deltaaegis-v0.8-report-intelligence-summary-ingest.log

cat /tmp/deltaaegis-v0.8-report-intelligence-summary-ingest.log

echo
echo "[*] Generating report..."
python3 deltaaegis.py \
  --db "$DB_PATH" \
  --events "$EVENTS_PATH" \
  report \
  --latest \
  --scope 192.168.4.0/24 \
  --output "$REPORT_PATH" >/tmp/deltaaegis-v0.8-report-intelligence-summary-report.log

cat /tmp/deltaaegis-v0.8-report-intelligence-summary-report.log

echo
echo "[*] Validating report intelligence summary content..."

python3 - "$REPORT_PATH" <<'PY'
import sys
from pathlib import Path

report_path = Path(sys.argv[1])

if not report_path.is_file():
    raise SystemExit(f"[-] Missing report: {report_path}")

text = report_path.read_text(encoding="utf-8")

required_phrases = [
    "## NetSniper Intelligence Summary",
    "Classified assets",
    "Possible / weak classifications",
    "Unknown assets",
    "Evidence-backed assets",
    "Classification contradictions",
    "High-confidence assets",
    "Classified percentage",
    "### Top Classifications",
    "### Classification Review Queue",
]

missing = [phrase for phrase in required_phrases if phrase not in text]

if missing:
    raise SystemExit(f"[-] Report missing expected phrase(s): {missing}")

print("[+] PASS: report contains NetSniper intelligence summary.")
print(f"[*] Report path: {report_path}")
PY

echo
echo "[+] PASS: DeltaAegis v0.8 report intelligence summary validation succeeded."
