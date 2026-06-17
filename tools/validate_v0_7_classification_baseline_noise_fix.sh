#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/DeltaAegis}" || {
  echo "[-] Could not enter DeltaAegis repo."
  exit 1
}

DB_PATH="/tmp/deltaaegis-v0.7-classification-baseline-noise-fix.db"
EVENTS_PATH="/tmp/deltaaegis-v0.7-classification-baseline-noise-fix.jsonl"
INGEST_LOG="/tmp/deltaaegis-v0.7-classification-baseline-noise-fix-ingest.log"

rm -f "$DB_PATH" "$EVENTS_PATH" "$INGEST_LOG"

echo "[*] Running syntax check..."
python3 -m py_compile deltaaegis.py

echo "[*] Running live tests..."
pytest -q

echo "[*] Running classification event synthetic validator..."
./tools/validate_v0_7_classification_events.sh

echo "[*] Running real ingest baseline-noise check..."
python3 deltaaegis.py \
  --db "$DB_PATH" \
  --runs-dir "$HOME/NetSniper/runs" \
  --events "$EVENTS_PATH" \
  ingest > "$INGEST_LOG"

cat "$INGEST_LOG"

echo
echo "[*] Checking for classification events created only because v1.4 intelligence first appeared..."

classification_lines="$(
  if [ -f "$EVENTS_PATH" ]; then
    grep -E 'DEVICE_CLASSIFICATION_CHANGED|DEVICE_CLASSIFICATION_CONFIDENCE_CHANGED|DEVICE_CLASSIFICATION_WEAK|DEVICE_CLASSIFICATION_CONTRADICTION' "$EVENTS_PATH" 2>/dev/null || true
  fi
)"

bad_lines="$(
  printf '%s\n' "$classification_lines" \
    | grep -E '"classification_method": null|"classification_type": null|"device_type_confidence": null' \
    || true
)"

bad_count="$(
  printf '%s\n' "$bad_lines" \
    | awk 'NF {count++} END {print count + 0}'
)"

if [ "$bad_count" -ne 0 ]; then
  echo "[-] Found $bad_count classification event(s) comparing against pre-v1.4/non-intelligence baselines."
  printf '%s\n' "$bad_lines" | head -10
  exit 1
fi

echo "[+] PASS: No classification events were generated from pre-v1.4/non-intelligence baselines."

echo
echo "[*] Classification event summary:"
printf '%s\n' "$classification_lines" | python3 -c '
import json, sys
from collections import Counter

counts = Counter()

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        counts[json.loads(line)["event_type"]] += 1
    except Exception:
        pass

if not counts:
    print("    no real classification events observed")
else:
    for key, value in sorted(counts.items()):
        print(f"    {key}: {value}")
'

echo
echo "[+] PASS: Classification baseline-noise validation succeeded."
