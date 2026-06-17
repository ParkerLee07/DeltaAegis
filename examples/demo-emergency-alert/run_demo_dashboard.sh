#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

DEMO_DB="/tmp/deltaaegis-demo-emergency.db"
DEMO_EVENTS="/tmp/deltaaegis-demo-emergency-events.jsonl"
DEMO_SCOPE="192.0.2.0/24"
DEMO_RUNS="examples/demo-emergency-alert/runs"
DEMO_ASSET="mac:02:42:ac:10:00:10"

rm -f "$DEMO_DB" "$DEMO_EVENTS"

echo "[1/4] Ingesting demo emergency telemetry into $DEMO_DB"
python3 deltaaegis.py \
  --db "$DEMO_DB" \
  --runs-dir "$DEMO_RUNS" \
  --events "$DEMO_EVENTS" \
  ingest

echo
echo "[2/4] Adding demo asset annotation"
python3 deltaaegis.py \
  --db "$DEMO_DB" \
  annotate-asset "$DEMO_ASSET" \
  --owner "Demo SOC" \
  --role "Synthetic Administrative Appliance" \
  --criticality "CRITICAL" \
  --notes "Synthetic demo asset used to show emergency alert, event, risk, report, and dashboard workflows."

echo
echo "[3/4] Demo alert preview"
python3 deltaaegis.py \
  --db "$DEMO_DB" \
  alerts --scope "$DEMO_SCOPE" --limit 20 || true

echo
echo "[4/4] Starting dashboard"
echo "Open: http://127.0.0.1:8090"
echo "Scope: $DEMO_SCOPE"
echo

python3 deltaaegis.py \
  --db "$DEMO_DB" \
  dashboard --host 127.0.0.1 --port 8090 --scope "$DEMO_SCOPE"
