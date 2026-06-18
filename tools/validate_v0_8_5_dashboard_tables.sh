#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/DeltaAegis}" || {
  echo "[-] Could not enter DeltaAegis repo."
  exit 1
}

echo "[*] Running syntax check..."
python3 -m py_compile deltaaegis.py

echo "[*] Running live tests..."
pytest -q

echo "[*] Validating dashboard table rendering IDs and backend payloads..."

python3 - <<'PY'
from pathlib import Path
import deltaaegis as da

db_path = Path("data/deltaaegis.db")

if not db_path.is_file():
    raise SystemExit("[-] Expected local DeltaAegis database is missing: data/deltaaegis.db")

conn = da.connect(db_path)

scope = "192.168.4.0/24"

risk_rows = da.dashboard_risk_payload(conn, 20, scope=scope)
event_rows = da.dashboard_events_payload(conn, 20, scope=scope)
alert_rows = da.dashboard_alerts_payload(conn, 20, scope=scope)

print(f"risk rows:  {len(risk_rows)}")
print(f"event rows: {len(event_rows)}")
print(f"alert rows: {len(alert_rows)}")

if not risk_rows:
    raise SystemExit("[-] Backend dashboard risk payload is empty, but this database should have risk rows.")

if not event_rows:
    raise SystemExit("[-] Backend dashboard event payload is empty, but this database should have recent events.")

if not alert_rows:
    raise SystemExit("[-] Backend dashboard alert payload is empty, but this database should have alerts.")

html = da.dashboard_index_html()

required_html = [
    '<tbody id="risk-body"></tbody>',
    '<tbody id="events-body"></tbody>',
    '<tbody id="alerts-body"></tbody>',
]

required_js = [
    'document.getElementById("risk-body")',
    'document.getElementById("events-body")',
    'document.getElementById("alerts-body")',
]

for item in required_html + required_js:
    if item not in html:
        raise SystemExit(f"[-] Dashboard HTML/JS missing required ID/reference: {item}")

stale_ids = [
    '<tbody id="risk"></tbody>',
    '<tbody id="risk-subjects"></tbody>',
    '<tbody id="events"></tbody>',
    '<tbody id="delta-events"></tbody>',
    '<tbody id="alerts"></tbody>',
]

for item in stale_ids:
    if item in html:
        raise SystemExit(f"[-] Dashboard still contains stale tbody id: {item}")

sample = risk_rows[0]

for key in ["level", "score", "subject_key"]:
    if key not in sample:
        raise SystemExit(f"[-] Risk payload row missing expected key: {key}")

print("[+] PASS: dashboard risk, event, and alert tables have matching HTML/JS IDs and non-empty backend payloads.")
PY

echo
echo "[+] PASS: DeltaAegis v0.8.5 dashboard table validation succeeded."
