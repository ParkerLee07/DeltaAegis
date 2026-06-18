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

echo "[*] Running dashboard table validator..."
./tools/validate_v0_8_5_dashboard_tables.sh

echo "[*] Validating dashboard column alignment..."

python3 - <<'PY'
import re
import deltaaegis as da

html = da.dashboard_index_html()

required_text = [
    "Top Risk Subjects",
    "Recent Delta Events",
    "Recent Alerts",
    "Open Alerts",
    "Events",
    "Primary Reason",
    "<th>Type</th>",
    'document.getElementById("risk-body")',
    'document.getElementById("events-body")',
    'document.getElementById("alerts-body")',
    'colspan="11">No risk subjects calculated',
    'colspan="11">No recent delta events matched',
    'colspan="9">No recent alerts matched',
]

missing = [item for item in required_text if item not in html]

if missing:
    raise SystemExit(f"[-] Dashboard alignment content missing: {missing}")

def section_between(title, next_title=None):
    start = html.find(f"<h2>{title}</h2>")

    if start == -1:
        raise SystemExit(f"[-] Could not find section title: {title}")

    if next_title:
        end = html.find(f"<h2>{next_title}</h2>", start + 1)
    else:
        end = html.find("</section>", start + 1)

    if end == -1:
        end = start + 6000

    return html[start:end]

def count_headers(section):
    return len(re.findall(r"<th\b", section, flags=re.I))

risk_section = section_between("Top Risk Subjects", "Recent Delta Events")
event_section = section_between("Recent Delta Events", "Recent Alerts")
alert_section = section_between("Recent Alerts", "Asset Annotations")

risk_cols = count_headers(risk_section)
event_cols = count_headers(event_section)
alert_cols = count_headers(alert_section)

print(f"risk header columns:  {risk_cols}")
print(f"event header columns: {event_cols}")
print(f"alert header columns: {alert_cols}")

if risk_cols != 11:
    raise SystemExit(f"[-] Top Risk Subjects should have 11 columns, found {risk_cols}.")

if event_cols != 11:
    raise SystemExit(f"[-] Recent Delta Events should have 11 columns, found {event_cols}.")

if alert_cols != 9:
    raise SystemExit(f"[-] Recent Alerts should have 9 columns, found {alert_cols}.")

def function_slice(name):
    start = html.find(f"function {name}(")

    if start == -1:
        raise SystemExit(f"[-] Missing JavaScript function: {name}")

    next_names = [
        html.find(f"function {candidate}(", start + 1)
        for candidate in [
            "renderRisk",
            "renderEvents",
            "renderAlerts",
            "renderAnnotations",
            "renderRecommendedNextSteps",
            "loadDashboard",
        ]
    ]

    next_names = [index for index in next_names if index != -1]

    if next_names:
        end = min(next_names)
    else:
        end = start + 5000

    return html[start:end]

render_risk = function_slice("renderRisk")
render_events = function_slice("renderEvents")
render_alerts = function_slice("renderAlerts")

risk_required = [
    'document.getElementById("risk-body")',
    'colspan="11"',
    "row.level",
    "row.score",
    "row.subject_key",
    "row.ip_address || row.ip",
    "row.mac_address || row.mac",
    "row.identity_confidence || row.identity_state",
    "row.owner",
    "row.role || row.classification",
    "row.open_alerts",
    "row.event_count",
    "primaryReason",
]

event_required = [
    'document.getElementById("events-body")',
    'colspan="11"',
    "row.event_id || row.id",
    "row.scan_id",
    "row.baseline_scan_id",
    "row.severity",
    "row.event_type || row.type",
    "row.subject_key",
    "row.ip_address || row.ip",
    "row.mac_address || row.mac",
    "row.identity_confidence || row.identity_state",
    "row.created_at",
    "row.summary",
]

alert_required = [
    'document.getElementById("alerts-body")',
    'colspan="9"',
    "row.alert_id || row.id",
    "row.status",
    "row.severity",
    "row.subject_key",
    "row.event_type || row.type",
    "row.ip_address || row.ip",
    "row.mac_address || row.mac",
    "row.identity_confidence || row.identity_state",
    "row.summary",
]

for label, snippet, required in [
    ("renderRisk", render_risk, risk_required),
    ("renderEvents", render_events, event_required),
    ("renderAlerts", render_alerts, alert_required),
]:
    missing = [item for item in required if item not in snippet]

    if missing:
        raise SystemExit(f"[-] {label} missing expected aligned field(s): {missing}")

    print(f"[+] {label} contains expected aligned fields.")

print("[+] PASS: dashboard table headers and renderers are aligned.")
PY

echo
echo "[+] PASS: DeltaAegis v0.8.5 dashboard column alignment validation succeeded."
