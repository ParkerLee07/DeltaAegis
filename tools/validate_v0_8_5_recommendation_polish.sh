#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/DeltaAegis}" || {
  echo "[-] Could not enter DeltaAegis repo."
  exit 1
}

DB_PATH="/tmp/deltaaegis-v0.8.5-recommendation-polish.db"
EVENTS_PATH="/tmp/deltaaegis-v0.8.5-recommendation-polish-events.jsonl"
REPORT_PATH="/tmp/deltaaegis-v0.8.5-recommendation-polish-report.md"

rm -f "$DB_PATH" "$EVENTS_PATH" "$REPORT_PATH"

echo "[*] Running syntax check..."
python3 -m py_compile deltaaegis.py

echo "[*] Running live tests..."
pytest -q

echo "[*] Running existing v0.8.5 role-aware recommendations validator..."
./tools/validate_v0_8_5_role_aware_recommendations.sh

echo
echo "[*] Building temporary database..."
python3 deltaaegis.py \
  --db "$DB_PATH" \
  --runs-dir "$HOME/NetSniper/runs" \
  --events "$EVENTS_PATH" \
  ingest >/tmp/deltaaegis-v0.8.5-recommendation-polish-ingest.log

cat /tmp/deltaaegis-v0.8.5-recommendation-polish-ingest.log

echo
echo "[*] Validating recommendation wording polish..."

python3 - "$DB_PATH" "$REPORT_PATH" <<'PY'
import subprocess
import sys
from pathlib import Path

import deltaaegis as da

db_path = Path(sys.argv[1])
report_path = Path(sys.argv[2])

printer_record = {
    "subject_key": "mac:test-printer",
    "classification": "Network Printer",
    "classification_decision": "unknown",
    "classification_confidence": 0,
    "classification_open_ports": [631, 9100],
    "classification_risk_reasons": [],
}

printer_actions = da.risk_role_recommended_actions(printer_record)
printer_text = " ".join(printer_actions).lower()

if "identify this unknown asset" in printer_text:
    raise SystemExit(
        "[-] Suspected printer role still receives generic unknown-asset language."
    )

if "suspected" not in printer_text or "network printer" not in printer_text:
    raise SystemExit(
        "[-] Suspected printer role does not clearly ask for role verification."
    )

unknown_record = {
    "subject_key": "mac:test-unknown",
    "classification": "Unknown",
    "classification_decision": "unknown",
    "classification_confidence": 0,
    "classification_open_ports": [8080],
    "classification_risk_reasons": [],
}

unknown_actions = da.risk_role_recommended_actions(unknown_record)
unknown_text = " ".join(unknown_actions).lower()

if "identify this unknown asset" not in unknown_text:
    raise SystemExit(
        "[-] Truly unknown assets no longer receive unknown-asset identification guidance."
    )

web_record = {
    "subject_key": "mac:test-web",
    "classification": "Web Server",
    "classification_decision": "possible",
    "classification_confidence": 20,
    "classification_open_ports": [80, 443],
    "classification_risk_reasons": [],
}

web_actions = da.risk_role_recommended_actions(web_record)
web_text = " ".join(web_actions).lower()

if "verify the suspected web server role" not in web_text:
    raise SystemExit(
        "[-] Possible web-server role does not use suspected-role verification wording."
    )

conn = da.connect(db_path)

risk_rows = da.build_risk_register(
    conn,
    limit=200,
    scope="192.168.4.0/24",
)

if not risk_rows:
    raise SystemExit("[-] build_risk_register returned no rows.")

for row in risk_rows:
    classification = str(row.get("classification") or "Unknown").strip().lower()
    actions = " ".join(row.get("recommended_actions") or []).lower()

    if classification not in {"unknown", "unknown / ambiguous", "unknown/ambiguous", ""}:
        if "identify this unknown asset" in actions:
            raise SystemExit(
                "[-] Non-unknown role still received generic unknown-asset language: "
                f"{row.get('subject_key')} classification={row.get('classification')}"
            )

subprocess.run(
    [
        sys.executable,
        "deltaaegis.py",
        "--db",
        str(db_path),
        "--events",
        "/tmp/deltaaegis-v0.8.5-recommendation-polish-events.jsonl",
        "report",
        "--latest",
        "--scope",
        "192.168.4.0/24",
        "--limit",
        "50",
        "--risk-limit",
        "50",
        "--asset-limit",
        "50",
        "--output",
        str(report_path),
    ],
    check=True,
)

report_text = report_path.read_text(encoding="utf-8").lower()

if "## role-aware recommended actions" not in report_text:
    raise SystemExit("[-] Report lost Role-Aware Recommended Actions section.")

print("[+] PASS: recommendation wording distinguishes suspected roles from truly unknown assets.")
print()
print("[*] Synthetic recommendation preview:")

for label, actions in [
    ("suspected printer", printer_actions),
    ("true unknown", unknown_actions),
    ("possible web", web_actions),
]:
    print(f"    {label}:")
    for action in actions[:3]:
        print(f"        - {action}")
PY

echo
echo "[+] PASS: DeltaAegis v0.8.5 recommendation polish validation succeeded."
