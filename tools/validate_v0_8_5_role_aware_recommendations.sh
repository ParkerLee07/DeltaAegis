#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/DeltaAegis}" || {
  echo "[-] Could not enter DeltaAegis repo."
  exit 1
}

DB_PATH="/tmp/deltaaegis-v0.8.5-role-aware-recommendations.db"
EVENTS_PATH="/tmp/deltaaegis-v0.8.5-role-aware-recommendations-events.jsonl"
REPORT_PATH="/tmp/deltaaegis-v0.8.5-role-aware-recommendations-report.md"

rm -f "$DB_PATH" "$EVENTS_PATH" "$REPORT_PATH"

echo "[*] Running syntax check..."
python3 -m py_compile deltaaegis.py

echo "[*] Running live tests..."
pytest -q

echo "[*] Running existing v0.8.5 role-aware risk validator..."
./tools/validate_v0_8_5_role_aware_risk.sh

echo
echo "[*] Building temporary database..."
python3 deltaaegis.py \
  --db "$DB_PATH" \
  --runs-dir "$HOME/NetSniper/runs" \
  --events "$EVENTS_PATH" \
  ingest >/tmp/deltaaegis-v0.8.5-role-aware-recommendations-ingest.log

cat /tmp/deltaaegis-v0.8.5-role-aware-recommendations-ingest.log

echo
echo "[*] Validating role-aware recommended actions..."

python3 - "$DB_PATH" "$REPORT_PATH" <<'PY'
import subprocess
import sys
from pathlib import Path

import deltaaegis as da

db_path = Path(sys.argv[1])
report_path = Path(sys.argv[2])

conn = da.connect(db_path)

risk_rows = da.build_risk_register(
    conn,
    limit=200,
    scope="192.168.4.0/24",
)

if not risk_rows:
    raise SystemExit("[-] build_risk_register returned no rows.")

action_rows = [
    row for row in risk_rows
    if row.get("recommended_actions")
]

if not action_rows:
    raise SystemExit("[-] No risk rows include role-aware recommended actions.")

if not any(row.get("classification") for row in action_rows):
    raise SystemExit("[-] Recommended-action rows are missing classification labels.")

if not any(
    any(
        keyword in action.lower()
        for keyword in ["verify", "review", "validate", "annotate", "identify", "confirm"]
    )
    for row in action_rows
    for action in row.get("recommended_actions", [])
):
    raise SystemExit("[-] Recommended actions do not contain useful operator verbs.")

dashboard_rows = da.dashboard_risk_payload(
    conn,
    limit=50,
    scope="192.168.4.0/24",
)

if not any(row.get("recommended_actions") for row in dashboard_rows):
    raise SystemExit("[-] Dashboard risk payload does not expose recommended_actions.")

html = da.dashboard_index_html()

if "Role-aware follow-up for" not in html:
    raise SystemExit("[-] Dashboard HTML does not render role-aware recommendations.")

subprocess.run(
    [
        sys.executable,
        "deltaaegis.py",
        "--db",
        str(db_path),
        "--events",
        "/tmp/deltaaegis-v0.8.5-role-aware-recommendations-events.jsonl",
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

report_text = report_path.read_text(encoding="utf-8")

required = [
    "## Role-Aware Recommended Actions",
    "Recommended action:",
]

missing = [phrase for phrase in required if phrase not in report_text]

if missing:
    raise SystemExit(f"[-] Report missing role-aware recommendation phrase(s): {missing}")

print("[+] PASS: role-aware recommended actions are present in risk register, dashboard payload, dashboard guidance, and report.")
print()
print("[*] Role-aware recommendation preview:")
for row in action_rows[:6]:
    print(
        f"    {row['level']:<8} score={row['score']:>3} "
        f"{row.get('subject_key')} "
        f"classification={row.get('classification')} "
        f"decision={row.get('classification_decision')} "
        f"confidence={row.get('classification_confidence')}"
    )
    for action in row.get("recommended_actions", [])[:2]:
        print(f"        - {action}")
PY

echo
echo "[+] PASS: DeltaAegis v0.8.5 role-aware recommendations validation succeeded."
