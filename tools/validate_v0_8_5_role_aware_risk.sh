#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/DeltaAegis}" || {
  echo "[-] Could not enter DeltaAegis repo."
  exit 1
}

DB_PATH="/tmp/deltaaegis-v0.8.5-role-aware-risk.db"
EVENTS_PATH="/tmp/deltaaegis-v0.8.5-role-aware-risk-events.jsonl"
REPORT_PATH="/tmp/deltaaegis-v0.8.5-role-aware-risk-report.md"

rm -f "$DB_PATH" "$EVENTS_PATH" "$REPORT_PATH"

echo "[*] Running syntax check..."
python3 -m py_compile deltaaegis.py

echo "[*] Running live tests..."
pytest -q

echo "[*] Running existing v0.8 report intelligence validator..."
./tools/validate_v0_8_report_intelligence_summary.sh

echo
echo "[*] Building temporary database..."
python3 deltaaegis.py \
  --db "$DB_PATH" \
  --runs-dir "$HOME/NetSniper/runs" \
  --events "$EVENTS_PATH" \
  ingest >/tmp/deltaaegis-v0.8.5-role-aware-risk-ingest.log

cat /tmp/deltaaegis-v0.8.5-role-aware-risk-ingest.log

echo
echo "[*] Validating classification-aware risk register..."

python3 - "$DB_PATH" "$REPORT_PATH" <<'PY'
import sys
from pathlib import Path

import deltaaegis as da
import subprocess

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

role_context_rows = [
    row for row in risk_rows
    if int(row.get("classification_risk_points") or 0) > 0
]

if not role_context_rows:
    raise SystemExit("[-] No risk rows received classification-aware role context points.")

if not any(row.get("classification") for row in role_context_rows):
    raise SystemExit("[-] Role-aware risk rows are missing classification labels.")

if not any(row.get("classification_risk_reasons") for row in role_context_rows):
    raise SystemExit("[-] Role-aware risk rows are missing classification risk reasons.")

if not any(
    any("Classification-aware role context" in reason for reason in row.get("reasons", []))
    for row in role_context_rows
):
    raise SystemExit("[-] Classification-aware reasons were not merged into risk reasons.")

dashboard_rows = da.dashboard_risk_payload(
    conn,
    limit=50,
    scope="192.168.4.0/24",
)

if not any(int(row.get("classification_risk_points") or 0) > 0 for row in dashboard_rows):
    raise SystemExit("[-] Dashboard risk payload did not expose classification-aware context.")

subprocess.run(
    [
        sys.executable,
        "deltaaegis.py",
        "--db",
        str(db_path),
        "--events",
        "/tmp/deltaaegis-v0.8.5-role-aware-risk-events.jsonl",
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

if "classification-aware role context" not in report_text.lower():
    raise SystemExit("[-] Report does not mention classification-aware role context.")

print("[+] PASS: classification-aware role context is present in risk register, dashboard payload, and report.")
print()
print("[*] Role-aware risk preview:")
for row in role_context_rows[:8]:
    print(
        f"    {row['level']:<8} score={row['score']:>3} "
        f"context=+{row.get('classification_risk_points')} "
        f"{row.get('subject_key')} "
        f"classification={row.get('classification')} "
        f"decision={row.get('classification_decision')} "
        f"confidence={row.get('classification_confidence')}"
    )

    for reason in row.get("classification_risk_reasons", [])[:2]:
        print(f"        - {reason}")
PY

echo
echo "[+] PASS: DeltaAegis v0.8.5 role-aware risk validation succeeded."
