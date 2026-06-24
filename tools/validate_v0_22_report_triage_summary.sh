#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

pass() {
    echo "[PASS] $*"
}

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

grep -q 'operator_triage_summary(rows)' deltaaegis.py \
    || fail "report section does not call operator_triage_summary"

grep -q 'Operator triage buckets' deltaaegis.py \
    || fail "report section missing operator triage bucket summary"

grep -q 'Workflow | Signal | Subject | Triage | Triage Score' deltaaegis.py \
    || fail "report queue table does not preserve Workflow/Signal/Subject before triage columns"

python3 - <<'PY'
import deltaaegis as da

lines = []
rows = [
    da.operator_triage_enrich_row({
        "subject_key": "mac:aa",
        "priority_level": "HIGH",
        "priority_score": 74,
        "ticket_status": "OPEN",
        "ticket_signal_state": "MEANINGFUL_CHANGE",
        "ip_address": "192.168.5.10",
        "mac_address": "aa:aa:aa:aa:aa:aa",
        "device_type": "Linux Server",
        "role": "Server",
        "triggers": ["CURRENT_RISK", "RECENT_EVENT"],
        "primary_reason": "Synthetic high-priority reason",
        "recommended_action": "Synthetic action",
        "latest_event_at": "2026-06-24T17:00:00+00:00",
    }),
    da.operator_triage_enrich_row({
        "subject_key": "mac:bb",
        "priority_level": "LOW",
        "priority_score": 22,
        "ticket_status": "OPEN",
        "ticket_signal_state": "BASELINE_CONTEXT",
        "ip_address": "192.168.5.11",
        "mac_address": "bb:bb:bb:bb:bb:bb",
        "device_type": "Network Printer / Multifunction Printer",
        "role": "Printer",
        "triggers": ["CURRENT_RISK"],
        "primary_reason": "Synthetic baseline reason",
        "recommended_action": "Synthetic baseline action",
        "latest_event_at": "2026-06-24T16:00:00+00:00",
    }),
]

da.append_report_investigation_center_section(lines, rows)
report = "\n".join(lines)

required = [
    "## Investigation Command Center",
    "Operator triage buckets",
    "Operator triage urgency",
    "Missing context flags",
    "| Priority | Score | Workflow | Signal | Subject | Triage | Triage Score |",
    "NEEDS_REVIEW /",
    "NEEDS_CONTEXT /",
]

for marker in required:
    assert marker in report, marker

# Compatibility guard: older validators expect Workflow, Signal, and Subject to remain contiguous.
assert "| Priority | Score | Workflow | Signal | Subject |" in report, report

print("[PASS] synthetic v0.22 report triage summary validated")
PY

pass "DeltaAegis v0.22 report triage summary validation passed"
