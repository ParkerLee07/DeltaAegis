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

./tools/validate_v0_20_ticket_evidence_payload.sh \
    || fail "v0.20 ticket evidence payload validation failed"

grep -q 'route == "/api/ticket-evidence"' deltaaegis.py \
    || fail "/api/ticket-evidence route missing"

grep -q 'dashboard_ticket_evidence_payload' deltaaegis.py \
    || fail "ticket evidence payload call missing"

grep -q 'dashboard_json_response(self, payload)' deltaaegis.py \
    || fail "ticket evidence route does not return through dashboard_json_response"

if grep -q 'self.send_json(payload)' deltaaegis.py; then
    fail "ticket evidence route still uses missing self.send_json helper"
fi

grep -q 'ticket-evidence-panel' deltaaegis.py \
    || fail "dashboard ticket evidence panel missing"

grep -q 'function renderTicketEvidence' deltaaegis.py \
    || fail "renderTicketEvidence JS helper missing"

grep -q 'function loadTicketEvidence' deltaaegis.py \
    || fail "loadTicketEvidence JS helper missing"

grep -q 'function bindTicketEvidenceButtons' deltaaegis.py \
    || fail "bindTicketEvidenceButtons JS helper missing"

grep -q 'data-ticket-evidence-subject' deltaaegis.py \
    || fail "View Evidence ticket button data attribute missing"

grep -q 'View Evidence' deltaaegis.py \
    || fail "View Evidence button label missing"

grep -q 'Evidence Timeline' deltaaegis.py \
    || fail "Evidence Timeline section missing"

grep -q 'Current Risk Evidence' deltaaegis.py \
    || fail "Current Risk Evidence table missing"

grep -q 'Ticket History' deltaaegis.py \
    || fail "Ticket History table missing"

python3 - <<'PY'
from pathlib import Path
import deltaaegis

text = Path("deltaaegis.py").read_text(encoding="utf-8")

assert "route == \"/api/ticket-evidence\"" in text
assert "subject_key = query.get(\"subject_key\", [\"\"])[0]" in text
assert "dashboard_ticket_evidence_payload(" in text
assert "renderTicketEvidence(payload)" in text
assert "loadTicketEvidence(subject)" in text
assert "bindTicketEvidenceButtons" in text

payload = deltaaegis.dashboard_ticket_evidence_payload(
    connection=None,
    subject_key="",
    scope=None,
    limit=5,
)
assert payload["available"] is False
assert "subject_key is required" in payload["error"]

print("[PASS] static v0.20 dashboard ticket evidence contract validated")
PY

pass "DeltaAegis v0.20 dashboard ticket evidence validation passed"
