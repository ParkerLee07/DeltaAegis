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

./tools/validate_v0_17_ticket_queue_layout.sh \
    || fail "v0.17 ticket queue layout validator failed"

./tools/validate_v0_16_investigation_center_api.sh \
    || fail "v0.16 investigation center API validator failed"

grep -q 'def tune_investigation_center_ticket_signal' deltaaegis.py \
    || fail "ticket signal tuning helper is missing"

grep -q 'TICKET_EXPECTED_PRINTER_PORTS' deltaaegis.py \
    || fail "expected printer port profile is missing"

grep -q 'TICKET_HIGH_SIGNAL_PORTS' deltaaegis.py \
    || fail "high-signal port profile is missing"

grep -q 'BASELINE_CONTEXT' deltaaegis.py \
    || fail "baseline-context ticket state is missing"

grep -q 'MEANINGFUL_CHANGE' deltaaegis.py \
    || fail "meaningful-change ticket state is missing"

grep -q 'tune_investigation_center_ticket_signals(rows)' deltaaegis.py \
    || fail "dashboard investigation center payload does not tune rows"

grep -q 'report_investigation_center_rows = tune_investigation_center_ticket_signals' deltaaegis.py \
    || fail "report investigation center rows are not signal-tuned"

python3 - <<'PY'
import deltaaegis

normal_printer = {
    "subject_key": "mac:aa:bb:cc:dd:ee:ff",
    "priority_score": 100,
    "priority_level": "CRITICAL",
    "device_type": "Network Printer / Multifunction Printer",
    "classification": "Network Printer / Multifunction Printer",
    "role": "Network Printer / Multifunction Printer",
    "triggers": ["CURRENT_RISK"],
    "open_ports": ["tcp/80", "tcp/443", "tcp/631", "tcp/9100"],
    "open_alerts": 0,
    "recent_events": 0,
    "port_behavior_count": 0,
    "current_finding_count": 4,
    "primary_reason": "Current asset severity HIGH: +15",
    "recommended_action": "Confirm role.",
}

tuned = deltaaegis.tune_investigation_center_ticket_signal(normal_printer)
assert tuned["ticket_signal_state"] == "BASELINE_CONTEXT", tuned
assert tuned["priority_score"] <= 34, tuned
assert tuned["priority_level"] in {"LOW", "INFO"}, tuned
assert "BASELINE_CONTEXT" in tuned["triggers"], tuned

telnet_printer = dict(normal_printer)
telnet_printer["open_ports"] = ["tcp/80", "tcp/443", "tcp/631", "tcp/9100", "tcp/23"]

tuned_telnet = deltaaegis.tune_investigation_center_ticket_signal(telnet_printer)
assert tuned_telnet["ticket_signal_state"] == "ACTIONABLE", tuned_telnet
assert tuned_telnet["priority_score"] == 100, tuned_telnet

flapping_printer = dict(normal_printer)
flapping_printer["triggers"] = ["CURRENT_RISK", "PORT_BEHAVIOR"]
flapping_printer["port_behavior_count"] = 2

tuned_flapping = deltaaegis.tune_investigation_center_ticket_signal(flapping_printer)
assert tuned_flapping["ticket_signal_state"] == "MEANINGFUL_CHANGE", tuned_flapping
assert tuned_flapping["priority_score"] <= 74, tuned_flapping

server = dict(normal_printer)
server["device_type"] = "Linux Server"
server["classification"] = "Linux Server"
server["role"] = "Linux Server"
server["open_ports"] = ["tcp/22", "tcp/443"]
server["triggers"] = ["CURRENT_RISK"]

tuned_server = deltaaegis.tune_investigation_center_ticket_signal(server)
assert tuned_server["ticket_signal_state"] == "ACTIONABLE", tuned_server
assert tuned_server["priority_score"] == 100, tuned_server

rows = deltaaegis.tune_investigation_center_ticket_signals([
    normal_printer,
    server,
])
assert rows[0]["device_type"] == "Linux Server", rows
assert rows[-1]["ticket_signal_state"] == "BASELINE_CONTEXT", rows

summary = deltaaegis.investigation_center_summary(rows)
assert summary["baseline_context"] == 1, summary

print("[PASS] synthetic ticket signal tuning behavior validated")
PY

pass "DeltaAegis v0.17 ticket signal tuning validation passed"
