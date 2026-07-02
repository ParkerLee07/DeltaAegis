#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py

python3 - <<'PY'
from pathlib import Path

text = Path("deltaaegis.py").read_text(encoding="utf-8")

required = [
    '"admin.telemetry.cleanup": "ADMIN"',
    '("GET", "/api/telemetry-cleanup/preview", "admin.telemetry.cleanup")',
    '("POST", "/api/telemetry-cleanup/clear-all", "admin.telemetry.cleanup")',
    "def dashboard_telemetry_cleanup_preview_payload(",
    "def dashboard_telemetry_cleanup_clear_all_payload(",
    "telemetry_cleanup_preview(connection)",
    "telemetry_cleanup_clear_all(",
    'action="TELEMETRY_CLEANUP_CLEAR_ALL"',
    'route == "/api/telemetry-cleanup/preview"',
    'route == "/api/telemetry-cleanup/clear-all"',
    'self.require_permission("admin.telemetry.cleanup")',
    "dashboard_read_request_payload(self)",
    "connection.commit()",
    "TELEMETRY_CLEANUP_CONFIRMATION",
    'id="deltaaegis-telemetry-cleanup-panel"',
    'id="telemetry-cleanup-confirmation"',
    'id="telemetry-cleanup-clear-all"',
    'fetch("/api/telemetry-cleanup/preview"',
    'fetch("/api/telemetry-cleanup/clear-all"',
    "Type DELETE TELEMETRY exactly",
]

for needle in required:
    if needle not in text:
        raise SystemExit(f"[FAIL] missing telemetry cleanup dashboard/API requirement: {needle}")

preview_index = text.find('route == "/api/telemetry-cleanup/preview"')
clear_index = text.find('route == "/api/telemetry-cleanup/clear-all"')
if preview_index < 0 or clear_index < 0:
    raise SystemExit("[FAIL] telemetry cleanup routes are missing")

preview_block_end = text.find("if route ==", preview_index + 1)
preview_block = text[preview_index:preview_block_end if preview_block_end > preview_index else preview_index + 900]
if 'self.require_permission("admin.telemetry.cleanup")' not in preview_block:
    raise SystemExit("[FAIL] preview route is not explicitly ADMIN-gated")

clear_block_end = text.find('if route in {\n                "/api/netsniper/schedule-create"', clear_index)
if clear_block_end < 0:
    clear_block_end = text.find("return", clear_index) + 500
clear_block = text[clear_index:clear_block_end]
for needle in [
    'self.require_permission("admin.telemetry.cleanup")',
    "dashboard_read_request_payload(self)",
    "dashboard_telemetry_cleanup_clear_all_payload(",
    "connection.commit()",
]:
    if needle not in clear_block:
        raise SystemExit(f"[FAIL] clear-all route missing guardrail: {needle}")

payload_start = text.find("def dashboard_telemetry_cleanup_clear_all_payload(")
payload_end = text.find("\ndef ", payload_start + 1)
payload_block = text[payload_start:payload_end if payload_end > payload_start else len(text)]

for needle in [
    "dashboard_bool_from_payload",
    "telemetry_cleanup_clear_all(",
    "record_access_audit_event(",
    'action="TELEMETRY_CLEANUP_CLEAR_ALL"',
    "total_deleted_rows",
    "protected_tables_preserved",
]:
    if needle not in payload_block:
        raise SystemExit(f"[FAIL] clear-all payload missing audit/safety detail: {needle}")

if "DELETE FROM access_users" in payload_block or "DELETE FROM access_api_tokens" in payload_block or "DELETE FROM access_sessions" in payload_block:
    raise SystemExit("[FAIL] dashboard/API payload directly deletes protected auth tables")

print("[PASS] v0.36 telemetry cleanup dashboard/API python checks passed")
PY

time tools/validate_v0_36_telemetry_cleanup.sh

echo "[PASS] DeltaAegis v0.36 telemetry cleanup dashboard/API validation passed"
