#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

pass() {
    echo "[PASS] $1"
}

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

grep -Fq 'DeltaAegis v0.32.0: NetSniper v2 telemetry compatibility' deltaaegis.py \
    || fail "deltaaegis.py top metadata does not advertise v0.32.0"

grep -Fq 'DeltaAegis v0.32.0 — NetSniper v2 Compatibility' deltaaegis.py \
    || fail "CLI parser metadata does not advertise v0.32.0"

grep -Fq '## Current Release — v0.32.0' README.md \
    || fail "README does not advertise v0.32.0 as current release"

grep -Fq 'DeltaAegis v0.32.0 — NetSniper v2 Compatibility' README.md \
    || fail "README missing v0.32.0 release title"

grep -Fq 'netsniper-run-v3' README.md \
    || fail "README missing netsniper-run-v3 release detail"

grep -Fq 'bundle_quality.json' README.md \
    || fail "README missing bundle_quality.json release detail"

grep -Fq './tools/validate_v0_32_release.sh' README.md \
    || fail "README missing v0.32 release gate command"

grep -Fq '## v0.32.0 — NetSniper v2 Compatibility' CHANGELOG.md \
    || fail "CHANGELOG missing v0.32.0 entry"

python3 - <<'PY_META'
from pathlib import Path

readme = Path("README.md").read_text(encoding="utf-8")
source = Path("deltaaegis.py").read_text(encoding="utf-8")
release_gate = Path("tools/validate_v0_32_release.sh").read_text(encoding="utf-8")

start = readme.find("## Current Release")
assert start != -1, "README missing Current Release section"
next_section = readme.find("\n## ", start + 1)
current = readme[start:] if next_section == -1 else readme[start:next_section]

assert "Current Release — v0.32.0" in current
assert "DeltaAegis v0.32.0 — NetSniper v2 Compatibility" in current
assert "netsniper-run-v3" in current
assert "bundle_quality.json" in current
assert "./tools/validate_v0_32_release.sh" in current
assert "Current Release — v0.31.0" not in current
assert "DeltaAegis v0.31.0 — Scheduled Profile-Aware Scans" not in current

required_source = [
    'NETSNIPER_SUPPORTED_SCHEMAS = {"netsniper-run-v1", "netsniper-run-v2", "netsniper-run-v3"}',
    'NETSNIPER_PROFILE_AWARE_SCHEMAS = {"netsniper-run-v2", "netsniper-run-v3"}',
    "def load_netsniper_bundle_quality(",
    "bundle_deltaaegis_ready",
    "bundle_quality_json",
    "requested_profile",
    "effective_profile",
    "profile_runtime_budget_seconds",
    "def dashboard_scan_context_payload(",
    "Requested profile",
    "Effective profile",
    "Runtime budget",
    "DeltaAegis ready",
]

missing_source = [item for item in required_source if item not in source]
assert not missing_source, f"missing v0.32 source fragments: {missing_source}"

required_validators = [
    "validate_v0_32_netsniper_v2_ingest.sh",
    "validate_v0_32_dashboard_v2_metadata.sh",
    "validate_v0_32_release_metadata.sh",
    "python3 -m pytest tests/test_deltaaegis_v02.py",
]

missing_validators = [item for item in required_validators if item not in release_gate]
assert not missing_validators, f"release gate missing validators: {missing_validators}"

for forbidden in (
    "validate_v0_31_release_metadata.sh",
    "validate_v0_31_release.sh",
):
    assert forbidden not in release_gate, (
        "v0.32 release gate must not execute older metadata release gates"
    )

print("[PASS] v0.32 release metadata python checks passed")
PY_META

pass "DeltaAegis v0.32 release metadata validation passed"
