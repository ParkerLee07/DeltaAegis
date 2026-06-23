#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BUNDLE_DIR="${1:-/home/parker/NetSniper/runs/20260623-123007}"

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

pass() {
    echo "[PASS] $*"
}

[ -d "$BUNDLE_DIR" ] || fail "Bundle directory not found: $BUNDLE_DIR"

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

grep -q 'DeltaAegis v0.14.0 — NetSniper Scan Orchestration' README.md \
    || fail "README does not identify v0.14.0 as current release"

grep -q 'v0.14.0 — NetSniper Scan Orchestration' CHANGELOG.md \
    || fail "CHANGELOG does not mention v0.14.0"

grep -q 'DeltaAegis v0.14.0' deltaaegis.py \
    || fail "CLI/script metadata does not mention v0.14.0"

grep -q 'CREATE TABLE IF NOT EXISTS scan_jobs' deltaaegis.py \
    || fail "scan_jobs table is missing"

grep -q 'def command_scan_start' deltaaegis.py \
    || fail "scan-start command is missing"

grep -q 'def command_scan_jobs' deltaaegis.py \
    || fail "scan-jobs command is missing"

grep -q 'route == "/api/scan-jobs"' deltaaegis.py \
    || fail "/api/scan-jobs route is missing"

grep -q 'data-tab-target="scan-jobs"' deltaaegis.py \
    || fail "dashboard Scan Jobs tab is missing"

grep -q 'Why This Level?' deltaaegis.py \
    || fail "dashboard risk explanations are missing"

grep -q -- '--non-interactive' deltaaegis.py \
    || fail "fixed NetSniper command does not include --non-interactive"

grep -q -- '--greenbone' deltaaegis.py \
    || fail "fixed NetSniper command does not include --greenbone"

grep -q -- '--json-status' deltaaegis.py \
    || fail "fixed NetSniper command does not include --json-status"

grep -q 'target must be a private IPv4 CIDR' deltaaegis.py \
    || fail "private CIDR safety guard is missing"

if grep -q 'route == "/api/scan-start"' deltaaegis.py; then
    fail "v0.14 should not expose dashboard /api/scan-start"
fi

for validator in \
    tools/validate_v0_14_scan_job_registry.sh \
    tools/validate_v0_14_scan_start.sh \
    tools/validate_v0_14_scan_jobs_dashboard.sh \
    tools/validate_v0_14_risk_explanations.sh
do
    [ -x "$validator" ] || fail "Missing or non-executable validator: $validator"
done

./tools/validate_v0_14_scan_job_registry.sh
./tools/validate_v0_14_scan_start.sh
./tools/validate_v0_14_scan_jobs_dashboard.sh
./tools/validate_v0_14_risk_explanations.sh
./tools/validate_v0_13_release.sh "$BUNDLE_DIR"

pass "DeltaAegis v0.14 release validation passed"
