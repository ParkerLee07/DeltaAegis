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

grep -q 'DeltaAegis v0.16.0 — Investigation Command Center' README.md \
    || fail "README no longer preserves v0.16.0 release text"

grep -q 'DeltaAegis v0.15.0 — MAC-Port Behavior Correlation' README.md \
    || fail "README no longer preserves v0.15.0 release text"

grep -q 'v0.16.0 — Investigation Command Center' CHANGELOG.md \
    || fail "CHANGELOG does not mention v0.16.0"

grep -q 'DeltaAegis v0.16.0' deltaaegis.py \
    || fail "CLI/script metadata no longer preserves v0.16.0 compatibility text"

grep -q 'DeltaAegis v0.15.0' deltaaegis.py \
    || fail "CLI/script metadata no longer preserves v0.15.0 compatibility text"

grep -q 'def dashboard_investigation_center_payload' deltaaegis.py \
    || fail "investigation center dashboard payload is missing"

grep -q 'def investigation_center_rows' deltaaegis.py \
    || fail "investigation center row builder is missing"

grep -q 'route == "/api/investigation-center"' deltaaegis.py \
    || fail "/api/investigation-center route is missing"

grep -q 'data-tab-target="command-center"' deltaaegis.py \
    || fail "dashboard Command Center tab is missing"

grep -q 'def command_investigation_center' deltaaegis.py \
    || fail "investigation-center CLI command is missing"

grep -q 'sub.add_parser("investigation-center"' deltaaegis.py \
    || fail "investigation-center parser is missing"

grep -q 'def append_report_investigation_center_section' deltaaegis.py \
    || fail "Investigation Command Center report section is missing"

grep -q 'Investigation Center API: `/api/investigation-center?limit=25`' deltaaegis.py \
    || fail "Investigation Center API report usage note is missing"

for validator in \
    tools/validate_v0_16_investigation_center_api.sh \
    tools/validate_v0_16_command_center_dashboard.sh \
    tools/validate_v0_16_investigation_center_cli.sh \
    tools/validate_v0_16_investigation_center_report.sh \
    tools/validate_v0_15_release.sh \
    tools/validate_v0_14_release.sh \
    tools/validate_v0_13_release.sh \
    tools/validate_v0_12_release.sh
do
    [ -x "$validator" ] || fail "Missing or non-executable validator: $validator"
done

./tools/validate_readme_current.sh
./tools/validate_v0_16_investigation_center_api.sh
./tools/validate_v0_16_command_center_dashboard.sh
./tools/validate_v0_16_investigation_center_cli.sh
./tools/validate_v0_16_investigation_center_report.sh
./tools/validate_v0_15_release.sh "$BUNDLE_DIR"
./tools/validate_v0_14_release.sh "$BUNDLE_DIR"
./tools/validate_v0_13_release.sh "$BUNDLE_DIR"
./tools/validate_v0_12_release.sh

pytest -q

pass "DeltaAegis v0.16 release validation passed"
