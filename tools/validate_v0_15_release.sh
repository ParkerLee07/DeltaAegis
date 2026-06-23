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

grep -q 'DeltaAegis v0.15.0 — MAC-Port Behavior Correlation' README.md \
    || fail "README no longer preserves v0.15.0 release text"

grep -q 'DeltaAegis v0.14.0 — NetSniper Scan Orchestration' README.md \
    || fail "README no longer preserves v0.14.0 compatibility text"

grep -q 'v0.15.0 — MAC-Port Behavior Correlation' CHANGELOG.md \
    || fail "CHANGELOG does not mention v0.15.0"

grep -q 'DeltaAegis v0.15.0' deltaaegis.py \
    || fail "CLI/script metadata does not mention v0.15.0"

grep -q 'DeltaAegis v0.14.0' deltaaegis.py \
    || fail "CLI/script metadata no longer preserves v0.14.0 compatibility text"

grep -q 'def command_port_behavior' deltaaegis.py \
    || fail "port-behavior CLI command is missing"

grep -q 'route == "/api/port-behavior"' deltaaegis.py \
    || fail "/api/port-behavior route is missing"

grep -q 'data-tab-target="port-behavior"' deltaaegis.py \
    || fail "dashboard Port Behavior tab is missing"

grep -q 'def current_port_behavior_risk_by_asset' deltaaegis.py \
    || fail "port behavior current-risk helper is missing"

grep -q 'def append_report_port_behavior_section' deltaaegis.py \
    || fail "MAC-port behavior report section is missing"

grep -q 'MAC-Port Behavior Changes' deltaaegis.py \
    || fail "MAC-Port Behavior Changes report heading is missing"

grep -q 'Port behavior API: `/api/port-behavior?limit=25&lookback=5`' deltaaegis.py \
    || fail "Port Behavior API report usage note is missing"

for validator in \
    tools/validate_v0_15_port_behavior_cli.sh \
    tools/validate_v0_15_port_behavior_dashboard.sh \
    tools/validate_v0_15_port_behavior_risk.sh \
    tools/validate_v0_15_port_behavior_report.sh \
    tools/validate_v0_14_release.sh \
    tools/validate_v0_13_release.sh \
    tools/validate_v0_12_release.sh
do
    [ -x "$validator" ] || fail "Missing or non-executable validator: $validator"
done

./tools/validate_readme_current.sh
./tools/validate_v0_15_port_behavior_cli.sh
./tools/validate_v0_15_port_behavior_dashboard.sh
./tools/validate_v0_15_port_behavior_risk.sh
./tools/validate_v0_15_port_behavior_report.sh
./tools/validate_v0_14_release.sh "$BUNDLE_DIR"
./tools/validate_v0_13_release.sh "$BUNDLE_DIR"
./tools/validate_v0_12_release.sh

pass "DeltaAegis v0.15 release validation passed"
