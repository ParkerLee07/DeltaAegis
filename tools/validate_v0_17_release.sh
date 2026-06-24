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

grep -q 'DeltaAegis v0.17.0 — Executive SIEM Dashboard Refresh' README.md \
    || fail "README does not identify v0.17.0 as current release"

grep -q 'DeltaAegis v0.16.0 — Investigation Command Center' README.md \
    || fail "README no longer preserves v0.16.0 release text"

grep -q 'v0.17.0 — Executive SIEM Dashboard Refresh' CHANGELOG.md \
    || fail "CHANGELOG does not mention v0.17.0"

grep -q 'DeltaAegis v0.17.0' deltaaegis.py \
    || fail "CLI/script metadata does not mention v0.17.0"

grep -q 'DeltaAegis v0.16.0' deltaaegis.py \
    || fail "CLI/script metadata no longer preserves v0.16.0 compatibility text"

grep -q 'DeltaAegis Executive SIEM Dashboard' deltaaegis.py \
    || fail "Executive SIEM dashboard title is missing"

grep -q 'v0.17 Executive SIEM Dashboard Refresh' deltaaegis.py \
    || fail "v0.17 executive dashboard CSS marker is missing"

grep -q 'v0.17 SIEM-style executive chart panels' deltaaegis.py \
    || fail "v0.17 SIEM chart marker is missing"

grep -q 'v0.17 SIEM-style ticket queue' deltaaegis.py \
    || fail "v0.17 ticket queue marker is missing"

grep -q 'v0.17 ticket signal tuning' deltaaegis.py \
    || fail "v0.17 ticket signal tuning marker is missing"

grep -q 'v0.17 ticket signal state labels' deltaaegis.py \
    || fail "v0.17 ticket signal badge marker is missing"

for validator in \
    tools/validate_v0_17_dashboard_shell_theme.sh \
    tools/validate_v0_17_siem_charts.sh \
    tools/validate_v0_17_ticket_queue_layout.sh \
    tools/validate_v0_17_ticket_signal_tuning.sh \
    tools/validate_v0_17_ticket_signal_badges.sh \
    tools/validate_v0_16_release.sh \
    tools/validate_v0_15_release.sh \
    tools/validate_v0_14_release.sh \
    tools/validate_v0_13_release.sh \
    tools/validate_v0_12_release.sh
do
    [ -x "$validator" ] || fail "Missing or non-executable validator: $validator"
done

./tools/validate_readme_current.sh
./tools/validate_v0_17_dashboard_shell_theme.sh
./tools/validate_v0_17_siem_charts.sh
./tools/validate_v0_17_ticket_queue_layout.sh
./tools/validate_v0_17_ticket_signal_tuning.sh
./tools/validate_v0_17_ticket_signal_badges.sh
./tools/validate_v0_16_release.sh "$BUNDLE_DIR"
./tools/validate_v0_15_release.sh "$BUNDLE_DIR"
./tools/validate_v0_14_release.sh "$BUNDLE_DIR"
./tools/validate_v0_13_release.sh "$BUNDLE_DIR"
./tools/validate_v0_12_release.sh

pytest -q

pass "DeltaAegis v0.17 release validation passed"
