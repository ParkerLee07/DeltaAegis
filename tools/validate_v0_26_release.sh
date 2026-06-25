#!/usr/bin/env bash
set -euo pipefail

NETSNIPER_RUN_DIR="${1:-/home/parker/NetSniper/runs/20260623-123007}"

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

pass() {
    echo "[PASS] $1"
}

cd "$(dirname "$0")/.." || exit 1

[[ -d "$NETSNIPER_RUN_DIR" ]] || fail "NetSniper run directory missing: $NETSNIPER_RUN_DIR"

python3 -m py_compile deltaaegis.py \
    || fail "deltaaegis.py does not compile"

python3 deltaaegis.py --help | grep -Fq 'DeltaAegis v0.26.0' \
    || fail "deltaaegis.py help missing v0.26.0 CLI release description"

python3 deltaaegis.py --help | grep -Fq 'Dashboard User Management' \
    || fail "deltaaegis.py help missing Dashboard User Management CLI release description"

grep -Fq '## Current Release — v0.26.0' README.md \
    || fail "README missing v0.26.0 current release header"

grep -Fq 'DeltaAegis v0.26.0 — Dashboard User Management' README.md \
    || fail "README missing v0.26.0 release summary"

grep -Fq 'ACCESS_USER_DASHBOARD_*' README.md \
    || fail "README missing user-management audit event summary"

if grep -Fq '## Current Release — v0.25.0' README.md; then
    fail "README still advertises v0.25.0 as current release"
fi

for stale in \
    'RELEASE v0.19 filters' \
    'Release v0.19 filters' \
    'v0.19 filters'
do
    if grep -Fq "$stale" deltaaegis.py README.md; then
        fail "stale release/filter wording remains: $stale"
    fi
done

for validator in \
    tools/validate_v0_26_admin_users_api.sh \
    tools/validate_v0_26_operator_users_page.sh \
    tools/validate_v0_26_admin_user_actions.sh \
    tools/validate_v0_26_operator_user_action_controls.sh \
    tools/validate_v0_26_user_audit_visibility.sh \
    tools/validate_v0_26_operator_audit_navigation_polish.sh \
    tools/validate_v0_26_dashboard_ui_polish.sh
do
    [[ -x "$validator" ]] || fail "validator is missing or not executable: $validator"
done

./tools/validate_v0_26_admin_users_api.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.26 admin users API gate failed"

./tools/validate_v0_26_operator_users_page.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.26 operator users page gate failed"

./tools/validate_v0_26_admin_user_actions.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.26 admin user actions gate failed"

./tools/validate_v0_26_operator_user_action_controls.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.26 operator user action controls gate failed"

./tools/validate_v0_26_user_audit_visibility.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.26 user audit visibility gate failed"

./tools/validate_v0_26_operator_audit_navigation_polish.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.26 operator audit/navigation polish gate failed"

./tools/validate_v0_26_dashboard_ui_polish.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.26 dashboard UI polish gate failed"

for inherited_validator in \
    tools/validate_v0_25_operator_session_page.sh \
    tools/validate_v0_25_operator_session_actions.sh \
    tools/validate_v0_25_backward_compatibility_markers.sh
do
    if [[ -x "$inherited_validator" ]]; then
        "$inherited_validator" "$NETSNIPER_RUN_DIR" \
            || fail "inherited v0.25 compatibility gate failed: $inherited_validator"
    fi
done

pass "DeltaAegis v0.26 release validation passed"
