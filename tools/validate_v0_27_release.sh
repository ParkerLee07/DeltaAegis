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

python3 -m py_compile deltaaegis.py || fail "deltaaegis.py does not compile"

./tools/validate_v0_27_install_first_admin_bootstrap.sh \
    || fail "v0.27 install first-admin bootstrap gate failed"

./tools/validate_v0_27_first_admin_setup.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.27 first-admin setup gate failed"

./tools/validate_v0_27_rbac_policy_matrix.sh "$NETSNIPER_RUN_DIR" \
    || fail "v0.27 RBAC policy matrix gate failed"

# Only scan runtime/installer files for public default credentials.
# Validator files may mention forbidden strings as test fixtures.
SCAN_FILES=(
    "deltaaegis.py"
    "install.sh"
    "tools/bootstrap_first_admin.py"
    "tools/reset_dashboard_admin.py"
)

: > /tmp/deltaaegis-v027-default-password-grep.txt

for file in "${SCAN_FILES[@]}"; do
    if [[ -f "$file" ]]; then
        grep -n 'admin123' "$file" >> /tmp/deltaaegis-v027-default-password-grep.txt || true
    fi
done

if [[ -s /tmp/deltaaegis-v027-default-password-grep.txt ]]; then
    cat /tmp/deltaaegis-v027-default-password-grep.txt
    fail "public default password must not be committed in runtime/installer files"
fi

pass "DeltaAegis v0.27 release validation passed"
