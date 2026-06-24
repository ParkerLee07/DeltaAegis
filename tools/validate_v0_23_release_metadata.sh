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

grep -q 'DeltaAegis v0.23.0' deltaaegis.py \
    || fail "deltaaegis.py does not advertise v0.23.0"

python3 deltaaegis.py --help | grep -q 'v0.23.0' \
    || fail "CLI help does not advertise v0.23.0"

grep -q 'DeltaAegis v0.23.0 — Enterprise Access Control' README.md \
    || fail "README current release does not advertise v0.23.0"

head -5 CHANGELOG.md | grep -q 'v0.23.0 — Enterprise Access Control' \
    || fail "CHANGELOG does not start with v0.23.0"

for validator in \
    ./tools/validate_v0_23_access_model.sh \
    ./tools/validate_v0_23_access_cli_tokens.sh \
    ./tools/validate_v0_23_dashboard_db_token_auth.sh \
    ./tools/validate_v0_23_access_audit_visibility.sh \
    ./tools/validate_v0_23_backward_compatibility.sh
do
    grep -q 'PASS' "$validator" || fail "validator appears incomplete: $validator"
done

grep -q 'validate_v0_23_backward_compatibility.sh' tools/validate_v0_23_release.sh \
    || fail "v0.23 release gate does not include metadata-safe backward compatibility"

if grep -q 'validate_v0_22_release.sh' tools/validate_v0_23_release.sh; then
    fail "v0.23 release gate must not call v0.22 release metadata gate"
fi

pass "DeltaAegis v0.23 release metadata validation passed"
