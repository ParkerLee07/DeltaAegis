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

python3 deltaaegis.py --help | grep -q 'v0.24.0' \
    || fail "CLI help does not advertise v0.24.0"

grep -q 'DeltaAegis v0.24.0' deltaaegis.py \
    || fail "deltaaegis.py does not advertise v0.24.0"

grep -q 'DeltaAegis v0.24.0 — Dashboard Session Login' README.md \
    || fail "README does not document v0.24.0 Dashboard Session Login"

head -40 CHANGELOG.md | grep -q 'DeltaAegis v0.24.0 — Dashboard Session Login' \
    || fail "CHANGELOG does not start with v0.24.0 Dashboard Session Login"

for validator in \
    tools/validate_v0_24_session_model.sh \
    tools/validate_v0_24_login_logout_routes.sh \
    tools/validate_v0_24_api_session.sh \
    tools/validate_v0_24_backward_compatibility.sh \
    tools/validate_v0_24_release_metadata.sh \
    tools/validate_v0_24_release.sh
do
    test -x "$validator" || fail "missing executable validator: $validator"
done

grep -q 'validate_v0_24_backward_compatibility.sh' tools/validate_v0_24_release.sh \
    || fail "v0.24 release gate does not include backward compatibility validation"

if grep -q 'validate_v0_23_release.sh' tools/validate_v0_24_release.sh; then
    fail "v0.24 release gate must not call v0.23 release metadata validator"
fi

pass "DeltaAegis v0.24 release metadata validation passed"
