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

for needle in \
    'triage_bucket' \
    'triage_urgency' \
    'CHANGED_SINCE_REVIEW' \
    'NEEDS_REVIEW' \
    'access_users' \
    'access_api_tokens' \
    'access_audit_log' \
    'access_sessions' \
    'user-password' \
    'X-DeltaAegis-Token' \
    'route == "/login"' \
    'route == "/logout"' \
    'route == "/api/session"'
do
    grep -Fq -- "$needle" deltaaegis.py || fail "missing backward compatibility marker: $needle"
done

pass "DeltaAegis v0.25 backward compatibility marker validation passed"
