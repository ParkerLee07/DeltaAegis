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

grep -Fq 'Current Release — v0.29.0' README.md \
    || fail "README does not advertise v0.29.0 as current release"

grep -Fq 'DeltaAegis v0.29.0 — Guarded NetSniper Scan Jobs' README.md \
    || fail "README missing v0.29.0 release title"

grep -Fq 'POST /api/netsniper/scan-start' README.md \
    || fail "README missing scan-start API documentation"

grep -Fq 'ADMIN-only' README.md \
    || fail "README missing ADMIN-only scan boundary"

grep -Fq 'private IPv4 CIDR' README.md \
    || fail "README missing private CIDR scan boundary"

grep -Fq 'No raw shell command input' README.md \
    || fail "README missing no-raw-shell scan boundary"

grep -Fq '"scan.start": "ADMIN"' deltaaegis.py \
    || fail "deltaaegis.py missing ADMIN scan.start permission"

grep -Fq 'id="netsniper-scan-start-form"' deltaaegis.py \
    || fail "deltaaegis.py missing NetSniper scan-start form"

grep -Fq 'def dashboard_netsniper_scan_worker' deltaaegis.py \
    || fail "deltaaegis.py missing dashboard NetSniper scan worker"

grep -Fq 'fetch("/api/netsniper/scan-start"' deltaaegis.py \
    || fail "deltaaegis.py missing dashboard scan-start POST"

if grep -nE 'shell=True' deltaaegis.py; then
    fail "unsafe subprocess shell=True pattern found"
fi

pass "DeltaAegis v0.29 release metadata validation passed"
