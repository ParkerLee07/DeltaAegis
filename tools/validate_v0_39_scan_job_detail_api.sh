#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

printf '%s\n' \
  "DeltaAegis v0.39 Scan Job Detail API Validator" \
  "================================================"

python3 -m py_compile deltaaegis.py

python3 - <<'PY'
from __future__ import annotations

from pathlib import Path
import inspect
import tempfile

import deltaaegis


source = Path("deltaaegis.py").read_text(encoding="utf-8")

required_source = (
    '("GET", "/api/netsniper/job-detail", "dashboard.read")',
    'if route == "/api/netsniper/job-detail":',
    'query.get("job_id", [""])[0]',
    "dashboard_scan_job_detail_payload(",
    "logs_root=DEFAULT_SCAN_LOGS",
)

for fragment in required_source:
    assert fragment in source, f"missing API requirement: {fragment}"

route_start = source.index(
    '            if route == "/api/netsniper/job-detail":'
)
route_end = source.index(
    '            if route == "/api/netsniper/status":',
    route_start,
)
route_source = source[route_start:route_end]

for forbidden in (
    'query.get("path"',
    'query.get("file"',
    'query.get("log_path"',
    "Path(query",
    "open(query",
):
    assert forbidden not in route_source, (
        f"caller-controlled path handling found: {forbidden}"
    )

helper_signature = inspect.signature(
    deltaaegis.dashboard_scan_job_detail_payload
)

assert "job_id" in helper_signature.parameters
assert "tail_bytes" in helper_signature.parameters
assert "logs_root" in helper_signature.parameters
assert "path" not in helper_signature.parameters
assert "filename" not in helper_signature.parameters

assert (
    deltaaegis.normalize_scan_job_log_tail_bytes(1)
    == deltaaegis.SCAN_JOB_LOG_TAIL_MINIMUM_BYTES
)
assert (
    deltaaegis.normalize_scan_job_log_tail_bytes(999999)
    == deltaaegis.SCAN_JOB_LOG_TAIL_MAXIMUM_BYTES
)
assert (
    deltaaegis.normalize_scan_job_log_tail_bytes("invalid")
    == deltaaegis.SCAN_JOB_LOG_TAIL_DEFAULT_BYTES
)


with tempfile.TemporaryDirectory(
    prefix="deltaaegis-v039-job-detail-"
) as temp_dir:
    temp = Path(temp_dir)
    db_path = temp / "deltaaegis.db"
    logs_root = temp / "scan-logs"
    outside_root = temp / "outside"

    logs_root.mkdir()
    outside_root.mkdir()

    connection = deltaaegis.connect(db_path)

    job = deltaaegis.create_scan_job(
        connection,
        "192.168.70.0/24",
        temp / "fake-netsniper.sh",
        temp / "runs",
        scan_profile="balanced",
    )
    connection.commit()

    job_id = job["job_id"]
    stdout_log = logs_root / f"{job_id}.stdout.log"
    stderr_log = logs_root / f"{job_id}.stderr.log"

    stdout_log.write_text(
        ("old-output\n" * 300)
        + "visible-stdout-tail\n",
        encoding="utf-8",
    )
    stderr_log.write_text(
        "visible-stderr-tail\n",
        encoding="utf-8",
    )

    deltaaegis.update_scan_job(
        connection,
        job_id,
        status="RUNNING",
        started_at="2026-07-06T17:00:00+00:00",
        heartbeat_at="2026-07-06T17:00:05+00:00",
        process_pid=54321,
        stdout_log=str(stdout_log),
        stderr_log=str(stderr_log),
        message="NetSniper scan running profile=balanced",
    )
    connection.commit()

    detail = deltaaegis.dashboard_scan_job_detail_payload(
        connection,
        job_id,
        tail_bytes=1024,
        logs_root=logs_root,
    )

    assert detail["ok"] is True
    assert detail["found"] is True
    assert detail["job_id"] == job_id
    assert detail["tail_bytes"] == 1024

    returned_job = detail["job"]

    assert returned_job["status"] == "RUNNING"
    assert returned_job["process_pid"] == 54321
    assert (
        returned_job["heartbeat_at"]
        == "2026-07-06T17:00:05+00:00"
    )

    assert detail["stdout"]["available"] is True
    assert detail["stdout"]["truncated"] is True
    assert detail["stdout"]["bytes_read"] <= 1024
    assert "visible-stdout-tail" in detail["stdout"]["text"]

    assert detail["stderr"]["available"] is True
    assert detail["stderr"]["truncated"] is False
    assert "visible-stderr-tail" in detail["stderr"]["text"]

    outside_file = outside_root / f"{job_id}.stderr.log"
    outside_file.write_text(
        "must-not-be-returned\n",
        encoding="utf-8",
    )

    deltaaegis.update_scan_job(
        connection,
        job_id,
        stderr_log=str(outside_file),
    )
    connection.commit()

    confined = deltaaegis.dashboard_scan_job_detail_payload(
        connection,
        job_id,
        tail_bytes=1024,
        logs_root=logs_root,
    )

    assert confined["stderr"]["available"] is False
    assert confined["stderr"]["text"] == ""
    assert (
        confined["stderr"]["reason"]
        == "log_path_outside_allowed_root"
    )
    assert "must-not-be-returned" not in str(confined)

    wrong_name = logs_root / "unrelated.log"
    wrong_name.write_text(
        "wrong-file\n",
        encoding="utf-8",
    )

    deltaaegis.update_scan_job(
        connection,
        job_id,
        stderr_log=str(wrong_name),
    )
    connection.commit()

    filename_guard = (
        deltaaegis.dashboard_scan_job_detail_payload(
            connection,
            job_id,
            tail_bytes=1024,
            logs_root=logs_root,
        )
    )

    assert filename_guard["stderr"]["available"] is False
    assert (
        filename_guard["stderr"]["reason"]
        == "unexpected_log_filename"
    )

    missing = deltaaegis.dashboard_scan_job_detail_payload(
        connection,
        "scan-missing-job",
        logs_root=logs_root,
    )

    assert missing["ok"] is False
    assert missing["found"] is False
    assert missing["error"] == "scan job not found"

    invalid = deltaaegis.dashboard_scan_job_detail_payload(
        connection,
        "../../etc/passwd",
        logs_root=logs_root,
    )

    assert invalid["ok"] is False
    assert invalid["found"] is False
    assert invalid["error"] == "invalid scan job id"

    connection.close()

print("PASS: dashboard.read RBAC policy")
print("PASS: fixed read-only job-detail route")
print("PASS: PID and heartbeat detail exposure")
print("PASS: bounded stdout log tail")
print("PASS: bounded stderr log tail")
print("PASS: log-root confinement")
print("PASS: expected filename enforcement")
print("PASS: invalid and missing job handling")
print("PASS: no caller-controlled filesystem path")
PY

git diff --check

printf '%s\n' \
  "PASS: DeltaAegis v0.39 scan job detail API validator"
