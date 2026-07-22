#!/usr/bin/env python3
"""Collect bounded v1 Stage 5 soak evidence without changing Git state."""

from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import deltaaegis  # noqa: E402
from deltaaegis_core import operations  # noqa: E402


STOP_REQUESTED = False


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def request_stop(_signum, _frame) -> None:
    global STOP_REQUESTED
    STOP_REQUESTED = True


def sample(database: Path) -> dict[str, object]:
    started = time.perf_counter()
    connection = deltaaegis.connect(database)
    try:
        readiness = operations.readiness_report(
            connection,
            database_path=database,
        )
        integrity = str(connection.execute("PRAGMA quick_check").fetchone()[0])
        foreign_key_failures = len(
            connection.execute("PRAGMA foreign_key_check").fetchall()
        )
        failed_workers = int(
            connection.execute(
                "SELECT COUNT(*) FROM scan_jobs WHERE status='FAILED'"
            ).fetchone()[0]
        )
    finally:
        connection.close()
    return {
        "sampled_at": utc_now(),
        "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
        "readiness": readiness["status"],
        "blocking_failure_count": readiness["blocking_failure_count"],
        "integrity": integrity,
        "foreign_key_failures": foreign_key_failures,
        "failed_scan_jobs_total": failed_workers,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--duration-hours", type=float, default=24.0)
    parser.add_argument("--interval-seconds", type=float, default=60.0)
    parser.add_argument(
        "--release-evidence",
        action="store_true",
        help="Require the approved 24-hour minimum and 60-second-or-faster sampling.",
    )
    args = parser.parse_args()
    if args.duration_hours <= 0 or args.duration_hours > 168:
        parser.error("--duration-hours must be greater than 0 and at most 168")
    if args.interval_seconds <= 0 or args.interval_seconds > 3600:
        parser.error("--interval-seconds must be greater than 0 and at most 3600")
    minimum = float(operations.PERFORMANCE_TARGETS["soak"]["minimum_hours"])
    if args.release_evidence and args.duration_hours < minimum:
        parser.error(f"release evidence requires at least {minimum:g} hours")
    if args.release_evidence and args.interval_seconds > float(
        operations.PERFORMANCE_TARGETS["soak"]["sample_interval_seconds"]
    ):
        parser.error("release evidence sampling interval exceeds the approved maximum")

    database = args.db.expanduser().resolve()
    if not database.is_file():
        parser.error(f"database does not exist: {database}")
    output = args.output.expanduser().resolve(strict=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    started_at = utc_now()
    started = time.monotonic()
    deadline = started + args.duration_hours * 3600.0
    samples: list[dict[str, object]] = []
    initial_failed_jobs: int | None = None

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    while not STOP_REQUESTED and time.monotonic() < deadline:
        item = sample(database)
        if initial_failed_jobs is None:
            initial_failed_jobs = int(item["failed_scan_jobs_total"])
        item["unplanned_worker_failures"] = max(
            0,
            int(item["failed_scan_jobs_total"]) - initial_failed_jobs,
        )
        samples.append(item)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(args.interval_seconds, remaining))

    elapsed_hours = (time.monotonic() - started) / 3600.0
    integrity_failures = sum(
        1
        for item in samples
        if item["integrity"] != "ok" or int(item["foreign_key_failures"]) != 0
    )
    readiness_failures = sum(
        1 for item in samples if item["readiness"] != "READY"
    )
    worker_failures = max(
        (int(item["unplanned_worker_failures"]) for item in samples),
        default=0,
    )
    completed_duration = elapsed_hours >= args.duration_hours * 0.999
    release_eligible = (
        args.release_evidence
        and elapsed_hours >= minimum
        and integrity_failures == 0
        and readiness_failures == 0
        and worker_failures == 0
        and not STOP_REQUESTED
    )
    receipt = {
        "schema_version": "deltaaegis-v1-soak-evidence-v1",
        "started_at": started_at,
        "completed_at": utc_now(),
        "database_filename": database.name,
        "requested_hours": args.duration_hours,
        "elapsed_hours": round(elapsed_hours, 6),
        "interval_seconds": args.interval_seconds,
        "sample_count": len(samples),
        "interrupted": STOP_REQUESTED,
        "completed_requested_duration": completed_duration,
        "release_evidence_requested": args.release_evidence,
        "release_eligible": release_eligible,
        "summary": {
            "integrity_failures": integrity_failures,
            "readiness_failures": readiness_failures,
            "unplanned_worker_failures": worker_failures,
        },
        "samples": samples,
    }
    output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
    if not completed_duration or integrity_failures or readiness_failures or worker_failures:
        return 1
    if args.release_evidence and not release_eligible:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
