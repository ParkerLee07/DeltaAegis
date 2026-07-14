#!/usr/bin/env python3
"""Durable scan, schedule, cancellation, and watchdog policy for DeltaAegis v0.44."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from deltaaegis_core.auth import DeltaAegisError


SCAN_JOB_STATUSES = {"QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"}
TRUEAEGIS_JOB_STATUSES = {"QUEUED", "RUNNING", "COMPLETED", "FAILED"}
ALLOWED_NETSNIPER_SCAN_PROFILES = {"quick", "balanced", "accurate"}
RFC1918_IPV4_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
SCAN_JOB_CANCEL_ACTOR_MAX_LENGTH = 96
SCAN_JOB_CANCEL_REASON_MAX_LENGTH = 500
SCAN_JOB_LOG_TAIL_DEFAULT_BYTES = 16 * 1024
SCAN_JOB_LOG_TAIL_MINIMUM_BYTES = 1024
SCAN_JOB_LOG_TAIL_MAXIMUM_BYTES = 64 * 1024
ALLOWED_SCAN_SCHEDULE_CADENCE_MINUTES = {60, 120, 360, 720, 1440}
SCAN_SCHEDULE_DELETE_CONFIRMATION_PREFIX = "DELETE SCHEDULE "
STALE_SCAN_JOB_MINIMUM_MINUTES = 60
STALE_SCAN_JOB_DEFAULT_MINUTES = 360
STALE_SCAN_JOB_MAXIMUM_MINUTES = 10080
SCAN_JOB_WATCHDOG_SCHEMA_VERSION = "deltaaegis-scan-watchdog-v1"
SCAN_JOB_WATCHDOG_STALE_MINUTES = 10
SCAN_JOB_WATCHDOG_PROC_ROOT = Path("/proc")


@dataclass(frozen=True)
class JobContext:
    active_scan_job_exists_error_type: type[Exception]
    create_scan_job: Callable[..., dict[str, Any]]


def utc_now_text() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def validate_private_cidr(target: str) -> str:
    raw = (target or "").strip()

    if not raw:
        raise DeltaAegisError("target CIDR is required")

    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError as exc:
        raise DeltaAegisError(f"invalid target CIDR: {raw}") from exc

    if network.version != 4:
        raise DeltaAegisError("only IPv4 CIDR targets are supported")

    if not any(network.subnet_of(allowed) for allowed in RFC1918_IPV4_NETWORKS):
        raise DeltaAegisError(
            "target must be a private IPv4 CIDR contained within RFC1918 "
            "space (10/8, 172.16/12, or 192.168/16)"
        )

    return str(network)


def validate_netsniper_scan_profile(profile: str | None) -> str:
    value = str(profile or "balanced").strip().lower()

    if not value:
        value = "balanced"

    if value == "deep":
        raise DeltaAegisError("NetSniper scan profile 'deep' is planned but not runtime-enabled. Use quick, balanced, or accurate.")

    if value not in ALLOWED_NETSNIPER_SCAN_PROFILES:
        allowed = ", ".join(sorted(ALLOWED_NETSNIPER_SCAN_PROFILES))
        raise DeltaAegisError(f"invalid NetSniper scan profile: {profile!r}; allowed profiles: {allowed}")

    return value


def create_scan_job(
    connection: sqlite3.Connection,
    target: str,
    netsniper_path: Path,
    runs_dir: Path,
    auto_ingest: bool = False,
    scan_profile: str = "balanced",
    schedule_id: str | None = None,
) -> dict[str, Any]:
    safe_target = validate_private_cidr(target)
    safe_profile = validate_netsniper_scan_profile(scan_profile)
    safe_schedule_id = str(schedule_id or "").strip()

    if len(safe_schedule_id) > 96:
        raise DeltaAegisError("scan schedule id is too long")

    now = utc_now_text()
    job_id = f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"

    connection.execute(
        """
        INSERT INTO scan_jobs (
            job_id,
            target,
            network_scope,
            schedule_id,
            status,
            created_at,
            updated_at,
            netsniper_path,
            runs_dir,
            scan_profile,
            auto_ingest,
            status_json,
            message
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            job_id,
            safe_target,
            safe_target,
            safe_schedule_id,
            "QUEUED",
            now,
            now,
            str(netsniper_path),
            str(runs_dir),
            safe_profile,
            1 if auto_ingest else 0,
            "{}",
            "scan job queued",
        ),
    )

    return {
        "job_id": job_id,
        "target": safe_target,
        "network_scope": safe_target,
        "schedule_id": safe_schedule_id,
        "status": "QUEUED",
        "created_at": now,
        "updated_at": now,
        "heartbeat_at": None,
        "cancel_requested_at": None,
        "cancel_requested_by": "",
        "cancel_reason": "",
        "cancelled_at": None,
        "process_pid": None,
        "netsniper_path": str(netsniper_path),
        "runs_dir": str(runs_dir),
        "scan_profile": safe_profile,
        "auto_ingest": auto_ingest,
        "status_json": {},
        "message": "scan job queued",
    }


def update_scan_job(
    connection: sqlite3.Connection,
    job_id: str,
    **fields: Any,
) -> None:
    allowed = {
        "status",
        "started_at",
        "heartbeat_at",
        "cancel_requested_at",
        "cancel_requested_by",
        "cancel_reason",
        "cancelled_at",
        "finished_at",
        "process_pid",
        "bundle_path",
        "exit_code",
        "stdout_log",
        "stderr_log",
        "status_json",
        "message",
    }

    updates = []
    params: list[Any] = []

    for key, value in fields.items():
        if key not in allowed:
            raise DeltaAegisError(f"invalid scan job field update: {key}")

        if key == "status":
            value = str(value).upper()

            if value not in SCAN_JOB_STATUSES:
                raise DeltaAegisError(f"invalid scan job status: {value}")

        if key == "status_json":
            value = json.dumps(value or {}, sort_keys=True)

        updates.append(f"{key} = ?")
        params.append(value)

    updates.append("updated_at = ?")
    params.append(utc_now_text())
    params.append(job_id)

    connection.execute(
        f"""
        UPDATE scan_jobs
        SET {", ".join(updates)}
        WHERE job_id = ?
        """,
        tuple(params),
    )


def normalize_scan_job_cancel_actor(value: Any = None) -> str:
    actor = str(value or "operator").strip() or "operator"
    if len(actor) > SCAN_JOB_CANCEL_ACTOR_MAX_LENGTH:
        raise DeltaAegisError(
            f"scan cancellation requester exceeds "
            f"{SCAN_JOB_CANCEL_ACTOR_MAX_LENGTH} characters"
        )
    return actor


def normalize_scan_job_cancel_reason(value: Any = None) -> str:
    reason = (
        str(value or "operator requested cancellation").strip()
        or "operator requested cancellation"
    )
    if len(reason) > SCAN_JOB_CANCEL_REASON_MAX_LENGTH:
        raise DeltaAegisError(
            f"scan cancellation reason exceeds "
            f"{SCAN_JOB_CANCEL_REASON_MAX_LENGTH} characters"
        )
    return reason


def scan_job_row(
    connection: sqlite3.Connection,
    job_id: str,
) -> sqlite3.Row | None:
    return connection.execute(
        "SELECT * FROM scan_jobs WHERE job_id = ?",
        (str(job_id or "").strip(),),
    ).fetchone()


def scan_job_cancellation_request(
    connection: sqlite3.Connection,
    job_id: str,
) -> dict[str, Any]:
    row = scan_job_row(connection, job_id)
    if row is None:
        return {"found": False, "requested": False, "job": None}

    job = scan_job_to_dict(row)
    return {
        "found": True,
        "requested": bool(job.get("cancel_requested_at")),
        "requested_at": job.get("cancel_requested_at"),
        "requested_by": job.get("cancel_requested_by") or "",
        "reason": job.get("cancel_reason") or "",
        "job": job,
    }


def request_scan_job_cancellation(
    connection: sqlite3.Connection,
    job_id: Any,
    requested_by: Any = None,
    reason: Any = None,
) -> dict[str, Any]:
    safe_job_id = str(job_id or "").strip()

    if (
        not safe_job_id
        or len(safe_job_id) > 160
        or re.fullmatch(r"[A-Za-z0-9._:-]+", safe_job_id) is None
    ):
        raise DeltaAegisError("invalid scan job id")

    actor = normalize_scan_job_cancel_actor(requested_by)
    cancel_reason = normalize_scan_job_cancel_reason(reason)
    row = scan_job_row(connection, safe_job_id)

    if row is None:
        raise DeltaAegisError(f"scan job not found: {safe_job_id}")

    job = scan_job_to_dict(row)
    status = str(job.get("status") or "").upper()

    if status == "CANCELLED":
        job["cancellation_action"] = "already_cancelled"
        return job

    if status in {"COMPLETED", "FAILED"}:
        raise DeltaAegisError(
            f"cannot cancel terminal scan job {safe_job_id} with status {status}"
        )

    if job.get("cancel_requested_at"):
        job["cancellation_action"] = "already_requested"
        return job

    now = utc_now_text()
    status_json = dict(job.get("status_json") or {})
    status_json["cancellation"] = {
        "requested_at": now,
        "requested_by": actor,
        "reason": cancel_reason,
        "state": "CANCELLED_BEFORE_START" if status == "QUEUED" else "REQUESTED",
    }

    fields: dict[str, Any] = {
        "cancel_requested_at": now,
        "cancel_requested_by": actor,
        "cancel_reason": cancel_reason,
        "status_json": status_json,
        "message": f"scan cancellation requested by {actor}: {cancel_reason}",
    }

    if status == "QUEUED":
        fields.update(
            {
                "status": "CANCELLED",
                "cancelled_at": now,
                "finished_at": now,
                "heartbeat_at": now,
                "exit_code": 130,
                "message": (
                    f"scan cancelled before process launch by "
                    f"{actor}: {cancel_reason}"
                ),
            }
        )

    update_scan_job(connection, safe_job_id, **fields)
    updated_row = scan_job_row(connection, safe_job_id)

    if updated_row is None:
        raise DeltaAegisError(f"scan job disappeared unexpectedly: {safe_job_id}")

    result = scan_job_to_dict(updated_row)
    result["cancellation_action"] = (
        "cancelled_before_start" if status == "QUEUED" else "requested"
    )
    return result


def decode_json_field(value: str | None, default):
    if not value:
        return default

    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def scan_job_to_dict(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(row)

    item["auto_ingest"] = bool(item.get("auto_ingest"))
    item["scan_profile"] = item.get("scan_profile") or "balanced"
    item["schedule_id"] = item.get("schedule_id") or ""

    process_pid = item.get("process_pid")
    if process_pid in ("", None):
        item["process_pid"] = None
    else:
        try:
            item["process_pid"] = int(process_pid)
        except (TypeError, ValueError):
            item["process_pid"] = None

    item["heartbeat_at"] = item.get("heartbeat_at") or None
    item["cancel_requested_at"] = item.get("cancel_requested_at") or None
    item["cancel_requested_by"] = item.get("cancel_requested_by") or ""
    item["cancel_reason"] = item.get("cancel_reason") or ""
    item["cancelled_at"] = item.get("cancelled_at") or None
    item["status_json"] = decode_json_field(item.get("status_json"), {})

    return item


def query_scan_jobs(
    connection: sqlite3.Connection,
    limit: int = 20,
    status: str | None = None,
    scope: str | None = None,
) -> list[sqlite3.Row]:
    clauses = []
    params: list[Any] = []

    if status:
        normalized_status = status.strip().upper()

        if normalized_status not in SCAN_JOB_STATUSES:
            raise DeltaAegisError(f"invalid scan job status: {status}")

        clauses.append("status = ?")
        params.append(normalized_status)

    if scope:
        clauses.append("network_scope = ?")
        params.append(scope)

    where = " WHERE " + " AND ".join(clauses) if clauses else ""

    params.append(limit)

    return connection.execute(
        f"""
        SELECT
            job_id,
            target,
            network_scope,
            schedule_id,
            status,
            created_at,
            updated_at,
            started_at,
            heartbeat_at,
            cancel_requested_at,
            cancel_requested_by,
            cancel_reason,
            cancelled_at,
            finished_at,
            process_pid,
            netsniper_path,
            runs_dir,
            scan_profile,
            bundle_path,
            exit_code,
            auto_ingest,
            stdout_log,
            stderr_log,
            status_json,
            message
        FROM scan_jobs
        {where}
        ORDER BY created_at DESC, updated_at DESC
        LIMIT ?
        """,
        tuple(params),
    ).fetchall()


def normalize_scan_job_log_tail_bytes(value: Any = None) -> int:
    try:
        requested = int(value or SCAN_JOB_LOG_TAIL_DEFAULT_BYTES)
    except (TypeError, ValueError):
        requested = SCAN_JOB_LOG_TAIL_DEFAULT_BYTES

    return max(
        SCAN_JOB_LOG_TAIL_MINIMUM_BYTES,
        min(SCAN_JOB_LOG_TAIL_MAXIMUM_BYTES, requested),
    )


def scan_job_log_tail_payload(
    path_value: Any,
    job_id: str,
    stream: str,
    logs_root: Path,
    max_bytes: Any = None,
) -> dict[str, Any]:
    safe_stream = str(stream or "").strip().lower()

    if safe_stream not in {"stdout", "stderr"}:
        raise DeltaAegisError(
            f"unsupported scan job log stream: {stream!r}"
        )

    limit = normalize_scan_job_log_tail_bytes(max_bytes)
    payload = {
        "stream": safe_stream,
        "available": False,
        "text": "",
        "truncated": False,
        "file_size": 0,
        "bytes_read": 0,
        "tail_bytes_limit": limit,
        "updated_at": None,
        "reason": None,
    }

    if not path_value:
        payload["reason"] = "log_path_not_recorded"
        return payload

    root = Path(logs_root).expanduser().resolve()
    candidate = Path(str(path_value)).expanduser().resolve()
    expected_name = f"{job_id}.{safe_stream}.log"

    try:
        candidate.relative_to(root)
    except ValueError:
        payload["reason"] = "log_path_outside_allowed_root"
        return payload

    if candidate.name != expected_name:
        payload["reason"] = "unexpected_log_filename"
        return payload

    if not candidate.is_file():
        payload["reason"] = "log_file_not_found"
        return payload

    try:
        stat = candidate.stat()
        file_size = int(stat.st_size)
        start = max(0, file_size - limit)

        with candidate.open("rb") as handle:
            handle.seek(start)
            content = handle.read(limit)

        payload.update(
            {
                "available": True,
                "text": content.decode(
                    "utf-8",
                    errors="replace",
                ),
                "truncated": start > 0,
                "file_size": file_size,
                "bytes_read": len(content),
                "updated_at": datetime.fromtimestamp(
                    stat.st_mtime,
                    timezone.utc,
                ).isoformat(timespec="seconds"),
            }
        )
    except OSError as exc:
        payload["reason"] = f"log_read_failed:{exc.__class__.__name__}"

    return payload


def trueaegis_job_to_dict(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(row)

    for key in ("imported_observations", "correlation_count"):
        try:
            item[key] = int(item.get(key) or 0)
        except (TypeError, ValueError):
            item[key] = 0

    if item.get("exit_code") in ("", None):
        item["exit_code"] = None
    else:
        try:
            item["exit_code"] = int(item.get("exit_code"))
        except (TypeError, ValueError):
            item["exit_code"] = None

    item["scan_job_id"] = str(item.get("scan_job_id") or "")
    item["schedule_id"] = str(item.get("schedule_id") or "")
    item["trigger_source"] = str(item.get("trigger_source") or "manual_dashboard")

    return item


def create_trueaegis_job(
    connection: sqlite3.Connection,
    scan_id: str | None,
    network_scope: str | None,
    manifest_path: Path,
    trueaegis_path: Path,
    scan_job_id: str | None = None,
    schedule_id: str | None = None,
    trigger_source: str = "manual_dashboard",
) -> dict[str, Any]:
    safe_manifest_path = Path(manifest_path).expanduser()
    safe_trueaegis_path = Path(trueaegis_path).expanduser()
    safe_scan_job_id = str(scan_job_id or "").strip()
    safe_schedule_id = str(schedule_id or "").strip()
    safe_trigger_source = str(trigger_source or "manual_dashboard").strip().lower()

    if safe_trigger_source not in {"manual_dashboard", "scheduled_followup"}:
        raise DeltaAegisError(f"invalid TrueAegis trigger source: {trigger_source}")

    now = utc_now_text()
    job_id = f"trueaegis-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"

    connection.execute(
        """
        INSERT INTO trueaegis_jobs (
            job_id,
            status,
            scan_id,
            scan_job_id,
            schedule_id,
            trigger_source,
            network_scope,
            manifest_path,
            trueaegis_path,
            message,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            job_id,
            "QUEUED",
            str(scan_id or ""),
            safe_scan_job_id,
            safe_schedule_id,
            safe_trigger_source,
            str(network_scope or ""),
            str(safe_manifest_path),
            str(safe_trueaegis_path),
            "TrueAegis validation job queued",
            now,
            now,
        ),
    )

    row = connection.execute(
        "SELECT * FROM trueaegis_jobs WHERE job_id = ?",
        (job_id,),
    ).fetchone()

    if row is None:
        raise DeltaAegisError(f"TrueAegis job was not created: {job_id}")

    return trueaegis_job_to_dict(row)


def update_trueaegis_job(
    connection: sqlite3.Connection,
    job_id: str,
    **fields: Any,
) -> None:
    allowed = {
        "status",
        "started_at",
        "completed_at",
        "validation_results_path",
        "validation_run_id",
        "imported_observations",
        "correlation_count",
        "stdout_log_path",
        "stderr_log_path",
        "exit_code",
        "message",
    }

    updates = []
    params: list[Any] = []

    for key, value in fields.items():
        if key not in allowed:
            raise DeltaAegisError(f"invalid TrueAegis job field update: {key}")

        if key == "status":
            value = str(value).upper()

            if value not in TRUEAEGIS_JOB_STATUSES:
                raise DeltaAegisError(f"invalid TrueAegis job status: {value}")

        if key in {"imported_observations", "correlation_count"}:
            value = max(0, int(value or 0))

        updates.append(f"{key} = ?")
        params.append(value)

    if not updates:
        return

    updates.append("updated_at = ?")
    params.append(utc_now_text())
    params.append(job_id)

    connection.execute(
        f"""
        UPDATE trueaegis_jobs
        SET {", ".join(updates)}
        WHERE job_id = ?
        """,
        tuple(params),
    )


def query_trueaegis_jobs(
    connection: sqlite3.Connection,
    limit: int = 20,
    status: str | None = None,
    scope: str | None = None,
) -> list[sqlite3.Row]:
    clauses = []
    params: list[Any] = []

    if status:
        normalized_status = status.strip().upper()

        if normalized_status not in TRUEAEGIS_JOB_STATUSES:
            raise DeltaAegisError(f"invalid TrueAegis job status: {status}")

        clauses.append("status = ?")
        params.append(normalized_status)

    if scope:
        clauses.append("network_scope = ?")
        params.append(scope)

    where = " WHERE " + " AND ".join(clauses) if clauses else ""

    try:
        safe_limit = int(limit)
    except (TypeError, ValueError):
        safe_limit = 20

    safe_limit = max(1, min(safe_limit, 200))
    params.append(safe_limit)

    return connection.execute(
        f"""
        SELECT
            job_id,
            status,
            scan_id,
            scan_job_id,
            schedule_id,
            trigger_source,
            network_scope,
            manifest_path,
            trueaegis_path,
            validation_results_path,
            validation_run_id,
            imported_observations,
            correlation_count,
            stdout_log_path,
            stderr_log_path,
            exit_code,
            message,
            created_at,
            updated_at,
            started_at,
            completed_at
        FROM trueaegis_jobs
        {where}
        ORDER BY created_at DESC, updated_at DESC
        LIMIT ?
        """,
        tuple(params),
    ).fetchall()


def scan_schedule_history_row_to_dict(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(row)

    history_item = {
        "schedule_id": item.get("schedule_id") or "",
        "name": item.get("name") or "",
        "target": item.get("target") or "",
        "network_scope": item.get("network_scope") or "",
        "scan_profile": item.get("scan_profile") or "balanced",
        "cadence_minutes": int(item.get("cadence_minutes") or 0),
        "enabled": bool(item.get("enabled")),
        "auto_ingest": bool(item.get("auto_ingest")),
        "last_run_at": item.get("last_run_at"),
        "next_run_at": item.get("next_run_at"),
        "last_job_id": item.get("last_job_id") or "",
        "last_status": item.get("last_status") or "",
        "failure_count": int(item.get("failure_count") or 0),
        "skip_count": int(item.get("skip_count") or 0),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
        "message": item.get("schedule_message") or "",
        "deleted": bool(item.get("deleted")),
        "deleted_at": item.get("deleted_at"),
        "linked_job_count": int(item.get("linked_job_count") or 0),
        "linked_active_job_count": int(item.get("linked_active_job_count") or 0),
        "linked_job_status_counts": decode_json_field(
            item.get("linked_job_status_counts_json"),
            {},
        ),
        "job": None,
    }

    if item.get("job_id"):
        history_item["job"] = {
            "job_id": item.get("job_id") or "",
            "target": item.get("job_target") or "",
            "network_scope": item.get("job_network_scope") or "",
            "schedule_id": item.get("job_schedule_id") or "",
            "status": item.get("job_status") or "",
            "created_at": item.get("job_created_at"),
            "updated_at": item.get("job_updated_at"),
            "started_at": item.get("job_started_at"),
            "finished_at": item.get("job_finished_at"),
            "netsniper_path": item.get("netsniper_path") or "",
            "runs_dir": item.get("runs_dir") or "",
            "scan_profile": item.get("job_scan_profile") or "balanced",
            "bundle_path": item.get("bundle_path"),
            "exit_code": item.get("exit_code"),
            "auto_ingest": bool(item.get("job_auto_ingest")),
            "stdout_log": item.get("stdout_log"),
            "stderr_log": item.get("stderr_log"),
            "status_json": decode_json_field(item.get("status_json"), {}),
            "message": item.get("job_message") or "",
        }

    return history_item


def query_scan_schedule_history(
    connection: sqlite3.Connection,
    limit: int = 50,
    scope: str | None = None,
) -> list[sqlite3.Row]:
    safe_limit = max(1, min(int(limit or 50), 200))
    clauses = []
    params: list[Any] = []

    if scope:
        clauses.append("s.network_scope = ?")
        params.append(scope)

    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    params.append(safe_limit)

    return connection.execute(
        f"""
        WITH schedule_sources AS (
            SELECT
                schedule_id,
                name,
                target,
                network_scope,
                scan_profile,
                cadence_minutes,
                enabled,
                auto_ingest,
                run_trueaegis_after_ingest,
                last_run_at,
                next_run_at,
                last_job_id,
                last_status,
                failure_count,
                skip_count,
                created_at,
                updated_at,
                message,
                0 AS deleted,
                NULL AS deleted_at,
                0 AS linked_job_count,
                0 AS linked_active_job_count,
                '{{}}' AS linked_job_status_counts_json
            FROM scan_schedules

            UNION ALL

            SELECT
                d.schedule_id,
                d.name,
                d.target,
                d.network_scope,
                d.scan_profile,
                d.cadence_minutes,
                0 AS enabled,
                d.auto_ingest,
                d.run_trueaegis_after_ingest,
                d.last_run_at,
                NULL AS next_run_at,
                d.last_job_id,
                d.last_status,
                d.failure_count,
                d.skip_count,
                d.created_at,
                d.updated_at,
                d.message,
                1 AS deleted,
                d.deleted_at,
                d.linked_job_count,
                d.linked_active_job_count,
                d.linked_job_status_counts_json
            FROM scan_schedule_deletions d
            WHERE NOT EXISTS (
                SELECT 1
                FROM scan_schedules active
                WHERE active.schedule_id = d.schedule_id
            )
        )
        SELECT
            s.schedule_id AS schedule_id,
            s.name AS name,
            s.target AS target,
            s.network_scope AS network_scope,
            s.scan_profile AS scan_profile,
            s.cadence_minutes AS cadence_minutes,
            s.enabled AS enabled,
            s.auto_ingest AS auto_ingest,
            s.run_trueaegis_after_ingest AS run_trueaegis_after_ingest,
            s.last_run_at AS last_run_at,
            s.next_run_at AS next_run_at,
            s.last_job_id AS last_job_id,
            s.last_status AS last_status,
            s.failure_count AS failure_count,
            s.skip_count AS skip_count,
            s.created_at AS created_at,
            s.updated_at AS updated_at,
            s.message AS schedule_message,
            s.deleted AS deleted,
            s.deleted_at AS deleted_at,
            s.linked_job_count AS linked_job_count,
            s.linked_active_job_count AS linked_active_job_count,
            s.linked_job_status_counts_json AS linked_job_status_counts_json,
            j.job_id AS job_id,
            j.target AS job_target,
            j.network_scope AS job_network_scope,
            j.schedule_id AS job_schedule_id,
            j.status AS job_status,
            j.created_at AS job_created_at,
            j.updated_at AS job_updated_at,
            j.started_at AS job_started_at,
            j.finished_at AS job_finished_at,
            j.netsniper_path AS netsniper_path,
            j.runs_dir AS runs_dir,
            j.scan_profile AS job_scan_profile,
            j.bundle_path AS bundle_path,
            j.exit_code AS exit_code,
            j.auto_ingest AS job_auto_ingest,
            j.stdout_log AS stdout_log,
            j.stderr_log AS stderr_log,
            j.status_json AS status_json,
            j.message AS job_message
        FROM schedule_sources s
        LEFT JOIN scan_jobs j
            ON j.schedule_id = s.schedule_id
            OR j.job_id = s.last_job_id
        {where}
        ORDER BY
            COALESCE(j.created_at, s.last_run_at, s.updated_at, s.created_at) DESC,
            s.created_at DESC
        LIMIT ?
        """,
        tuple(params),
    ).fetchall()


def validate_scan_schedule_cadence_minutes(value: int | str | None) -> int:
    try:
        minutes = int(value if value is not None else 60)
    except (TypeError, ValueError) as exc:
        raise DeltaAegisError(f"invalid schedule cadence minutes: {value!r}") from exc

    if minutes not in ALLOWED_SCAN_SCHEDULE_CADENCE_MINUTES:
        allowed = ", ".join(str(item) for item in sorted(ALLOWED_SCAN_SCHEDULE_CADENCE_MINUTES))
        raise DeltaAegisError(
            f"invalid schedule cadence minutes: {minutes}; allowed values: {allowed}"
        )

    return minutes


def validate_scan_schedule_name(name: str | None) -> str:
    value = str(name or "").strip()

    if not value:
        raise DeltaAegisError("schedule name is required")

    if len(value) > 80:
        raise DeltaAegisError("schedule name must be 80 characters or fewer")

    return value


def scan_schedule_to_dict(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(row)

    item["enabled"] = bool(item.get("enabled"))
    item["auto_ingest"] = bool(item.get("auto_ingest"))
    item["run_trueaegis_after_ingest"] = bool(item.get("run_trueaegis_after_ingest"))
    item["cadence_minutes"] = int(item.get("cadence_minutes") or 60)
    item["scan_profile"] = item.get("scan_profile") or "balanced"

    return item


def create_scan_schedule(
    connection: sqlite3.Connection,
    name: str,
    target: str,
    scan_profile: str = "balanced",
    cadence_minutes: int = 60,
    enabled: bool = True,
    auto_ingest: bool = True,
    run_trueaegis_after_ingest: bool = False,
) -> dict[str, Any]:
    safe_name = validate_scan_schedule_name(name)
    safe_target = validate_private_cidr(target)
    safe_profile = validate_netsniper_scan_profile(scan_profile)
    safe_cadence = validate_scan_schedule_cadence_minutes(cadence_minutes)

    now = utc_now_text()
    schedule_id = f"sched-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
    next_run_at = now if enabled else None

    connection.execute(
        """
        INSERT INTO scan_schedules (
            schedule_id,
            name,
            target,
            network_scope,
            scan_profile,
            cadence_minutes,
            enabled,
            auto_ingest,
            run_trueaegis_after_ingest,
            next_run_at,
            created_at,
            updated_at,
            message
        ) VALUES (
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?
        )
        """,
        (
            schedule_id,
            safe_name,
            safe_target,
            safe_target,
            safe_profile,
            safe_cadence,
            1 if enabled else 0,
            1 if auto_ingest else 0,
            1 if run_trueaegis_after_ingest else 0,
            next_run_at,
            now,
            now,
            "schedule created",
        ),
    )

    row = connection.execute(
        "SELECT * FROM scan_schedules WHERE schedule_id = ?",
        (schedule_id,),
    ).fetchone()

    if row is None:
        raise DeltaAegisError(f"scan schedule disappeared unexpectedly: {schedule_id}")

    return scan_schedule_to_dict(row)


def query_scan_schedules(
    connection: sqlite3.Connection,
    limit: int = 20,
    enabled: bool | None = None,
    scope: str | None = None,
) -> list[sqlite3.Row]:
    clauses = []
    params: list[Any] = []

    if enabled is not None:
        clauses.append("enabled = ?")
        params.append(1 if enabled else 0)

    if scope:
        clauses.append("network_scope = ?")
        params.append(validate_private_cidr(scope))

    where = " WHERE " + " AND ".join(clauses) if clauses else ""

    params.append(limit)

    return connection.execute(
        f"""
        SELECT
            schedule_id,
            name,
            target,
            network_scope,
            scan_profile,
            cadence_minutes,
            enabled,
            auto_ingest,
            run_trueaegis_after_ingest,
            last_run_at,
            next_run_at,
            last_job_id,
            last_status,
            failure_count,
            skip_count,
            created_at,
            updated_at,
            message
        FROM scan_schedules
        {where}
        ORDER BY enabled DESC, next_run_at ASC, created_at DESC
        LIMIT ?
        """,
        tuple(params),
    ).fetchall()


def utc_datetime_to_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")


def next_schedule_run_text(cadence_minutes: int, base_time: datetime | None = None) -> str:
    safe_cadence = validate_scan_schedule_cadence_minutes(cadence_minutes)
    base = base_time or datetime.now(timezone.utc)
    return utc_datetime_to_text(base + timedelta(minutes=safe_cadence))


def active_scan_job_row(connection: sqlite3.Connection) -> sqlite3.Row | None:
    return connection.execute(
        """
        SELECT *
        FROM scan_jobs
        WHERE status IN ('QUEUED', 'RUNNING')
        ORDER BY created_at DESC, updated_at DESC
        LIMIT 1
        """
    ).fetchone()


def active_scan_job_exists(connection: sqlite3.Connection) -> bool:
    return active_scan_job_row(connection) is not None


def reserve_scan_job_if_idle(
    connection: sqlite3.Connection,
    target: str,
    netsniper_path: Path,
    runs_dir: Path,
    *,
    auto_ingest: bool = False,
    scan_profile: str = "balanced",
    schedule_id: str | None = None,
    context: JobContext,
) -> dict[str, Any]:
    """Atomically enforce the global one-active-NetSniper-job invariant."""
    if not isinstance(connection, sqlite3.Connection):
        # Historical receipt validators use a deliberately minimal connection
        # test double. Production connections always take the serialized path.
        job = context.create_scan_job(
            connection,
            target,
            netsniper_path,
            runs_dir,
            auto_ingest=auto_ingest,
            scan_profile=scan_profile,
            schedule_id=schedule_id,
        )
        commit = getattr(connection, "commit", None)
        if callable(commit):
            commit()
        return job

    if connection.in_transaction:
        raise DeltaAegisError(
            "atomic scan reservation requires a connection with no active transaction"
        )

    try:
        # BEGIN IMMEDIATE serializes all competing dashboard, scheduler, and
        # CLI reservations before any caller can perform the active-job check.
        connection.execute("BEGIN IMMEDIATE")
        active = active_scan_job_row(connection)
        if active is not None:
            raise context.active_scan_job_exists_error_type(scan_job_to_dict(active))

        job = context.create_scan_job(
            connection,
            target,
            netsniper_path,
            runs_dir,
            auto_ingest=auto_ingest,
            scan_profile=scan_profile,
            schedule_id=schedule_id,
        )
        connection.commit()
        return job
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise


def scan_job_parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None

    text_value = str(value).strip()

    if not text_value:
        return None

    if text_value.endswith("Z"):
        text_value = text_value[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(text_value)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def scan_job_active_reference_time(job: dict[str, Any] | sqlite3.Row) -> datetime | None:
    item = dict(job)

    # Heartbeats are authoritative for running-job liveness. The remaining
    # timestamps preserve recovery for queued jobs that never launched.
    for key in (
        "heartbeat_at",
        "updated_at",
        "started_at",
        "created_at",
    ):
        parsed = scan_job_parse_datetime(item.get(key))
        if parsed is not None:
            return parsed

    return None


def normalize_stale_scan_job_minutes(value: Any = None) -> int:
    try:
        minutes = int(value or STALE_SCAN_JOB_DEFAULT_MINUTES)
    except (TypeError, ValueError):
        minutes = STALE_SCAN_JOB_DEFAULT_MINUTES

    return max(
        STALE_SCAN_JOB_MINIMUM_MINUTES,
        min(STALE_SCAN_JOB_MAXIMUM_MINUTES, minutes),
    )


def scan_job_is_stale_active(
    job: dict[str, Any] | sqlite3.Row,
    now: datetime | None = None,
    stale_minutes: int = STALE_SCAN_JOB_DEFAULT_MINUTES,
) -> bool:
    item = dict(job)
    status = str(item.get("status") or "").upper()

    if status not in {"QUEUED", "RUNNING"}:
        return False

    reference = scan_job_active_reference_time(item)

    if reference is None:
        return False

    now_value = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    age_seconds = (now_value - reference).total_seconds()

    return age_seconds >= normalize_stale_scan_job_minutes(stale_minutes) * 60


def query_stale_active_scan_jobs(
    connection: sqlite3.Connection,
    stale_minutes: int = STALE_SCAN_JOB_DEFAULT_MINUTES,
    now: datetime | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT *
        FROM scan_jobs
        WHERE status IN ('QUEUED', 'RUNNING')
        ORDER BY created_at ASC, updated_at ASC
        LIMIT ?
        """,
        (max(1, int(limit or 50)),),
    ).fetchall()

    now_value = now or datetime.now(timezone.utc)
    safe_minutes = normalize_stale_scan_job_minutes(stale_minutes)

    stale_jobs: list[dict[str, Any]] = []

    for row in rows:
        item = scan_job_to_dict(row)
        reference = scan_job_active_reference_time(item)

        if reference is not None:
            item["active_reference_at"] = reference.isoformat()
            item["active_age_minutes"] = max(
                0,
                int((now_value.astimezone(timezone.utc) - reference).total_seconds() // 60),
            )
        else:
            item["active_reference_at"] = None
            item["active_age_minutes"] = None

        if scan_job_is_stale_active(item, now=now_value, stale_minutes=safe_minutes):
            stale_jobs.append(item)

    return stale_jobs


def scan_job_process_liveness(
    job: dict[str, Any] | sqlite3.Row,
    proc_root: Path | str | None = None,
) -> dict[str, Any]:
    # Inspect the recorded process without signaling or mutating it.
    item = dict(job)
    root = Path(
        proc_root
        if proc_root is not None
        else SCAN_JOB_WATCHDOG_PROC_ROOT
    )
    expected_path = str(
        Path(str(item.get("netsniper_path") or "")).expanduser()
    )
    pid_value = item.get("process_pid")

    try:
        pid = int(pid_value)
    except (TypeError, ValueError):
        pid = None

    result: dict[str, Any] = {
        "pid": pid,
        "proc_root": str(root),
        "expected_netsniper_path": expected_path,
        "process_exists": False,
        "identity_readable": False,
        "matches_expected_netsniper": False,
        "state": "PROCESS_NOT_RECORDED",
        "cmdline": "",
    }

    if pid is None or pid <= 0:
        return result

    process_root = root / str(pid)

    if not process_root.exists():
        result["state"] = "PROCESS_MISSING"
        return result

    result["process_exists"] = True

    try:
        raw_cmdline = (process_root / "cmdline").read_bytes()
    except OSError as exc:
        result["state"] = "PROCESS_IDENTITY_UNVERIFIABLE"
        result["identity_error"] = exc.__class__.__name__
        return result

    arguments = [
        value.decode("utf-8", errors="replace")
        for value in raw_cmdline.split(b"\x00")
        if value
    ]
    result["identity_readable"] = True
    result["cmdline"] = " ".join(arguments)[:1024]
    matches = bool(
        expected_path
        and any(argument == expected_path for argument in arguments)
    )
    result["matches_expected_netsniper"] = matches
    result["state"] = (
        "LIVE_EXPECTED_PROCESS"
        if matches
        else "PID_REUSE_OR_UNEXPECTED_PROCESS"
    )
    return result


def scan_job_watchdog_evaluation(
    job: dict[str, Any] | sqlite3.Row,
    now: datetime | None = None,
    stale_minutes: int = SCAN_JOB_WATCHDOG_STALE_MINUTES,
    proc_root: Path | str | None = None,
) -> dict[str, Any]:
    item = scan_job_to_dict(job)
    status = str(item.get("status") or "").upper()
    safe_minutes = max(1, int(stale_minutes or 1))
    now_value = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    reference = scan_job_active_reference_time(item)
    age_minutes = None

    if reference is not None:
        age_minutes = max(
            0,
            int(
                (now_value - reference.astimezone(timezone.utc)).total_seconds()
                // 60
            ),
        )

    stale = bool(
        status in {"QUEUED", "RUNNING"}
        and age_minutes is not None
        and age_minutes >= safe_minutes
    )
    process = scan_job_process_liveness(item, proc_root=proc_root)
    process_state = str(process.get("state") or "UNKNOWN")
    classification = "NOT_ACTIVE"
    action = "NONE"
    recoverable = False

    if status in {"QUEUED", "RUNNING"} and not stale:
        classification = "FRESH_ACTIVE_ROW"
    elif status == "QUEUED" and process_state in {
        "PROCESS_NOT_RECORDED",
        "PROCESS_MISSING",
        "PID_REUSE_OR_UNEXPECTED_PROCESS",
    }:
        classification = "DEAD_QUEUED_JOB"
        action = "MARK_FAILED"
        recoverable = True
    elif status == "RUNNING" and process_state in {
        "PROCESS_NOT_RECORDED",
        "PROCESS_MISSING",
    }:
        classification = "DEAD_PROCESS_STALE_ROW"
        action = "MARK_FAILED"
        recoverable = True
    elif status == "RUNNING" and process_state == "PID_REUSE_OR_UNEXPECTED_PROCESS":
        classification = "PID_REUSE_OR_UNEXPECTED_PROCESS"
        action = "MARK_FAILED"
        recoverable = True
    elif status in {"QUEUED", "RUNNING"} and process_state == "LIVE_EXPECTED_PROCESS":
        classification = "LIVE_PROCESS_STALE_HEARTBEAT"
        action = "OPERATOR_REVIEW"
    elif status in {"QUEUED", "RUNNING"} and process_state == "PROCESS_IDENTITY_UNVERIFIABLE":
        classification = "PROCESS_IDENTITY_UNVERIFIABLE"
        action = "OPERATOR_REVIEW"
    elif status in {"QUEUED", "RUNNING"}:
        classification = "STALE_ACTIVE_ROW_REVIEW"
        action = "OPERATOR_REVIEW"

    return {
        "schema_version": SCAN_JOB_WATCHDOG_SCHEMA_VERSION,
        "checked_at": utc_datetime_to_text(now_value),
        "job_id": str(item.get("job_id") or ""),
        "status": status,
        "classification": classification,
        "action": action,
        "recoverable": recoverable,
        "stale": stale,
        "stale_threshold_minutes": safe_minutes,
        "active_reference_at": (
            utc_datetime_to_text(reference)
            if reference is not None
            else None
        ),
        "active_age_minutes": age_minutes,
        "process": process,
    }


def query_due_scan_schedules(
    connection: sqlite3.Connection,
    limit: int = 1,
    now_text: str | None = None,
) -> list[sqlite3.Row]:
    now_value = now_text or utc_now_text()

    return connection.execute(
        """
        SELECT
            schedule_id,
            name,
            target,
            network_scope,
            scan_profile,
            cadence_minutes,
            enabled,
            auto_ingest,
            run_trueaegis_after_ingest,
            last_run_at,
            next_run_at,
            last_job_id,
            last_status,
            failure_count,
            skip_count,
            created_at,
            updated_at,
            message
        FROM scan_schedules
        WHERE enabled = 1
          AND next_run_at IS NOT NULL
          AND next_run_at <= ?
        ORDER BY next_run_at ASC, created_at ASC
        LIMIT ?
        """,
        (now_value, limit),
    ).fetchall()


def mark_scan_schedule_skipped(
    connection: sqlite3.Connection,
    schedule_id: str,
    cadence_minutes: int,
    reason: str,
) -> dict[str, Any]:
    now_dt = datetime.now(timezone.utc)
    now = utc_datetime_to_text(now_dt)
    next_run_at = next_schedule_run_text(cadence_minutes, now_dt)

    connection.execute(
        """
        UPDATE scan_schedules
        SET
            skip_count = skip_count + 1,
            last_status = ?,
            next_run_at = ?,
            updated_at = ?,
            message = ?
        WHERE schedule_id = ?
        """,
        ("SKIPPED", next_run_at, now, reason, schedule_id),
    )

    row = connection.execute(
        "SELECT * FROM scan_schedules WHERE schedule_id = ?",
        (schedule_id,),
    ).fetchone()

    if row is None:
        raise DeltaAegisError(f"scan schedule disappeared unexpectedly: {schedule_id}")

    return scan_schedule_to_dict(row)


def update_scan_schedule_after_job(
    connection: sqlite3.Connection,
    schedule_id: str,
    cadence_minutes: int,
    job: dict[str, Any],
) -> dict[str, Any]:
    now_dt = datetime.now(timezone.utc)
    now = utc_datetime_to_text(now_dt)
    next_run_at = next_schedule_run_text(cadence_minutes, now_dt)
    status = str(job.get("status") or "UNKNOWN").upper()
    failure_increment = 0 if status == "COMPLETED" else 1

    cursor = connection.execute(
        """
        UPDATE scan_schedules
        SET
            last_run_at = ?,
            next_run_at = ?,
            last_job_id = ?,
            last_status = ?,
            failure_count = failure_count + ?,
            updated_at = ?,
            message = ?
        WHERE schedule_id = ?
        """,
        (
            now,
            next_run_at,
            job.get("job_id"),
            status,
            failure_increment,
            now,
            job.get("message") or f"scheduled scan finished with status {status}",
            schedule_id,
        ),
    )

    row = connection.execute(
        "SELECT * FROM scan_schedules WHERE schedule_id = ?",
        (schedule_id,),
    ).fetchone()

    if row is not None:
        return scan_schedule_to_dict(row)

    if cursor.rowcount == 0:
        summary = scan_schedule_linked_job_summary(
            connection,
            schedule_id,
        )
        connection.execute(
            """
            UPDATE scan_schedule_deletions
            SET
                last_run_at = ?,
                next_run_at = NULL,
                last_job_id = ?,
                last_status = ?,
                failure_count = failure_count + ?,
                updated_at = ?,
                message = ?,
                linked_job_count = ?,
                linked_active_job_count = ?,
                linked_job_status_counts_json = ?
            WHERE schedule_id = ?
            """,
            (
                now,
                job.get("job_id"),
                status,
                failure_increment,
                now,
                job.get("message")
                or f"deleted schedule job finished with status {status}",
                summary["linked_job_count"],
                summary["linked_active_job_count"],
                json.dumps(
                    summary["linked_job_status_counts"],
                    sort_keys=True,
                ),
                schedule_id,
            ),
        )

        deleted_row = connection.execute(
            "SELECT * FROM scan_schedule_deletions WHERE schedule_id = ?",
            (schedule_id,),
        ).fetchone()

        if deleted_row is not None:
            return scan_schedule_deletion_to_dict(deleted_row)

    raise DeltaAegisError(
        f"scan schedule disappeared without deletion evidence: {schedule_id}"
    )


def set_scan_schedule_enabled(
    connection: sqlite3.Connection,
    schedule_id: str,
    enabled: bool,
) -> dict[str, Any]:
    row = connection.execute(
        "SELECT * FROM scan_schedules WHERE schedule_id = ?",
        (schedule_id,),
    ).fetchone()

    if row is None:
        raise DeltaAegisError(f"scan schedule not found: {schedule_id}")

    now = utc_now_text()

    connection.execute(
        """
        UPDATE scan_schedules
        SET
            enabled = ?,
            next_run_at = ?,
            updated_at = ?,
            message = ?
        WHERE schedule_id = ?
        """,
        (
            1 if enabled else 0,
            now if enabled else None,
            now,
            "schedule enabled" if enabled else "schedule disabled",
            schedule_id,
        ),
    )

    row = connection.execute(
        "SELECT * FROM scan_schedules WHERE schedule_id = ?",
        (schedule_id,),
    ).fetchone()

    if row is None:
        raise DeltaAegisError(f"scan schedule disappeared unexpectedly: {schedule_id}")

    return scan_schedule_to_dict(row)


def scan_schedule_delete_confirmation(schedule_id: Any) -> str:
    safe_schedule_id = str(schedule_id or "").strip()

    if not safe_schedule_id:
        raise DeltaAegisError("scan schedule id is required")

    return f"{SCAN_SCHEDULE_DELETE_CONFIRMATION_PREFIX}{safe_schedule_id}"


def scan_schedule_deletion_to_dict(
    row: sqlite3.Row | dict[str, Any],
) -> dict[str, Any]:
    item = scan_schedule_to_dict(row)
    item["deleted"] = True
    item["deleted_at"] = item.get("deleted_at")
    item["linked_job_count"] = int(item.get("linked_job_count") or 0)
    item["linked_active_job_count"] = int(
        item.get("linked_active_job_count") or 0
    )
    item["linked_job_status_counts"] = decode_json_field(
        item.get("linked_job_status_counts_json"),
        {},
    )
    item["linked_jobs_preserved"] = True
    item["active_jobs_cancelled"] = False
    item["cancellation_required_for_active_jobs"] = bool(
        item["linked_active_job_count"]
    )
    return item


def scan_schedule_linked_job_summary(
    connection: sqlite3.Connection,
    schedule_id: str,
) -> dict[str, Any]:
    rows = connection.execute(
        "SELECT status, COUNT(*) AS count "
        "FROM scan_jobs "
        "WHERE schedule_id = ? "
        "GROUP BY status "
        "ORDER BY status",
        (schedule_id,),
    ).fetchall()

    status_counts = {
        str(row["status"] or "UNKNOWN").upper(): int(row["count"] or 0)
        for row in rows
    }
    linked_job_count = sum(status_counts.values())
    linked_active_job_count = sum(
        status_counts.get(status, 0)
        for status in ("QUEUED", "RUNNING")
    )

    return {
        "linked_job_count": linked_job_count,
        "linked_active_job_count": linked_active_job_count,
        "linked_job_status_counts": status_counts,
    }


def delete_scan_schedule(
    connection: sqlite3.Connection,
    schedule_id: str,
) -> dict[str, Any]:
    safe_schedule_id = str(schedule_id or "").strip()
    row = connection.execute(
        "SELECT * FROM scan_schedules WHERE schedule_id = ?",
        (safe_schedule_id,),
    ).fetchone()

    if row is None:
        raise DeltaAegisError(
            f"scan schedule not found: {safe_schedule_id}"
        )

    schedule = scan_schedule_to_dict(row)
    summary = scan_schedule_linked_job_summary(
        connection,
        safe_schedule_id,
    )
    deleted_at = utc_now_text()

    connection.execute(
        """
        INSERT OR REPLACE INTO scan_schedule_deletions (
            schedule_id,
            name,
            target,
            network_scope,
            scan_profile,
            cadence_minutes,
            enabled,
            auto_ingest,
            run_trueaegis_after_ingest,
            last_run_at,
            next_run_at,
            last_job_id,
            last_status,
            failure_count,
            skip_count,
            created_at,
            updated_at,
            message,
            deleted_at,
            linked_job_count,
            linked_active_job_count,
            linked_job_status_counts_json
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            safe_schedule_id,
            schedule["name"],
            schedule["target"],
            schedule["network_scope"],
            schedule["scan_profile"],
            schedule["cadence_minutes"],
            1 if schedule["enabled"] else 0,
            1 if schedule["auto_ingest"] else 0,
            1 if schedule.get("run_trueaegis_after_ingest") else 0,
            schedule.get("last_run_at"),
            schedule.get("next_run_at"),
            schedule.get("last_job_id"),
            schedule.get("last_status"),
            int(schedule.get("failure_count") or 0),
            int(schedule.get("skip_count") or 0),
            schedule.get("created_at") or deleted_at,
            schedule.get("updated_at") or deleted_at,
            schedule.get("message") or "",
            deleted_at,
            summary["linked_job_count"],
            summary["linked_active_job_count"],
            json.dumps(
                summary["linked_job_status_counts"],
                sort_keys=True,
            ),
        ),
    )

    cursor = connection.execute(
        "DELETE FROM scan_schedules WHERE schedule_id = ?",
        (safe_schedule_id,),
    )

    if cursor.rowcount != 1:
        raise DeltaAegisError(
            f"scan schedule deletion failed: {safe_schedule_id}"
        )

    deleted_row = connection.execute(
        "SELECT * FROM scan_schedule_deletions WHERE schedule_id = ?",
        (safe_schedule_id,),
    ).fetchone()

    if deleted_row is None:
        raise DeltaAegisError(
            f"scan schedule deletion evidence missing: {safe_schedule_id}"
        )

    return scan_schedule_deletion_to_dict(deleted_row)
