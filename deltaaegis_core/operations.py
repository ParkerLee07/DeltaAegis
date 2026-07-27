"""Operational health, readiness, diagnostics, and contract pins for v1."""

from __future__ import annotations

import json
import os
import platform
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from deltaaegis_core import detection, identity


HEALTH_SCHEMA_VERSION = "deltaaegis-health-v1"
READINESS_SCHEMA_VERSION = "deltaaegis-readiness-v1"
DIAGNOSTIC_SCHEMA_VERSION = "deltaaegis-diagnostics-v1"
INTEGRATION_CONTRACT_SCHEMA_VERSION = "deltaaegis-integration-compatibility-v1"
PERFORMANCE_TARGET_SCHEMA_VERSION = "deltaaegis-performance-targets-v1"
EXPECTED_MIGRATIONS = (
    "0001-v045-foundation",
    "0002-v045-telemetry-trust",
    "0003-v1-api-security",
    "0004-v1-sensor-scope-identity",
    "0005-v1-deterministic-detection",
)
SENSITIVE_KEY_PARTS = (
    "password",
    "secret",
    "raw_token",
    "authorization",
    "cookie",
    "csrf",
    "session_token",
)


INTEGRATION_COMPATIBILITY = {
    "schema_version": INTEGRATION_CONTRACT_SCHEMA_VERSION,
    "netsniper": {
        "semantic_version": "2.1.0",
        "source_commit": "0624a36550f6eb62ed0daa6862e5cc25a0d93236",
        "manifest_schemas": ["netsniper-run-v3", "netsniper-run-v2"],
        "capability_schema": "netsniper-capability-manifest-v1",
        "host_classification_schema": "netsniper-host-classification-v2",
        "classifier_version": "netsniper-classifier-v2",
        "execution_boundary": "fixed-argv-headless-cli",
    },
    "trueaegis": {
        "supported_semver": ">=1.2.0,<2.0.0",
        "contract": "trueaegis-validation-results-v1",
        "source_witness_commit": "16b9e88b232aac568859ab8d68e2eaa26558c4e7",
        "required_shape": "json-array-of-validation-result-objects",
        "optional": True,
    },
}


PERFORMANCE_TARGETS = {
    "schema_version": PERFORMANCE_TARGET_SCHEMA_VERSION,
    "baseline": {
        "release": "v0.43",
        "cold_import_median_ms": 558.686,
        "fresh_schema_init_median_ms": 28.078,
        "summary_payload_median_ms": 5.666,
        "assets_payload_median_ms": 4.804,
        "report_generation_median_ms": 489.329,
        "database_bytes_per_asset": 1399.467,
    },
    "targets": {
        "cold_import_max_ms": 2000.0,
        "fresh_schema_init_max_ms": 500.0,
        "summary_payload_max_ms": 100.0,
        "assets_payload_max_ms": 100.0,
        "report_generation_max_ms": 2000.0,
        "database_bytes_per_asset_max": 5000.0,
        "readiness_max_ms": 1000.0,
        "combined_release_gate_max_seconds": 600.0,
    },
    "soak": {
        "minimum_hours": 24,
        "sample_interval_seconds": 60,
        "maximum_unplanned_worker_failures": 0,
        "maximum_integrity_failures": 0,
    },
}


class OperationsError(ValueError):
    """Raised for malformed operational or integration evidence."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _check(name: str, ok: bool, detail: str, *, blocking: bool = True) -> dict[str, Any]:
    return {
        "name": str(name),
        "status": "PASS" if ok else "FAIL",
        "blocking": bool(blocking),
        "detail": str(detail)[:1000],
    }


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        for key, item in value.items():
            normalized = str(key).casefold()
            if any(part in normalized for part in SENSITIVE_KEY_PARTS):
                output[str(key)] = "[REDACTED]"
            else:
                output[str(key)] = _redact(item)
        return output
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, str) and len(value) > 4000:
        return value[:4000] + "...[truncated]"
    return value


def liveness_report() -> dict[str, Any]:
    return {
        "schema_version": HEALTH_SCHEMA_VERSION,
        "status": "UP",
        "generated_at": utc_now(),
        "process": {
            "pid": os.getpid(),
            "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        },
    }


def _migration_checks(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    table = connection.execute(
        "SELECT 1 FROM sqlite_schema WHERE type='table' AND name='schema_migrations'"
    ).fetchone()
    if table is None:
        return [_check("migration_ledger", False, "schema_migrations is absent")]
    rows = connection.execute(
        "SELECT migration_id FROM schema_migrations ORDER BY migration_id"
    ).fetchall()
    applied = {str(row["migration_id"]) for row in rows}
    missing = [item for item in EXPECTED_MIGRATIONS if item not in applied]
    return [
        _check(
            "migration_ledger",
            not missing,
            (
                "all expected migrations are applied"
                if not missing
                else f"missing={missing}"
            ),
        )
    ]


def _database_checks(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    quick = str(connection.execute("PRAGMA quick_check").fetchone()[0])
    foreign_rows = connection.execute("PRAGMA foreign_key_check").fetchall()
    writable = not bool(connection.execute("PRAGMA query_only").fetchone()[0])
    return [
        _check("database_quick_check", quick == "ok", quick),
        _check(
            "database_foreign_keys",
            not foreign_rows,
            "no foreign-key violations" if not foreign_rows else f"{len(foreign_rows)} violation(s)",
        ),
        _check("database_write_boundary", writable, "database connection is writable"),
    ]


def _worker_checks(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    scan_rows = connection.execute(
        "SELECT status, COUNT(*) AS count FROM scan_jobs GROUP BY status"
    ).fetchall()
    trueaegis_rows = connection.execute(
        "SELECT status, COUNT(*) AS count FROM trueaegis_jobs GROUP BY status"
    ).fetchall()
    invalid_scan = sum(
        int(row["count"])
        for row in scan_rows
        if str(row["status"]) not in {"QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"}
    )
    invalid_validation = sum(
        int(row["count"])
        for row in trueaegis_rows
        if str(row["status"]) not in {"QUEUED", "RUNNING", "COMPLETED", "FAILED"}
    )
    return [
        _check(
            "scan_worker_ledger",
            invalid_scan == 0,
            f"states={{{', '.join(f'{row[0]}:{row[1]}' for row in scan_rows)}}}",
        ),
        _check(
            "trueaegis_worker_ledger",
            invalid_validation == 0,
            f"states={{{', '.join(f'{row[0]}:{row[1]}' for row in trueaegis_rows)}}}",
            blocking=False,
        ),
    ]


def _integration_checks(
    *,
    netsniper_path: Path | None,
    trueaegis_path: Path | None,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    if netsniper_path is not None:
        path = Path(netsniper_path).expanduser()
        checks.append(
            _check(
                "netsniper_executable",
                path.is_file() and os.access(path, os.X_OK),
                "configured NetSniper CLI is executable" if path.is_file() and os.access(path, os.X_OK) else "configured NetSniper CLI is unavailable",
            )
        )
    else:
        checks.append(
            _check(
                "netsniper_executable",
                True,
                "not evaluated without an execution configuration",
                blocking=False,
            )
        )
    if trueaegis_path is not None:
        path = Path(trueaegis_path).expanduser()
        checks.append(
            _check(
                "trueaegis_executable",
                path.is_file() and os.access(path, os.X_OK),
                "configured optional TrueAegis CLI is executable" if path.is_file() and os.access(path, os.X_OK) else "configured optional TrueAegis CLI is unavailable",
                blocking=False,
            )
        )
    return checks


def readiness_report(
    connection: sqlite3.Connection,
    *,
    database_path: Path | None = None,
    netsniper_path: Path | None = None,
    trueaegis_path: Path | None = None,
) -> dict[str, Any]:
    checks = [
        *_migration_checks(connection),
        *_database_checks(connection),
        *_worker_checks(connection),
    ]
    try:
        identity.validate_schema(connection)
    except (identity.IdentityError, sqlite3.Error) as exc:
        checks.append(_check("identity_schema", False, str(exc)))
    else:
        checks.append(_check("identity_schema", True, "sensor/scope schema is ready"))
    try:
        detection.validate_schema(connection)
    except (detection.DetectionError, sqlite3.Error) as exc:
        checks.append(_check("detection_schema", False, str(exc)))
    else:
        checks.append(_check("detection_schema", True, "detection ledger is ready"))
    checks.extend(
        _integration_checks(
            netsniper_path=netsniper_path,
            trueaegis_path=trueaegis_path,
        )
    )
    if database_path is not None:
        database = Path(database_path).expanduser().resolve(strict=False)
        usage = shutil.disk_usage(database.parent)
        checks.append(
            _check(
                "database_disk_capacity",
                usage.free >= max(64 * 1024 * 1024, database.stat().st_size * 2 if database.exists() else 0),
                f"free_bytes={usage.free}",
            )
        )
    blocking_failures = [
        item for item in checks if item["blocking"] and item["status"] != "PASS"
    ]
    return {
        "schema_version": READINESS_SCHEMA_VERSION,
        "status": "READY" if not blocking_failures else "NOT_READY",
        "generated_at": utc_now(),
        "checks": checks,
        "blocking_failure_count": len(blocking_failures),
    }


def diagnostics_report(
    connection: sqlite3.Connection,
    *,
    database_path: Path | None = None,
    netsniper_path: Path | None = None,
    trueaegis_path: Path | None = None,
) -> dict[str, Any]:
    readiness = readiness_report(
        connection,
        database_path=database_path,
        netsniper_path=netsniper_path,
        trueaegis_path=trueaegis_path,
    )
    migrations = [
        dict(row)
        for row in connection.execute(
            "SELECT migration_id, checksum, application_version, origin, "
            "applied_at FROM schema_migrations "
            "ORDER BY migration_id"
        ).fetchall()
    ]
    job_counts = {
        str(row["status"]): int(row["count"])
        for row in connection.execute(
            "SELECT status, COUNT(*) AS count FROM scan_jobs GROUP BY status"
        )
    }
    sensors = identity.list_sensors(connection, include_revoked=True)
    scopes = identity.list_scopes(
        connection,
        include_unassigned=True,
    )
    database: dict[str, Any] = {
        "page_count": int(connection.execute("PRAGMA page_count").fetchone()[0]),
        "page_size": int(connection.execute("PRAGMA page_size").fetchone()[0]),
    }
    if database_path is not None:
        path = Path(database_path).expanduser().resolve(strict=False)
        database.update(
            {
                "filename": path.name,
                "size_bytes": path.stat().st_size if path.exists() else 0,
                "parent_writable": os.access(path.parent, os.W_OK),
            }
        )
    report = {
        "schema_version": DIAGNOSTIC_SCHEMA_VERSION,
        "generated_at": utc_now(),
        "readiness": readiness,
        "runtime": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "sqlite": sqlite3.sqlite_version,
            "pid": os.getpid(),
        },
        "database": database,
        "migrations": migrations,
        "identity": {
            "sensor_count": len(sensors),
            "scope_count": len(scopes),
            "sensors": sensors[:100],
            "scopes": scopes[:500],
        },
        "workers": {"scan_job_counts": job_counts},
        "integrations": INTEGRATION_COMPATIBILITY,
        "performance_targets": PERFORMANCE_TARGETS,
    }
    return _redact(report)


def validate_trueaegis_fixture(value: Any) -> dict[str, Any]:
    if not isinstance(value, list):
        raise OperationsError("TrueAegis fixture must be a JSON array")
    allowed_statuses = {
        "CONFIRMED",
        "REACHABLE",
        "PROTECTED",
        "PROTOCOL_MISMATCH",
        "NOT_REACHABLE",
        "TIMEOUT",
        "INCONCLUSIVE",
        "PARTIALLY_CONFIRMED",
        "DEPENDENCY_MISSING",
        "UNKNOWN",
    }
    for index, row in enumerate(value):
        if not isinstance(row, Mapping):
            raise OperationsError(f"TrueAegis fixture row {index} is not an object")
        status = str(row.get("status") or "UNKNOWN").upper()
        if status not in allowed_statuses:
            raise OperationsError(
                f"TrueAegis fixture row {index} has unsupported status {status}"
            )
        if not str(row.get("host") or row.get("target") or "").strip():
            raise OperationsError(f"TrueAegis fixture row {index} lacks a host")
    return {
        "contract": INTEGRATION_COMPATIBILITY["trueaegis"]["contract"],
        "records": len(value),
        "status": "PASS",
    }


def validate_performance_sample(sample: Mapping[str, Any]) -> dict[str, Any]:
    targets = PERFORMANCE_TARGETS["targets"]
    checks = []
    for target_name, maximum in targets.items():
        metric = target_name.removesuffix("_max_ms").removesuffix("_max_seconds")
        if target_name == "database_bytes_per_asset_max":
            metric = "database_bytes_per_asset"
        if metric not in sample:
            continue
        try:
            actual = float(sample[metric])
        except (TypeError, ValueError) as exc:
            raise OperationsError(f"performance metric is not numeric: {metric}") from exc
        checks.append(
            {
                "metric": metric,
                "actual": actual,
                "maximum": float(maximum),
                "status": "PASS" if actual <= float(maximum) else "FAIL",
            }
        )
    if not checks:
        raise OperationsError("performance sample contains no recognized metrics")
    return {
        "schema_version": PERFORMANCE_TARGET_SCHEMA_VERSION,
        "status": "PASS" if all(item["status"] == "PASS" for item in checks) else "FAIL",
        "checks": checks,
    }


def canonical_contract_json() -> str:
    return json.dumps(
        INTEGRATION_COMPATIBILITY,
        indent=2,
        sort_keys=True,
    ) + "\n"


def canonical_performance_json() -> str:
    return json.dumps(PERFORMANCE_TARGETS, indent=2, sort_keys=True) + "\n"


__all__ = (
    "DIAGNOSTIC_SCHEMA_VERSION",
    "EXPECTED_MIGRATIONS",
    "HEALTH_SCHEMA_VERSION",
    "INTEGRATION_COMPATIBILITY",
    "INTEGRATION_CONTRACT_SCHEMA_VERSION",
    "OperationsError",
    "PERFORMANCE_TARGETS",
    "PERFORMANCE_TARGET_SCHEMA_VERSION",
    "READINESS_SCHEMA_VERSION",
    "canonical_contract_json",
    "canonical_performance_json",
    "diagnostics_report",
    "liveness_report",
    "readiness_report",
    "validate_performance_sample",
    "validate_trueaegis_fixture",
)
