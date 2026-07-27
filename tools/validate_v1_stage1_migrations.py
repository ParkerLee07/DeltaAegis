#!/usr/bin/env python3
"""Validate the DeltaAegis v1 Stage 1 upgrade and recovery contract."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import deltaaegis  # noqa: E402
from deltaaegis_core import auth, migrations  # noqa: E402


EXPECTED_TAGS = {
    "v0.42.0": {
        "commit": "5c78e0c764e5c5352a68d3e78b8f3fa79b1128ba",
        "source_sha256": "986212b74db632e39b4ff2edf5e8b5cb0605276ab1a09655d3ea9eddc1addfad",
    },
    "v0.42.1": {
        "commit": "dce4897e335a3d6978a6e3c0d6da54a194ade158",
        "source_sha256": "5458a1399dda7c973388ec846dd9a7c9eef403c7f038ba20a7393735d015e725",
    },
    "v0.42.2": {
        "commit": "cc8d099604083ae75f1bad595d53fd2b23433941",
        "source_sha256": "09e8ef6b7eae6a9431de3daf8c859cfa84d77026d92191ba04bdeb96aa7448d4",
    },
}
EXPECTED_LEGACY_SCHEMA = (
    "781be13dec43b657c383c9c7a217c3df83040319cbb8469d1d175667edf63b32"
)
EXPECTED_V045_RELEASE_COMMIT = "493df20dabed527757381e3cbae7cad3201b9c57"
EXPECTED_V045_RELEASE_TREE = "ab2c059806e0bbd3908f32200d79cb357e8fa61c"
EXPECTED_V045_SOURCE_WITNESS = "74cba5ec5aa3d35cd57416c3891c161d8bf5fd4b"
EXPECTED_V045_SOURCE_SHA256 = "e277bfeed6e5422d567c5207d14b6bc9a43c5fc8486f95be9c0b73d8c5706c12"
EXPECTED_V045_RUNTIME_SCHEMA = "7b15660af4a2a6f4424b1c6dc7c9fceaee962c998cd0ad7754bb3ed6051be654"
EXPECTED_V045_HISTORICAL_RUNTIME_SCHEMA = "5c777b2a731133a8793c6710eda3e1a18b15deb9ffa416bed71ffd70e11581ef"
EXPECTED_V045_HISTORICAL_ORIGIN = "v0.45.0-historical-additive-runtime-schema"
EXPECTED_V1_HISTORICAL_RUNTIME_SCHEMA = "6f82fe381a4ab11437a64d8ef0b127a0fe654183d3fe986f1735f2e156fac7c6"
EXPECTED_ORIGIN = "v0.42.0-v0.45.0-identical-base-schema"

V045_HISTORICAL_TABLE_SQL = {
    "asset_lifecycle": """CREATE TABLE "asset_lifecycle" (
            network_scope TEXT NOT NULL DEFAULT '',
            asset_key TEXT NOT NULL,
            identity_class TEXT NOT NULL,
            state TEXT NOT NULL,
            missing_count INTEGER NOT NULL DEFAULT 0,
            current_ip TEXT NOT NULL,
            mac_address TEXT,
            vendor TEXT,
            hostname TEXT,
            first_seen_scan_id TEXT NOT NULL,
            last_seen_scan_id TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            removed_at TEXT,
            PRIMARY KEY (network_scope, asset_key)
        )""",
    "asset_observations": """CREATE TABLE asset_observations (
    scan_id TEXT NOT NULL,
    asset_key TEXT NOT NULL,
    identity_confidence TEXT NOT NULL,
    identity_source TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    mac_address TEXT,
    vendor TEXT,
    hostname TEXT,
    device_type TEXT,
    severity TEXT,
    score INTEGER, identity_class TEXT NOT NULL DEFAULT 'IP_ONLY', device_type_confidence INTEGER, classification_type TEXT, classification_primary_type TEXT, classification_confidence INTEGER, classification_confidence_label TEXT, classification_decision TEXT, classification_method TEXT, classification_json TEXT NOT NULL DEFAULT '{}', classification_evidence_json TEXT NOT NULL DEFAULT '[]', classification_contradictions_json TEXT NOT NULL DEFAULT '[]', classification_candidates_json TEXT NOT NULL DEFAULT '[]', classification_confidence_band TEXT, classification_calibrated_decision TEXT, classification_siem_action TEXT, classification_calibration_reason TEXT, classification_validation_state TEXT, classification_contradiction_count INTEGER, classification_validator_summary_json TEXT NOT NULL DEFAULT '{}', classification_validators_json TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (scan_id, asset_key),
    FOREIGN KEY (scan_id) REFERENCES snapshots(scan_id) ON DELETE CASCADE
)""",
    "scan_jobs": """CREATE TABLE scan_jobs (
    job_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    network_scope TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    netsniper_path TEXT NOT NULL DEFAULT '',
    runs_dir TEXT NOT NULL DEFAULT '',
    bundle_path TEXT,
    exit_code INTEGER,
    auto_ingest INTEGER NOT NULL DEFAULT 0,
    stdout_log TEXT,
    stderr_log TEXT,
    status_json TEXT NOT NULL DEFAULT '{}',
    message TEXT NOT NULL DEFAULT ''
, scan_profile TEXT NOT NULL DEFAULT 'balanced', schedule_id TEXT NOT NULL DEFAULT '', process_pid INTEGER, heartbeat_at TEXT, cancel_requested_at TEXT, cancel_requested_by TEXT NOT NULL DEFAULT '', cancel_reason TEXT NOT NULL DEFAULT '', cancelled_at TEXT)""",
    "scan_schedules": """CREATE TABLE scan_schedules (
    schedule_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    target TEXT NOT NULL,
    network_scope TEXT NOT NULL,
    scan_profile TEXT NOT NULL DEFAULT 'balanced',
    cadence_minutes INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    auto_ingest INTEGER NOT NULL DEFAULT 1,
    last_run_at TEXT,
    next_run_at TEXT,
    last_job_id TEXT,
    last_status TEXT,
    failure_count INTEGER NOT NULL DEFAULT 0,
    skip_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT ''
, run_trueaegis_after_ingest INTEGER NOT NULL DEFAULT 0)""",
    "snapshots": """CREATE TABLE snapshots (
    scan_id TEXT PRIMARY KEY,
    manifest_path TEXT NOT NULL,
    target TEXT NOT NULL,
    scanner_version TEXT NOT NULL,
    scan_profile TEXT NOT NULL,
    created_at TEXT NOT NULL,
    imported_at TEXT NOT NULL,
    bundle_status TEXT NOT NULL,
    quality_status TEXT NOT NULL,
    quality_reason TEXT NOT NULL,
    xml_exit_status TEXT NOT NULL,
    hosts_up INTEGER NOT NULL,
    hosts_down INTEGER NOT NULL,
    hosts_total INTEGER NOT NULL,
    mac_backed_assets INTEGER NOT NULL,
    identity_coverage REAL NOT NULL,
    is_accepted_baseline INTEGER NOT NULL DEFAULT 0
, manifest_schema_version TEXT NOT NULL DEFAULT 'netsniper-run-v1', profile_fingerprint TEXT NOT NULL DEFAULT '', monitored_ports_json TEXT NOT NULL DEFAULT '[]', protocols_json TEXT NOT NULL DEFAULT '[]', discovery_interface TEXT, nmap_version TEXT, scan_started_at TEXT, scan_completed_at TEXT, neighbors_captured_at TEXT, network_scope TEXT NOT NULL DEFAULT '', requested_profile TEXT, effective_profile TEXT, profile_contract TEXT, profile_runtime_budget_seconds INTEGER, profile_host_timeout_seconds INTEGER, profile_duration_seconds INTEGER, profile_budget_exceeded INTEGER, bundle_quality_schema_version TEXT, bundle_deltaaegis_ready INTEGER, bundle_quality_json TEXT NOT NULL DEFAULT '{}', quality_decision_id TEXT, automated_quality_state TEXT, current_quality_state TEXT, bundle_digest TEXT NOT NULL DEFAULT '', evidence_retention_path TEXT NOT NULL DEFAULT '', quality_effects_json TEXT NOT NULL DEFAULT '{}', quality_reasons_json TEXT NOT NULL DEFAULT '[]', negative_evidence_allowed INTEGER NOT NULL DEFAULT 0)""",
    "trueaegis_jobs": """CREATE TABLE trueaegis_jobs (
    job_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    scan_id TEXT,
    network_scope TEXT NOT NULL DEFAULT '',
    manifest_path TEXT NOT NULL,
    trueaegis_path TEXT NOT NULL DEFAULT '',
    validation_results_path TEXT,
    validation_run_id TEXT,
    imported_observations INTEGER NOT NULL DEFAULT 0,
    correlation_count INTEGER NOT NULL DEFAULT 0,
    stdout_log_path TEXT,
    stderr_log_path TEXT,
    exit_code INTEGER,
    message TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT
, scan_job_id TEXT NOT NULL DEFAULT '', schedule_id TEXT NOT NULL DEFAULT '', trigger_source TEXT NOT NULL DEFAULT 'manual_dashboard')""",
}


class ValidationFailure(RuntimeError):
    pass


class InjectedInterruption(RuntimeError):
    pass


def check(condition: Any, message: str) -> None:
    if not condition:
        raise ValidationFailure(message)


def git_bytes(*args: str) -> bytes:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise ValidationFailure(
            f"git {' '.join(args)} failed: "
            + result.stderr.decode("utf-8", errors="replace")
        )
    return result.stdout


def git_text(*args: str) -> str:
    return git_bytes(*args).decode("utf-8", errors="strict").strip()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def create_exact_legacy_database(tag: str, destination: Path) -> str:
    metadata = EXPECTED_TAGS[tag]
    check(
        git_text("rev-parse", f"{tag}^{{commit}}") == metadata["commit"],
        f"{tag} commit fingerprint changed",
    )
    source = git_bytes("show", f"{tag}:deltaaegis.py")
    source_sha = sha256_bytes(source)
    check(
        source_sha == metadata["source_sha256"],
        f"{tag} deltaaegis.py fingerprint changed",
    )
    script = destination.parent / f"deltaaegis-{tag}.py"
    script.write_bytes(source)
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--db",
            str(destination),
            "summary",
        ],
        cwd=destination.parent,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    check(
        result.returncode == 0,
        f"{tag} could not materialize its database fixture: {result.stderr}",
    )
    check(destination.is_file(), f"{tag} did not create its database")
    connection = sqlite3.connect(destination)
    try:
        fingerprint = migrations.schema_fingerprint(connection)
    finally:
        connection.close()
    check(
        fingerprint == EXPECTED_LEGACY_SCHEMA,
        f"{tag} legacy schema fingerprint changed: {fingerprint}",
    )
    return source_sha


def resolve_v045_release_source_commit() -> str:
    for commit in (
        EXPECTED_V045_RELEASE_COMMIT,
        EXPECTED_V045_SOURCE_WITNESS,
    ):
        result = subprocess.run(
            ["git", "rev-parse", f"{commit}^{{tree}}"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if (
            result.returncode == 0
            and result.stdout.strip() == EXPECTED_V045_RELEASE_TREE
        ):
            return commit
    raise ValidationFailure(
        "neither the published v0.45.0 merge commit nor the audited "
        "source witness has the released tree"
    )


def materialize_v045_release_source(destination: Path) -> Path:
    source_commit = resolve_v045_release_source_commit()
    paths = [
        path
        for path in git_text(
            "ls-tree",
            "-r",
            "--name-only",
            source_commit,
        ).splitlines()
        if path == "deltaaegis.py"
        or (path.startswith("deltaaegis_core/") and path.endswith(".py"))
    ]
    check("deltaaegis.py" in paths, "v0.45 release source lacks deltaaegis.py")
    for relative in paths:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(git_bytes("show", f"{source_commit}:{relative}"))
    source = destination / "deltaaegis.py"
    check(
        sha256_bytes(source.read_bytes()) == EXPECTED_V045_SOURCE_SHA256,
        "v0.45 released source fingerprint changed",
    )
    return source


def create_exact_v045_database(
    destination: Path,
    *,
    expanded_runtime: bool,
) -> str:
    source_root = destination.parent / "v045-source"
    source = materialize_v045_release_source(source_root)
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    if expanded_runtime:
        program = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import deltaaegis as da
database = Path(sys.argv[2])
connection = da.connect(database)
da.ensure_netsniper_intelligence_host_schema(connection)
da.ensure_netsniper_intelligence_schema(connection)
da._telemetry_quality.ensure_schema(connection)
da._current_state.ensure_schema(connection)
connection.commit()
connection.close()
"""
        command = [
            sys.executable,
            "-c",
            program,
            str(source_root),
            str(destination),
        ]
    else:
        command = [
            sys.executable,
            str(source),
            "--db",
            str(destination),
            "--events",
            str(destination.parent / "events.jsonl"),
            "--reports-dir",
            str(destination.parent / "reports"),
            "summary",
        ]
    result = subprocess.run(
        command,
        cwd=source_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    check(
        result.returncode == 0,
        "v0.45 release source could not materialize its database fixture: "
        + result.stderr,
    )
    connection = sqlite3.connect(destination)
    try:
        fingerprint = migrations.schema_fingerprint(connection)
    finally:
        connection.close()
    expected = (
        EXPECTED_V045_RUNTIME_SCHEMA
        if expanded_runtime
        else EXPECTED_LEGACY_SCHEMA
    )
    check(
        fingerprint == expected,
        f"v0.45 database schema fingerprint changed: {fingerprint}",
    )
    return fingerprint


def convert_to_historical_v045_runtime_layout(database: Path) -> str:
    """Reproduce the audited schema emitted by released additive upgrades."""
    connection = sqlite3.connect(database)
    try:
        before = migrations.schema_fingerprint(connection)
        check(
            before == EXPECTED_V045_RUNTIME_SCHEMA,
            "historical-layout fixture did not start from exact v0.45 runtime",
        )
        connection.execute("PRAGMA foreign_keys = OFF")
        for table, table_sql in V045_HISTORICAL_TABLE_SQL.items():
            index_sql = [
                str(row[0])
                for row in connection.execute(
                    "SELECT sql FROM sqlite_master "
                    "WHERE type = 'index' AND tbl_name = ? AND sql IS NOT NULL "
                    "ORDER BY name",
                    (table,),
                )
            ]
            connection.execute(
                f"DROP TABLE {migrations.quote_identifier(table)}"
            )
            connection.execute(table_sql)
            for statement in index_sql:
                connection.execute(statement)
        connection.commit()
        check(
            connection.execute("PRAGMA foreign_key_check").fetchall() == [],
            "historical v0.45 fixture has foreign-key violations",
        )
        fingerprint = migrations.schema_fingerprint(connection)
    finally:
        connection.close()
    check(
        fingerprint == EXPECTED_V045_HISTORICAL_RUNTIME_SCHEMA,
        "historical v0.45 runtime fingerprint changed: " + fingerprint,
    )
    return fingerprint


def populate_protected_history(database: Path) -> None:
    now = "2026-07-21T18:45:00Z"
    future = (
        datetime.now(timezone.utc) + timedelta(days=2)
    ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    connection = sqlite3.connect(database)
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        connection.execute(
            "INSERT INTO snapshots ("
            "scan_id, manifest_path, target, network_scope, scanner_version, "
            "scan_profile, created_at, imported_at, bundle_status, quality_status, "
            "quality_reason, xml_exit_status, hosts_up, hosts_down, hosts_total, "
            "mac_backed_assets, identity_coverage, is_accepted_baseline"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "fixture-scan", "/evidence/manifest.json", "10.42.0.0/24",
                "10.42.0.0/24", "2.1.0", "balanced", now, now, "COMPLETE",
                "PASS", "fixture", "0", 1, 0, 1, 1, 1.0, 1,
            ),
        )
        connection.execute(
            "INSERT INTO asset_observations ("
            "scan_id, asset_key, identity_confidence, identity_source, ip_address, "
            "mac_address, vendor, hostname, severity, score, identity_class"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "fixture-scan", "mac:001122334455", "HIGH", "MAC",
                "10.42.0.10", "00:11:22:33:44:55", "Fixture Vendor",
                "fixture-host", "MEDIUM", 42, "MAC_BACKED",
            ),
        )
        connection.execute(
            "INSERT INTO service_observations ("
            "scan_id, asset_key, protocol, port, state, service_name, product, version"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("fixture-scan", "mac:001122334455", "tcp", 443, "open", "https", "fixture", "1"),
        )
        connection.execute(
            "INSERT INTO finding_observations ("
            "scan_id, asset_key, finding_id, name, service, port, score, evidence"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("fixture-scan", "mac:001122334455", "finding-1", "Fixture finding", "https", 443, 42, "fixture evidence"),
        )
        event = connection.execute(
            "INSERT INTO delta_events ("
            "scan_id, baseline_scan_id, event_type, severity, subject_key, "
            "previous_value, current_value, summary, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("fixture-scan", None, "NEW_ASSET", "MEDIUM", "mac:001122334455", None, "present", "fixture event", now),
        ).lastrowid
        alert = connection.execute(
            "INSERT INTO alerts ("
            "dedup_key, event_type, severity, subject_key, status, summary, "
            "opened_at, last_seen_at, first_event_id, last_event_id"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("fixture-alert", "NEW_ASSET", "MEDIUM", "mac:001122334455", "OPEN", "fixture alert", now, now, event, event),
        ).lastrowid
        connection.execute(
            "INSERT INTO alert_notes (alert_id, action, reason, created_at) VALUES (?, ?, ?, ?)",
            (alert, "ACK", "fixture note", now),
        )
        connection.execute(
            "INSERT INTO asset_annotations (asset_key, owner, role, criticality, notes, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("mac:001122334455", "fixture-owner", "gateway", "HIGH", "fixture", now),
        )
        connection.execute(
            "INSERT INTO asset_annotation_history (asset_key, owner, role, criticality, notes, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("mac:001122334455", "fixture-owner", "gateway", "HIGH", "fixture history", now),
        )
        connection.execute(
            "INSERT INTO asset_investigations (network_scope, asset_key, status, reason, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("10.42.0.0/24", "mac:001122334455", "INVESTIGATING", "fixture", now, now),
        )
        connection.execute(
            "INSERT INTO asset_investigation_history (network_scope, asset_key, status, reason, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            ("10.42.0.0/24", "mac:001122334455", "INVESTIGATING", "fixture", now),
        )
        connection.execute(
            "INSERT INTO logical_sites (site_id, name, description, status, created_at, updated_at) "
            "VALUES (?, ?, ?, 'ACTIVE', ?, ?)",
            ("fixture-site", "Fixture Site", "migration evidence", now, now),
        )
        connection.execute(
            "INSERT INTO logical_site_memberships (network_scope, site_id, created_at, updated_at) "
            "VALUES (?, ?, ?, ?)",
            ("10.42.0.0/24", "fixture-site", now, now),
        )
        connection.execute(
            "INSERT INTO access_users ("
            "user_id, username, display_name, role, password_hash, is_active, created_at, updated_at"
            ") VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
            ("fixture-user", "fixture-admin", "Fixture Admin", "ADMIN", "fixture-hash", now, now),
        )
        connection.execute(
            "INSERT INTO access_api_tokens ("
            "token_id, user_id, token_name, token_hash, token_prefix, role, is_active, created_at, updated_at, expires_at"
            ") VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, NULL)",
            ("fixture-token", "fixture-user", "Fixture token", "0" * 64, "da_fixture", "ADMIN", now, now),
        )
        connection.execute(
            "INSERT INTO access_sessions ("
            "session_id, user_id, session_token_hash, role, is_active, created_at, last_seen_at, expires_at, source_ip, user_agent"
            ") VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?)",
            ("fixture-session", "fixture-user", "1" * 64, "ADMIN", now, now, future, "127.0.0.1", "stage1-validator"),
        )
        connection.execute(
            "INSERT INTO access_audit_log ("
            "actor_user_id, actor_username, actor_role, action, target_type, target_key, detail_json, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("fixture-user", "fixture-admin", "ADMIN", "FIXTURE", "validator", "stage1", "{}", now),
        )
        connection.execute(
            "INSERT INTO scan_jobs (job_id, target, network_scope, status, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("fixture-job", "10.42.0.0/24", "10.42.0.0/24", "SUCCEEDED", now, now),
        )
        connection.execute(
            "INSERT INTO validation_runs ("
            "validation_run_id, source_path, source_filename, source_sha256, source_format, "
            "imported_at, result_count, status_counts_json"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("fixture-validation", "/evidence/validation.json", "validation.json", "2" * 64, "json", now, 1, '{"PASS":1}'),
        )
        connection.execute(
            "INSERT INTO validation_observations ("
            "observation_id, validation_run_id, row_index, finding_id, host, port, protocol, status, raw_json"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("fixture-observation", "fixture-validation", 0, "finding-1", "10.42.0.10", 443, "tcp", "PASS", "{}"),
        )
        connection.commit()
        check(connection.execute("PRAGMA foreign_key_check").fetchall() == [], "legacy fixture has foreign-key violations")
        check(connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "legacy fixture integrity failed")
    finally:
        connection.close()


def raw_history(
    database: Path,
    *,
    reference: dict[str, dict[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    try:
        return migrations.protected_history_fingerprints(
            connection,
            reference=reference,
        )
    finally:
        connection.close()


def schema_contract(database: Path) -> dict[str, Any]:
    """Describe schema semantics while ignoring historical column ordering."""
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    try:
        result: dict[str, Any] = {}
        for table in migrations.application_tables(connection):
            quoted_table = migrations.quote_identifier(table)
            columns = sorted(
                (
                    {
                        key: row[key]
                        for key in row.keys()
                        if key != "cid"
                    }
                    for row in connection.execute(
                        f"PRAGMA table_xinfo({quoted_table})"
                    )
                ),
                key=lambda item: str(item["name"]),
            )
            foreign_keys = sorted(
                (
                    {
                        key: row[key]
                        for key in row.keys()
                        if key not in {"id", "seq"}
                    }
                    for row in connection.execute(
                        f"PRAGMA foreign_key_list({quoted_table})"
                    )
                ),
                key=lambda item: json.dumps(item, sort_keys=True),
            )
            indexes = []
            for row in connection.execute(
                f"PRAGMA index_list({quoted_table})"
            ):
                if str(row["origin"]) == "pk":
                    continue
                name = str(row["name"])
                quoted_index = migrations.quote_identifier(name)
                index_columns = [
                    {
                        key: item[key]
                        for key in item.keys()
                        if key not in {"seqno", "cid"}
                    }
                    for item in connection.execute(
                        f"PRAGMA index_xinfo({quoted_index})"
                    )
                ]
                indexes.append(
                    {
                        "name": name,
                        "unique": row["unique"],
                        "origin": row["origin"],
                        "partial": row["partial"],
                        "columns": index_columns,
                    }
                )
            result[table] = {
                "columns": columns,
                "foreign_keys": foreign_keys,
                "indexes": sorted(indexes, key=lambda item: item["name"]),
            }
        return result
    finally:
        connection.close()


def ledger_rows(database: Path) -> list[dict[str, Any]]:
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    try:
        if "schema_migrations" not in migrations.application_tables(connection):
            return []
        return [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM schema_migrations ORDER BY migration_id"
            )
        ]
    finally:
        connection.close()


def verify_completed_upgrade(
    database: Path,
    *,
    expected_history: dict[str, dict[str, Any]],
    expected_schema: str,
    expected_origin: str = EXPECTED_ORIGIN,
    expected_schema_before: str = EXPECTED_LEGACY_SCHEMA,
) -> list[dict[str, Any]]:
    connection = deltaaegis.connect(database)
    try:
        rows = [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM schema_migrations ORDER BY migration_id"
            )
        ]
        definitions = deltaaegis.deltaaegis_schema_migrations()
        check(
            [row["migration_id"] for row in rows]
            == [item.migration_id for item in definitions],
            "completed ledger does not match the ordered migration definitions",
        )
        check(
            [row["checksum"] for row in rows]
            == [item.checksum for item in definitions],
            "completed ledger checksums do not match migration bytes",
        )
        check(
            {row["origin"] for row in rows} == {expected_origin},
            "completed ledger did not preserve the supported origin",
        )
        for row in rows:
            evidence = json.loads(row["outcome_json"])
            check(evidence["ledger_schema_version"] == migrations.MIGRATION_LEDGER_SCHEMA_VERSION, "ledger outcome version drift")
            check(isinstance(evidence["action"], dict), "ledger outcome lacks action evidence")
        first_outcome = json.loads(rows[0]["outcome_json"])
        check(
            first_outcome["schema_before"] == expected_schema_before,
            "first migration did not fingerprint the true pre-ledger schema",
        )
        check(
            isinstance(first_outcome.get("pre_migration_backup"), dict),
            "first migration lacks pre-migration backup evidence",
        )
        check(
            all(
                "pre_migration_backup" not in json.loads(row["outcome_json"])
                for row in rows[1:]
            ),
            "a later migration was incorrectly labeled with a pre-migration backup",
        )
        after_history = migrations.protected_history_fingerprints(
            connection,
            reference=expected_history,
        )
        migrations.verify_protected_history(expected_history, after_history)
        check(connection.execute("PRAGMA foreign_key_check").fetchall() == [], "upgraded database has foreign-key violations")
        check(connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "upgraded database integrity failed")
        check(migrations.schema_fingerprint(connection) == expected_schema, "fresh and upgraded schemas did not converge")
        token = connection.execute(
            "SELECT expires_at, scopes_json FROM access_api_tokens WHERE token_id = 'fixture-token'"
        ).fetchone()
        check(token is not None and str(token["expires_at"] or ""), "legacy API token was not bounded")
        scopes = json.loads(token["scopes_json"])
        check(scopes == sorted(auth.access_api_scopes_for_role("ADMIN")), "legacy API token scopes were not deterministically backfilled")
        csrf = connection.execute(
            "SELECT csrf_token_hash FROM access_sessions WHERE session_id = 'fixture-session'"
        ).fetchone()
        check(csrf is not None and len(str(csrf[0])) == 64, "legacy session did not receive fail-closed CSRF state")
        return rows
    finally:
        connection.close()


def validate_exact_origins(root: Path) -> tuple[Path, str]:
    fresh = root / "fresh.db"
    connection = deltaaegis.connect(fresh)
    try:
        fresh_schema = migrations.schema_fingerprint(connection)
        check(
            {row[0] for row in connection.execute("SELECT origin FROM schema_migrations")}
            == {"fresh"},
            "fresh database ledger origin is incorrect",
        )
    finally:
        connection.close()
    check(not list((root / "migration-backups").glob("*.manifest.json")), "fresh install unexpectedly created a pre-migration backup")

    legacy_schema_fingerprints: set[str] = set()
    retained_fixture: Path | None = None
    for tag in EXPECTED_TAGS:
        case = root / tag.replace(".", "-")
        case.mkdir()
        database = case / "legacy.db"
        source_sha = create_exact_legacy_database(tag, database)
        check(source_sha == deltaaegis.SUPPORTED_V042_SOURCE_SHA256[tag], f"{tag} source pin is not encoded in the runtime")
        populate_protected_history(database)
        before_history = raw_history(database)
        before_logical = deltaaegis._sqlite_database_logical_fingerprint(database)
        connection = sqlite3.connect(database)
        try:
            legacy_schema_fingerprints.add(migrations.schema_fingerprint(connection))
        finally:
            connection.close()

        rows = verify_completed_upgrade(
            database,
            expected_history=before_history,
            expected_schema=fresh_schema,
        )
        backup_evidence = json.loads(rows[0]["outcome_json"])["pre_migration_backup"]
        verified = deltaaegis.verify_database_backup_bundle(
            Path(backup_evidence["backup_path"]),
            Path(backup_evidence["manifest_path"]),
        )
        check(verified["logical_fingerprint"] == before_logical, f"{tag} backup was not the exact pre-migration state")
        backup_history = raw_history(Path(verified["backup_path"]))
        migrations.verify_protected_history(before_history, backup_history)
        check(ledger_rows(Path(verified["backup_path"])) == [], f"{tag} backup contains post-migration ledger state")

        rehearsal = case / "restore-rehearsal.db"
        restored = deltaaegis.create_database_restore_rehearsal(
            database,
            Path(verified["backup_path"]),
            Path(verified["manifest_path"]),
            rehearsal,
        )
        check(restored["restored_integrity_status"] == "ok", f"{tag} restore rehearsal integrity failed")
        migrations.verify_protected_history(before_history, raw_history(rehearsal))

        backups_before = sorted((case / "migration-backups").glob("*"))
        verify_completed_upgrade(database, expected_history=before_history, expected_schema=fresh_schema)
        backups_after = sorted((case / "migration-backups").glob("*"))
        check(backups_before == backups_after, f"{tag} idempotent reopen created another backup")
        retained_fixture = database

    check(legacy_schema_fingerprints == {EXPECTED_LEGACY_SCHEMA}, "supported v0.42 patch schemas are not identical as audited")

    for expanded_runtime in (False, True):
        label = "v0.45-runtime" if expanded_runtime else "v0.45-clean"
        case = root / label
        case.mkdir()
        database = case / "legacy.db"
        source_schema = create_exact_v045_database(
            database,
            expanded_runtime=expanded_runtime,
        )
        populate_protected_history(database)
        before_history = raw_history(database)
        before_logical = deltaaegis._sqlite_database_logical_fingerprint(database)
        expected_origin = (
            "v0.45.0-telemetry-runtime-schema"
            if expanded_runtime
            else EXPECTED_ORIGIN
        )
        rows = verify_completed_upgrade(
            database,
            expected_history=before_history,
            expected_schema=fresh_schema,
            expected_origin=expected_origin,
            expected_schema_before=source_schema,
        )
        backup_evidence = json.loads(rows[0]["outcome_json"])[
            "pre_migration_backup"
        ]
        verified = deltaaegis.verify_database_backup_bundle(
            Path(backup_evidence["backup_path"]),
            Path(backup_evidence["manifest_path"]),
        )
        check(
            verified["logical_fingerprint"] == before_logical,
            f"{label} backup was not the exact pre-migration state",
        )
        migrations.verify_protected_history(
            before_history,
            raw_history(Path(verified["backup_path"])),
        )

    historical_case = root / "v0.45-historical-runtime"
    historical_case.mkdir()
    historical_database = historical_case / "legacy.db"
    create_exact_v045_database(
        historical_database,
        expanded_runtime=True,
    )
    source_schema = convert_to_historical_v045_runtime_layout(
        historical_database
    )
    populate_protected_history(historical_database)
    before_history = raw_history(historical_database)
    before_logical = deltaaegis._sqlite_database_logical_fingerprint(
        historical_database
    )
    rows = verify_completed_upgrade(
        historical_database,
        expected_history=before_history,
        expected_schema=EXPECTED_V1_HISTORICAL_RUNTIME_SCHEMA,
        expected_origin=EXPECTED_V045_HISTORICAL_ORIGIN,
        expected_schema_before=source_schema,
    )
    check(
        schema_contract(historical_database) == schema_contract(fresh),
        "historical and fresh v1 databases do not expose the same schema contract",
    )
    backup_evidence = json.loads(rows[0]["outcome_json"])[
        "pre_migration_backup"
    ]
    verified = deltaaegis.verify_database_backup_bundle(
        Path(backup_evidence["backup_path"]),
        Path(backup_evidence["manifest_path"]),
    )
    check(
        verified["logical_fingerprint"] == before_logical,
        "historical v0.45 backup was not the exact pre-migration state",
    )
    migrations.verify_protected_history(
        before_history,
        raw_history(Path(verified["backup_path"])),
    )
    check(
        ledger_rows(Path(verified["backup_path"])) == [],
        "historical v0.45 backup contains post-migration ledger state",
    )
    rehearsal = historical_case / "restore-rehearsal.db"
    restored = deltaaegis.create_database_restore_rehearsal(
        historical_database,
        Path(verified["backup_path"]),
        Path(verified["manifest_path"]),
        rehearsal,
    )
    check(
        restored["restored_integrity_status"] == "ok",
        "historical v0.45 restore rehearsal integrity failed",
    )
    migrations.verify_protected_history(
        before_history,
        raw_history(rehearsal),
    )
    backups_before = sorted((historical_case / "migration-backups").glob("*"))
    verify_completed_upgrade(
        historical_database,
        expected_history=before_history,
        expected_schema=EXPECTED_V1_HISTORICAL_RUNTIME_SCHEMA,
        expected_origin=EXPECTED_V045_HISTORICAL_ORIGIN,
        expected_schema_before=source_schema,
    )
    backups_after = sorted((historical_case / "migration-backups").glob("*"))
    check(
        backups_before == backups_after,
        "historical v0.45 idempotent reopen created another backup",
    )

    check(retained_fixture is not None, "no exact legacy fixture was retained")
    return retained_fixture, fresh_schema


def run_with_interruption(database: Path, phase: str, target: str) -> None:
    connection = deltaaegis.open_database_connection(database)

    def interrupt(actual_phase: str, migration_id: str) -> None:
        if actual_phase == phase and migration_id == target:
            if phase == "after_backup":
                check(
                    "schema_migrations" not in migrations.application_tables(connection),
                    "ledger mutated before the verified backup boundary",
                )
            raise InjectedInterruption(f"{phase}:{target}")

    try:
        migrations.run_migrations(
            connection,
            database_path=database,
            application_version="1.0.0-stage12-validator",
            migrations=deltaaegis.deltaaegis_schema_migrations(),
            backup_root=database.parent / "migration-backups",
            create_backup=deltaaegis.create_sqlite_database_backup_bundle,
            verify_backup=deltaaegis.verify_database_backup_bundle,
            failure_hook=interrupt,
            origin_recognizer=deltaaegis.recognize_deltaaegis_database_origin,
        )
    except InjectedInterruption:
        pass
    else:
        raise ValidationFailure(f"injected interruption did not fire: {phase}:{target}")
    finally:
        connection.close()


def validate_interruption_boundaries(
    legacy_database: Path,
    root: Path,
    fresh_schema: str,
) -> None:
    # Recover an exact pre-migration fixture from the verified backup generated
    # by the origin test, then use independent copies for every interruption.
    rows = ledger_rows(legacy_database)
    evidence = json.loads(rows[0]["outcome_json"])["pre_migration_backup"]
    pristine = Path(evidence["backup_path"])
    expected_history = raw_history(pristine)
    definitions = deltaaegis.deltaaegis_schema_migrations()
    phases = ("before_apply", "after_apply", "before_ledger", "before_commit", "after_commit")
    cases = [("after_backup", definitions[0].migration_id)]
    cases.extend((phase, definitions[0].migration_id) for phase in phases)
    cases.extend((phase, definitions[1].migration_id) for phase in phases)

    for index, (phase, target) in enumerate(cases):
        case = root / f"interrupt-{index:02d}-{phase}-{target}"
        case.mkdir()
        database = case / "legacy.db"
        shutil.copy2(pristine, database)
        run_with_interruption(database, phase, target)
        rows_after_failure = ledger_rows(database)
        first_id, second_id = definitions[0].migration_id, definitions[1].migration_id
        expected_ids: list[str] = []
        if target == second_id:
            expected_ids.append(first_id)
        if phase == "after_commit":
            expected_ids.append(target)
        check(
            [row["migration_id"] for row in rows_after_failure] == expected_ids,
            f"interruption left a partial ledger at {phase}:{target}",
        )
        migrations.verify_protected_history(
            expected_history,
            raw_history(database, reference=expected_history),
        )
        verify_completed_upgrade(database, expected_history=expected_history, expected_schema=fresh_schema)
        if phase == "after_commit" and target == first_id:
            manifests = list((case / "migration-backups").glob("*.manifest.json"))
            check(
                len(manifests) == 1,
                "resume after the first commit created a second pre-migration backup",
            )


def expect_migration_failure(database: Path, phrase: str) -> None:
    try:
        connection = deltaaegis.connect(database)
    except (deltaaegis.DeltaAegisError, migrations.MigrationError, sqlite3.Error) as exc:
        check(phrase.lower() in str(exc).lower(), f"unexpected fail-closed message: {exc}")
    else:
        connection.close()
        raise ValidationFailure(f"database did not fail closed for {phrase}")


def validate_fail_closed_cases(legacy_database: Path, root: Path) -> None:
    unsupported = root / "unsupported.db"
    connection = sqlite3.connect(unsupported)
    connection.execute("CREATE TABLE unrelated (id INTEGER PRIMARY KEY)")
    connection.commit()
    connection.close()
    expect_migration_failure(unsupported, "required v0.42.x tables")

    historical_drift = root / "historical-runtime-with-real-drift.db"
    create_exact_v045_database(
        historical_drift,
        expanded_runtime=True,
    )
    convert_to_historical_v045_runtime_layout(historical_drift)
    connection = sqlite3.connect(historical_drift)
    connection.execute(
        "ALTER TABLE asset_lifecycle ADD COLUMN unsupported_runtime_value TEXT"
    )
    connection.commit()
    connection.close()
    expect_migration_failure(historical_drift, "asset_lifecycle")

    symlink_target = root / "symlink-target.db"
    shutil.copy2(legacy_database, symlink_target)
    symlink_path = root / "symlink-active.db"
    symlink_path.symlink_to(symlink_target)
    expect_migration_failure(symlink_path, "must not be a symlink")

    for column, value, phrase in (
        ("checksum", "f" * 64, "migration bytes changed"),
        ("outcome_json", "{}", "outcome version"),
        ("origin", "", "origin is missing"),
    ):
        tampered = root / f"tampered-{column}.db"
        shutil.copy2(legacy_database, tampered)
        connection = sqlite3.connect(tampered)
        connection.execute(
            f"UPDATE schema_migrations SET {column} = ? WHERE migration_id = (SELECT MIN(migration_id) FROM schema_migrations)",
            (value,),
        )
        connection.commit()
        connection.close()
        expect_migration_failure(tampered, phrase)

    broken_chain = root / "tampered-schema-chain.db"
    shutil.copy2(legacy_database, broken_chain)
    connection = sqlite3.connect(broken_chain)
    first_id = deltaaegis.deltaaegis_schema_migrations()[0].migration_id
    row = connection.execute(
        "SELECT outcome_json FROM schema_migrations WHERE migration_id = ?",
        (first_id,),
    ).fetchone()
    outcome = json.loads(row[0])
    outcome["schema_after"] = "e" * 64
    connection.execute(
        "UPDATE schema_migrations SET outcome_json = ? WHERE migration_id = ?",
        (json.dumps(outcome, sort_keys=True, separators=(",", ":")), first_id),
    )
    connection.commit()
    connection.close()
    expect_migration_failure(broken_chain, "schema chain")

    drifted_schema = root / "drifted-ledger-schema.db"
    shutil.copy2(legacy_database, drifted_schema)
    connection = sqlite3.connect(drifted_schema)
    connection.execute("CREATE INDEX unsupported_runtime_index ON alerts(status)")
    connection.commit()
    connection.close()
    expect_migration_failure(drifted_schema, "current database schema")

    unknown = root / "unknown-ledger.db"
    shutil.copy2(legacy_database, unknown)
    connection = sqlite3.connect(unknown)
    template = connection.execute(
        "SELECT checksum, applied_at, application_version, origin, outcome_json FROM schema_migrations LIMIT 1"
    ).fetchone()
    connection.execute(
        "INSERT INTO schema_migrations VALUES (?, ?, ?, ?, ?, ?)",
        ("9999-unknown-migration", *template),
    )
    connection.commit()
    connection.close()
    expect_migration_failure(unknown, "unknown to this application")

    empty = root / "empty-ledger.db"
    shutil.copy2(legacy_database, empty)
    connection = sqlite3.connect(empty)
    connection.execute("DELETE FROM schema_migrations")
    connection.commit()
    connection.close()
    expect_migration_failure(empty, "empty migration ledger")

    tampered_backup = root / "tampered-backup.db"
    manifest = root / "tampered-backup.db.manifest.json"
    bundle = deltaaegis.create_sqlite_database_backup_bundle(
        legacy_database,
        tampered_backup,
    )
    check(Path(bundle["manifest_path"]) == manifest, "backup manifest naming drift")
    with tampered_backup.open("r+b") as stream:
        stream.seek(0)
        first = stream.read(1)
        stream.seek(0)
        stream.write(bytes([first[0] ^ 0x01]))
    try:
        deltaaegis.verify_database_backup_bundle(tampered_backup, manifest)
    except deltaaegis.DeltaAegisError as exc:
        check("sha-256" in str(exc).lower(), "tampered backup did not fail at checksum verification")
    else:
        raise ValidationFailure("tampered migration backup was accepted")

    resume_case = root / "tampered-resume-backup"
    resume_case.mkdir()
    completed_rows = ledger_rows(legacy_database)
    pristine_evidence = json.loads(
        completed_rows[0]["outcome_json"]
    )["pre_migration_backup"]
    partial_database = resume_case / "legacy.db"
    shutil.copy2(Path(pristine_evidence["backup_path"]), partial_database)
    first_migration = deltaaegis.deltaaegis_schema_migrations()[0].migration_id
    run_with_interruption(partial_database, "after_commit", first_migration)
    partial_rows = ledger_rows(partial_database)
    check(len(partial_rows) == 1, "resume-tamper fixture is not partially migrated")
    partial_evidence = json.loads(
        partial_rows[0]["outcome_json"]
    )["pre_migration_backup"]
    recorded_backup = Path(partial_evidence["backup_path"])
    with recorded_backup.open("r+b") as stream:
        first = stream.read(1)
        check(bool(first), "recorded resume backup is empty")
        stream.seek(0)
        stream.write(bytes([first[0] ^ 0x01]))
    expect_migration_failure(partial_database, "sha-256")


def validate_concurrent_start(root: Path, fresh_schema: str) -> None:
    case = root / "concurrent"
    case.mkdir()
    database = case / "legacy.db"
    create_exact_legacy_database("v0.42.2", database)
    populate_protected_history(database)
    expected_history = raw_history(database)
    barrier = threading.Barrier(3)
    failures: list[BaseException] = []

    def worker() -> None:
        try:
            barrier.wait(timeout=10)
            connection = deltaaegis.connect(database)
            connection.close()
        except BaseException as exc:  # validator must retain thread evidence
            failures.append(exc)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait(timeout=10)
    for thread in threads:
        thread.join(timeout=30)
    check(all(not thread.is_alive() for thread in threads), "concurrent migration workers did not terminate")
    check(not failures, f"concurrent migration startup failed: {failures}")
    verify_completed_upgrade(database, expected_history=expected_history, expected_schema=fresh_schema)
    manifests = list((case / "migration-backups").glob("*.manifest.json"))
    check(len(manifests) == 1, "concurrent startup created more than one migration backup")


def validate_forced_interleaving(root: Path, fresh_schema: str) -> None:
    case = root / "forced-interleaving"
    case.mkdir()
    database = case / "legacy.db"
    create_exact_legacy_database("v0.42.2", database)
    populate_protected_history(database)
    expected_history = raw_history(database)
    first_committed = threading.Event()
    second_finished = threading.Event()
    failures: list[BaseException] = []
    first_migration = deltaaegis.deltaaegis_schema_migrations()[0].migration_id

    def first_worker() -> None:
        connection = deltaaegis.open_database_connection(database)

        def pause_after_first_commit(phase: str, migration_id: str) -> None:
            if phase == "after_commit" and migration_id == first_migration:
                first_committed.set()
                if not second_finished.wait(timeout=30):
                    raise ValidationFailure(
                        "second starter did not finish during forced interleaving"
                    )

        try:
            migrations.run_migrations(
                connection,
                database_path=database,
                application_version="1.0.0-stage12-interleaving-a",
                migrations=deltaaegis.deltaaegis_schema_migrations(),
                backup_root=case / "migration-backups",
                create_backup=deltaaegis.create_sqlite_database_backup_bundle,
                verify_backup=deltaaegis.verify_database_backup_bundle,
                failure_hook=pause_after_first_commit,
                origin_recognizer=deltaaegis.recognize_deltaaegis_database_origin,
            )
        except BaseException as exc:
            failures.append(exc)
        finally:
            connection.close()

    def second_worker() -> None:
        try:
            if not first_committed.wait(timeout=30):
                raise ValidationFailure("first starter did not reach its first commit")
            connection = deltaaegis.connect(database)
            connection.close()
        except BaseException as exc:
            failures.append(exc)
        finally:
            second_finished.set()

    threads = [
        threading.Thread(target=first_worker, daemon=True),
        threading.Thread(target=second_worker, daemon=True),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=45)
    check(
        all(not thread.is_alive() for thread in threads),
        "forced interleaving workers did not terminate",
    )
    check(not failures, f"forced interleaving migration failed: {failures}")
    verify_completed_upgrade(
        database,
        expected_history=expected_history,
        expected_schema=fresh_schema,
    )
    manifests = list((case / "migration-backups").glob("*.manifest.json"))
    check(
        len(manifests) == 1,
        "forced interleaving created more than one pre-migration backup",
    )


def main() -> int:
    check(
        deltaaegis.DELTAAEGIS_VERSION
        in {"1.0.0-stage12", "1.0.0"},
        "runtime stage version is outside the approved v1 candidate sequence",
    )
    check(tuple(deltaaegis.SUPPORTED_V042_SOURCE_SHA256) == tuple(EXPECTED_TAGS), "runtime supported-origin inventory drift")
    check(
        deltaaegis.SUPPORTED_V045_RELEASE_COMMIT == EXPECTED_V045_RELEASE_COMMIT
        and deltaaegis.SUPPORTED_V045_RELEASE_TREE == EXPECTED_V045_RELEASE_TREE
        and deltaaegis.SUPPORTED_V045_SOURCE_WITNESS == EXPECTED_V045_SOURCE_WITNESS
        and deltaaegis.SUPPORTED_V045_SOURCE_SHA256 == EXPECTED_V045_SOURCE_SHA256
        and deltaaegis.SUPPORTED_V045_RUNTIME_SCHEMA_SHA256 == EXPECTED_V045_RUNTIME_SCHEMA,
        "runtime v0.45 release or schema pins drifted",
    )
    check(
        deltaaegis.SUPPORTED_V045_HISTORICAL_RUNTIME_SCHEMA_SHA256
        == EXPECTED_V045_HISTORICAL_RUNTIME_SCHEMA,
        "runtime historical v0.45 schema pin drifted",
    )
    with tempfile.TemporaryDirectory(prefix="deltaaegis-v1-stage1-") as temporary:
        root = Path(temporary)
        origins_root = root / "origins"
        origins_root.mkdir()
        legacy_database, fresh_schema = validate_exact_origins(origins_root)
        interruption_root = root / "interruptions"
        interruption_root.mkdir()
        validate_interruption_boundaries(legacy_database, interruption_root, fresh_schema)
        fail_closed_root = root / "fail-closed"
        fail_closed_root.mkdir()
        validate_fail_closed_cases(legacy_database, fail_closed_root)
        validate_concurrent_start(root, fresh_schema)
        validate_forced_interleaving(root, fresh_schema)

    print(
        "[PASS] v1 Stage 1: exact v0.42, released v0.45, and audited historical v0.45 origins, checksummed forward migrations, "
        "verified backup/rehearsal, interruption recovery, history preservation, "
        "convergence, forced concurrency interleaving, and fail-closed ledger controls"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValidationFailure, migrations.MigrationError) as exc:
        print(f"[FAIL] v1 Stage 1: {exc}", file=sys.stderr)
        raise SystemExit(1)
