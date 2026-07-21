"""Forward-only, backup-integrated SQLite migrations for DeltaAegis v1.0.

The migration engine deliberately knows nothing about DeltaAegis domain SQL.
Callers provide immutable :class:`Migration` definitions and the existing
v0.41 backup/verification functions.  This keeps the storage boundary small
while making the safety ordering explicit and testable:

1. recognize a supported database origin;
2. validate every recorded migration checksum;
3. acquire a SQLite write reservation;
4. create and verify a consistent pre-migration backup;
5. apply one migration and its ledger row in the same transaction; and
6. verify foreign keys, integrity, and protected history before commit.

Schema downgrade is intentionally absent.  Recovery uses the verified backup
and the existing guarded restore-cutover workflow.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence


MIGRATION_LEDGER_SCHEMA_VERSION = "deltaaegis-schema-migrations-v1"
MIGRATION_ID_PATTERN = re.compile(r"[0-9]{4}-[a-z0-9][a-z0-9._-]{2,95}")
CHECKSUM_PATTERN = re.compile(r"[0-9a-f]{64}")

SCHEMA_MIGRATIONS_SQL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    migration_id TEXT PRIMARY KEY,
    checksum TEXT NOT NULL,
    applied_at TEXT NOT NULL,
    application_version TEXT NOT NULL,
    origin TEXT NOT NULL,
    outcome_json TEXT NOT NULL,
    CHECK (length(checksum) = 64)
);
CREATE INDEX IF NOT EXISTS idx_schema_migrations_applied_at
    ON schema_migrations(applied_at);
"""

# Tables whose existing records constitute protected operator or evidence
# history.  New columns may be added, but values in the captured columns may
# not disappear or change during a migration run.
PROTECTED_TABLES = (
    "snapshots",
    "asset_observations",
    "service_observations",
    "finding_observations",
    "delta_events",
    "asset_lifecycle",
    "alerts",
    "alert_notes",
    "asset_annotations",
    "asset_annotation_history",
    "asset_investigations",
    "asset_investigation_history",
    "investigation_ticket_state",
    "investigation_ticket_history",
    "logical_sites",
    "logical_site_memberships",
    "access_users",
    "access_api_tokens",
    "access_sessions",
    "access_audit_log",
    "scan_jobs",
    "scan_schedules",
    "scan_schedule_deletions",
    "trueaegis_jobs",
    "validation_runs",
    "validation_observations",
    "validation_correlations",
    "telemetry_quality_decisions",
    "telemetry_quality_reviews",
)

# These fields are deliberately enriched or bounded by supported migrations.
# All other pre-existing values remain byte-for-byte represented in the
# protected-history fingerprint.
PROTECTED_FIELD_EXCLUSIONS: Mapping[str, frozenset[str]] = {
    "snapshots": frozenset(
        {
            "network_scope",
            "quality_decision_id",
            "current_quality_state",
            "telemetry_effects_json",
        }
    ),
    "access_api_tokens": frozenset({"expires_at", "scopes_json"}),
    "access_sessions": frozenset({"csrf_token_hash"}),
}

KNOWN_REMOTE_FILESYSTEMS = frozenset(
    {
        "9p",
        "afs",
        "ceph",
        "cifs",
        "davfs",
        "fuse.sshfs",
        "gcsfuse",
        "glusterfs",
        "lustre",
        "nfs",
        "nfs4",
        "smb3",
    }
)


class MigrationError(RuntimeError):
    """A migration safety or compatibility boundary failed."""


MigrationAction = Callable[[sqlite3.Connection], Mapping[str, Any] | None]
MigrationValidator = Callable[[sqlite3.Connection], None]
FailureHook = Callable[[str, str], None]
BackupCreator = Callable[[Path, Path], Mapping[str, Any]]
BackupVerifier = Callable[[Path, Path], Mapping[str, Any]]
OriginRecognizer = Callable[[sqlite3.Connection], str]


@dataclass(frozen=True)
class Migration:
    """One immutable, bounded forward migration."""

    migration_id: str
    description: str
    checksum_material: str
    apply: MigrationAction
    validate: MigrationValidator

    def __post_init__(self) -> None:
        if MIGRATION_ID_PATTERN.fullmatch(self.migration_id) is None:
            raise ValueError(f"invalid migration id: {self.migration_id!r}")
        if not self.description.strip():
            raise ValueError("migration description is required")
        if not self.checksum_material:
            raise ValueError("migration checksum material is required")

    @property
    def checksum(self) -> str:
        implementation: dict[str, str] = {}
        for name, callback in (("apply", self.apply), ("validate", self.validate)):
            try:
                implementation[name] = inspect.getsource(callback)
            except (OSError, TypeError):
                implementation[name] = (
                    f"{getattr(callback, '__module__', '')}:"
                    f"{getattr(callback, '__qualname__', repr(callback))}"
                )
        payload = {
            "migration_id": self.migration_id,
            "description": self.description,
            "material": self.checksum_material,
            "implementation": implementation,
        }
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class MigrationRun:
    """Result evidence returned to the application connection boundary."""

    origin: str
    applied: tuple[str, ...]
    already_applied: tuple[str, ...]
    backup: Mapping[str, Any] | None
    schema_fingerprint: str


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def execute_sql_script(
    connection: sqlite3.Connection,
    script: str,
) -> None:
    """Execute a SQL script without sqlite3.executescript's implicit commit."""

    statement = ""
    for line in str(script).splitlines(keepends=True):
        statement += line
        if not sqlite3.complete_statement(statement):
            continue
        candidate = statement.strip()
        statement = ""
        if candidate:
            connection.execute(candidate)

    if statement.strip():
        raise MigrationError("migration SQL ended with an incomplete statement")


def quote_identifier(value: str) -> str:
    if not value or "\x00" in value:
        raise MigrationError("unsafe SQLite identifier")
    return '"' + value.replace('"', '""') + '"'


def application_tables(connection: sqlite3.Connection) -> tuple[str, ...]:
    rows = connection.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' "
        "ORDER BY name"
    ).fetchall()
    return tuple(str(row[0]) for row in rows)


def schema_fingerprint(connection: sqlite3.Connection) -> str:
    rows = connection.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL "
        "ORDER BY type, name, tbl_name"
    ).fetchall()
    payload = [tuple(row) for row in rows]
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def recognize_origin(connection: sqlite3.Connection) -> str:
    """Recognize fresh, ledgered, or supported v0.42-v0.45 databases."""

    tables = set(application_tables(connection))
    if not tables:
        return "fresh"

    if "schema_migrations" in tables:
        return "ledgered-v1"

    required = {
        "snapshots",
        "asset_observations",
        "service_observations",
        "finding_observations",
        "delta_events",
    }
    if required.issubset(tables):
        return "supported-v0.42-v0.45"

    raise MigrationError(
        "unsupported or ambiguous DeltaAegis database schema; "
        "expected a fresh database, a v1 migration ledger, or the "
        "documented v0.42-v0.45 evidence tables"
    )


def _mount_type_for_path(path: Path) -> str | None:
    mountinfo = Path("/proc/self/mountinfo")
    if not mountinfo.is_file():
        return None

    resolved = path.resolve(strict=False)
    best: tuple[int, str] | None = None
    try:
        lines = mountinfo.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None

    for line in lines:
        fields = line.split()
        if "-" not in fields:
            continue
        separator = fields.index("-")
        if separator + 1 >= len(fields) or len(fields) < 5:
            continue
        mount_point = Path(
            fields[4]
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\134", "\\")
        )
        try:
            resolved.relative_to(mount_point)
        except ValueError:
            continue
        candidate = (len(mount_point.parts), fields[separator + 1].lower())
        if best is None or candidate[0] > best[0]:
            best = candidate
    return best[1] if best else None


def assert_local_database_path(path: Path) -> Path:
    expanded = Path(path).expanduser()
    absolute = Path(os.path.abspath(os.fspath(expanded)))
    if os.path.lexists(absolute) and absolute.is_symlink():
        raise MigrationError(f"active database must not be a symlink: {absolute}")
    filesystem = _mount_type_for_path(absolute.parent)
    if filesystem in KNOWN_REMOTE_FILESYSTEMS:
        raise MigrationError(
            "active DeltaAegis databases require a local filesystem; "
            f"found {filesystem} for {absolute}"
        )
    return absolute


def _table_columns(
    connection: sqlite3.Connection,
    table: str,
) -> tuple[str, ...]:
    rows = connection.execute(
        f"PRAGMA table_info({quote_identifier(table)})"
    ).fetchall()
    excluded = PROTECTED_FIELD_EXCLUSIONS.get(table, frozenset())
    return tuple(str(row[1]) for row in rows if str(row[1]) not in excluded)


def _canonical_sqlite_value(value: Any) -> Any:
    if value is None:
        return ["null", None]
    if isinstance(value, bytes):
        return ["blob", value.hex()]
    if isinstance(value, bool):
        return ["integer", int(value)]
    if isinstance(value, int):
        return ["integer", value]
    if isinstance(value, float):
        return ["real", value.hex()]
    return ["text", str(value)]


def protected_history_fingerprints(
    connection: sqlite3.Connection,
    *,
    reference: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    available = set(application_tables(connection))
    evidence: dict[str, dict[str, Any]] = {}
    for table in PROTECTED_TABLES:
        if table not in available:
            continue
        if reference is not None and table in reference:
            columns = tuple(reference[table].get("columns") or ())
            actual_columns = {
                str(row[1])
                for row in connection.execute(
                    f"PRAGMA table_info({quote_identifier(table)})"
                ).fetchall()
            }
            missing_columns = sorted(set(columns) - actual_columns)
            if missing_columns:
                raise MigrationError(
                    f"protected columns disappeared from {table}: "
                    + ", ".join(missing_columns)
                )
        else:
            columns = _table_columns(connection, table)
        if not columns:
            continue
        quoted = ", ".join(quote_identifier(column) for column in columns)
        order = quoted
        digest = hashlib.sha256()
        count = 0
        for row in connection.execute(
            f"SELECT {quoted} FROM {quote_identifier(table)} ORDER BY {order}"
        ):
            encoded = json.dumps(
                [_canonical_sqlite_value(value) for value in row],
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
            count += 1
        evidence[table] = {
            "columns": columns,
            "rows": count,
            "sha256": digest.hexdigest(),
        }
    return evidence


def verify_protected_history(
    before: Mapping[str, Mapping[str, Any]],
    after: Mapping[str, Mapping[str, Any]],
) -> None:
    for table, expected in before.items():
        actual = after.get(table)
        if actual is None:
            raise MigrationError(f"protected table disappeared: {table}")
        if tuple(actual.get("columns") or ()) != tuple(expected.get("columns") or ()):
            raise MigrationError(f"protected columns changed unexpectedly: {table}")
        if int(actual.get("rows") or 0) != int(expected.get("rows") or 0):
            raise MigrationError(f"protected row count changed unexpectedly: {table}")
        if str(actual.get("sha256") or "") != str(expected.get("sha256") or ""):
            raise MigrationError(f"protected history changed unexpectedly: {table}")


def _recorded_migrations(
    connection: sqlite3.Connection,
) -> dict[str, sqlite3.Row]:
    if "schema_migrations" not in set(application_tables(connection)):
        return {}
    return {
        str(row["migration_id"]): row
        for row in connection.execute(
            "SELECT migration_id, checksum, applied_at, application_version, "
            "origin, outcome_json FROM schema_migrations ORDER BY migration_id"
        ).fetchall()
    }


def validate_ledger(
    recorded: Mapping[str, sqlite3.Row],
    migrations: Sequence[Migration],
) -> tuple[str, ...]:
    definitions = {migration.migration_id: migration for migration in migrations}
    unknown = sorted(set(recorded) - set(definitions))
    if unknown:
        raise MigrationError(
            "database contains migrations unknown to this application: "
            + ", ".join(unknown)
        )

    applied: list[str] = []
    seen_gap = False
    previous_schema_after: str | None = None
    for migration in migrations:
        row = recorded.get(migration.migration_id)
        if row is None:
            seen_gap = True
            continue
        if seen_gap:
            raise MigrationError(
                "migration ledger is non-contiguous at " + migration.migration_id
            )
        checksum = str(row["checksum"] or "").lower()
        if CHECKSUM_PATTERN.fullmatch(checksum) is None:
            raise MigrationError(
                f"recorded migration checksum is malformed: {migration.migration_id}"
            )
        if not secrets.compare_digest(checksum, migration.checksum):
            raise MigrationError(
                "recorded migration bytes changed for " + migration.migration_id
            )
        try:
            outcome = json.loads(str(row["outcome_json"] or ""))
        except json.JSONDecodeError as exc:
            raise MigrationError(
                f"recorded migration outcome is invalid: {migration.migration_id}"
            ) from exc
        if not isinstance(outcome, dict):
            raise MigrationError(
                f"recorded migration outcome is invalid: {migration.migration_id}"
            )
        if str(row["application_version"] or "").strip() == "":
            raise MigrationError(
                f"recorded application version is missing: {migration.migration_id}"
            )
        if str(row["origin"] or "").strip() == "":
            raise MigrationError(
                f"recorded migration origin is missing: {migration.migration_id}"
            )
        applied_at = str(row["applied_at"] or "").strip()
        try:
            parsed_applied_at = datetime.fromisoformat(
                applied_at.replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise MigrationError(
                f"recorded migration timestamp is invalid: {migration.migration_id}"
            ) from exc
        if parsed_applied_at.tzinfo is None:
            raise MigrationError(
                f"recorded migration timestamp lacks a timezone: {migration.migration_id}"
            )
        if outcome.get("ledger_schema_version") != MIGRATION_LEDGER_SCHEMA_VERSION:
            raise MigrationError(
                f"recorded migration outcome version is invalid: {migration.migration_id}"
            )
        if outcome.get("description") != migration.description:
            raise MigrationError(
                f"recorded migration description changed: {migration.migration_id}"
            )
        fingerprints: dict[str, str] = {}
        for fingerprint_name in ("schema_before", "schema_after"):
            fingerprint = str(outcome.get(fingerprint_name) or "").lower()
            if CHECKSUM_PATTERN.fullmatch(fingerprint) is None:
                raise MigrationError(
                    f"recorded {fingerprint_name} is invalid: {migration.migration_id}"
                )
            fingerprints[fingerprint_name] = fingerprint
        if (
            previous_schema_after is not None
            and fingerprints["schema_before"] != previous_schema_after
        ):
            raise MigrationError(
                "migration ledger schema chain is inconsistent at "
                + migration.migration_id
            )
        if not isinstance(outcome.get("action"), dict):
            raise MigrationError(
                f"recorded migration action evidence is invalid: {migration.migration_id}"
            )
        previous_schema_after = fingerprints["schema_after"]
        applied.append(migration.migration_id)
    return tuple(applied)


def _verify_ledger_schema_state(
    connection: sqlite3.Connection,
    recorded: Mapping[str, sqlite3.Row],
    migrations: Sequence[Migration],
) -> None:
    """Bind the latest durable ledger outcome to the live SQLite schema."""

    if not recorded:
        return
    latest = migrations[len(recorded) - 1]
    row = recorded[latest.migration_id]
    outcome = json.loads(str(row["outcome_json"]))
    expected = str(outcome["schema_after"]).lower()
    actual = schema_fingerprint(connection)
    if not secrets.compare_digest(actual, expected):
        raise MigrationError(
            "current database schema differs from the latest migration outcome"
        )


def _verify_database_invariants(connection: sqlite3.Connection) -> None:
    foreign = connection.execute("PRAGMA foreign_key_check").fetchall()
    if foreign:
        raise MigrationError(
            "migration introduced foreign-key violations: "
            + json.dumps([list(row) for row in foreign[:20]])
        )
    integrity = [
        str(row[0]).strip().lower()
        for row in connection.execute("PRAGMA integrity_check").fetchall()
    ]
    if integrity != ["ok"]:
        raise MigrationError(
            "migration integrity check failed: " + "; ".join(integrity)
        )


def default_backup_destination(database: Path, backup_root: Path) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    suffix = secrets.token_hex(4)
    return backup_root / (
        f"deltaaegis-pre-migration-{timestamp}-{suffix}-{database.name}"
    )


def _verified_recorded_backup(
    recorded: Mapping[str, sqlite3.Row],
    migrations: Sequence[Migration],
    verify_backup: BackupVerifier,
) -> dict[str, Any]:
    """Verify and return the original backup for a partially applied upgrade."""

    first = recorded.get(migrations[0].migration_id)
    if first is None:
        raise MigrationError(
            "partial migration ledger does not contain the first migration"
        )
    try:
        outcome = json.loads(str(first["outcome_json"] or ""))
    except json.JSONDecodeError as exc:
        raise MigrationError("first migration backup evidence is invalid") from exc
    reference = outcome.get("pre_migration_backup")
    if not isinstance(reference, dict):
        raise MigrationError(
            "partial legacy migration ledger lacks pre-migration backup evidence"
        )
    backup_path = str(reference.get("backup_path") or "").strip()
    manifest_path = str(reference.get("manifest_path") or "").strip()
    if not backup_path or not manifest_path:
        raise MigrationError(
            "partial legacy migration ledger has incomplete backup paths"
        )
    verified = dict(verify_backup(Path(backup_path), Path(manifest_path)))
    for key in (
        "backup_path",
        "manifest_path",
        "backup_sha256",
        "schema_fingerprint",
        "logical_fingerprint",
        "integrity_status",
    ):
        expected = reference.get(key)
        actual = verified.get(key)
        if expected is not None and str(actual) != str(expected):
            raise MigrationError(
                f"recorded pre-migration backup evidence changed: {key}"
            )
    return verified


def run_migrations(
    connection: sqlite3.Connection,
    *,
    database_path: Path,
    application_version: str,
    migrations: Sequence[Migration],
    backup_root: Path,
    create_backup: BackupCreator,
    verify_backup: BackupVerifier,
    failure_hook: FailureHook | None = None,
    origin_recognizer: OriginRecognizer | None = None,
) -> MigrationRun:
    """Validate and apply pending migrations to an already-open connection."""

    database = assert_local_database_path(database_path)
    if not migrations:
        raise MigrationError("at least one migration definition is required")
    ids = [migration.migration_id for migration in migrations]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise MigrationError("migration definitions must have unique ordered ids")

    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    if int(connection.execute("PRAGMA foreign_keys").fetchone()[0]) != 1:
        raise MigrationError("SQLite foreign-key enforcement could not be enabled")

    # Serialize origin recognition, ledger inspection, backup, and the first
    # migration under one write reservation.  Without this boundary two
    # concurrent starters could both observe the same pending ledger and race
    # to apply it.
    try:
        connection.execute("BEGIN IMMEDIATE")
        origin = (origin_recognizer or recognize_origin)(connection)
        recorded = _recorded_migrations(connection)
        already_applied = validate_ledger(recorded, migrations)
        _verify_ledger_schema_state(connection, recorded, migrations)
        if recorded:
            recorded_origins = {
                str(row["origin"] or "").strip() for row in recorded.values()
            }
            if len(recorded_origins) != 1:
                raise MigrationError("migration ledger contains inconsistent origins")
            recorded_origin = next(iter(recorded_origins))
            if origin == "ledgered-v1":
                origin = recorded_origin
            elif origin != recorded_origin:
                raise MigrationError(
                    "recognized database origin differs from its migration ledger"
                )
        elif origin == "ledgered-v1":
            raise MigrationError(
                "database contains an empty migration ledger and has no provable origin"
            )
        pending = [
            migration
            for migration in migrations
            if migration.migration_id not in recorded
        ]
        if not pending:
            for migration in migrations:
                migration.validate(connection)
            _verify_database_invariants(connection)
            result = MigrationRun(
                origin=origin,
                applied=(),
                already_applied=already_applied,
                backup=None,
                schema_fingerprint=schema_fingerprint(connection),
            )
            connection.commit()
            return result

        before_history = protected_history_fingerprints(connection)
    except Exception:
        connection.rollback()
        raise
    initial_recorded = dict(recorded)
    backup: Mapping[str, Any] | None = None
    applied: list[str] = []
    record_backup_migration_id: str | None = None

    try:
        if origin != "fresh":
            if initial_recorded:
                # A crash or concurrent starter may observe a partially
                # applied sequence. Reuse and re-verify the one true backup
                # recorded by migration 0001; never back up an intermediate
                # schema and mislabel it as pre-migration recovery evidence.
                backup = _verified_recorded_backup(
                    initial_recorded,
                    migrations,
                    verify_backup,
                )
            else:
                # Hold the initial write reservation from before backup
                # creation through the first migration commit. This prevents
                # another writer from changing the source between recovery
                # capture and the first schema mutation.
                resolved_backup_root = (
                    Path(backup_root).expanduser().resolve(strict=False)
                )
                resolved_backup_root.mkdir(
                    parents=True,
                    exist_ok=True,
                    mode=0o700,
                )
                destination = default_backup_destination(
                    database,
                    resolved_backup_root,
                )
                backup_result = dict(create_backup(database, destination))
                backup = dict(
                    verify_backup(
                        Path(str(backup_result["backup_path"])),
                        Path(str(backup_result["manifest_path"])),
                    )
                )
                record_backup_migration_id = pending[0].migration_id
                if failure_hook:
                    failure_hook("after_backup", pending[0].migration_id)
    except Exception:
        connection.rollback()
        raise

    for migration in migrations:
        try:
            if not connection.in_transaction:
                connection.execute("BEGIN IMMEDIATE")
            # Another starter may have committed while this connection was
            # between per-migration transactions. Refresh under the new write
            # reservation and skip work that is now durably complete.
            current_recorded = _recorded_migrations(connection)
            validate_ledger(current_recorded, migrations)
            _verify_ledger_schema_state(
                connection,
                current_recorded,
                migrations,
            )
            if migration.migration_id in current_recorded:
                connection.commit()
                continue
            expected_next = migrations[len(current_recorded)].migration_id
            if migration.migration_id != expected_next:
                connection.commit()
                continue
            # Ledger creation is part of the same transaction as the first
            # migration, so an interruption can never leave an empty ledger
            # that obscures the database's supported origin.
            prior_schema = schema_fingerprint(connection)
            execute_sql_script(connection, SCHEMA_MIGRATIONS_SQL)
            if failure_hook:
                failure_hook("before_apply", migration.migration_id)
            action_evidence = dict(migration.apply(connection) or {})
            if failure_hook:
                failure_hook("after_apply", migration.migration_id)
            migration.validate(connection)
            _verify_database_invariants(connection)
            current_history = protected_history_fingerprints(
                connection,
                reference=before_history,
            )
            verify_protected_history(before_history, current_history)
            current_schema = schema_fingerprint(connection)
            outcome = {
                "ledger_schema_version": MIGRATION_LEDGER_SCHEMA_VERSION,
                "description": migration.description,
                "schema_before": prior_schema,
                "schema_after": current_schema,
                "protected_tables": len(current_history),
                "action": action_evidence,
            }
            if (
                backup is not None
                and migration.migration_id == record_backup_migration_id
            ):
                outcome["pre_migration_backup"] = {
                    key: backup.get(key)
                    for key in (
                        "backup_path",
                        "manifest_path",
                        "backup_sha256",
                        "schema_fingerprint",
                        "logical_fingerprint",
                        "integrity_status",
                    )
                }
            if failure_hook:
                failure_hook("before_ledger", migration.migration_id)
            connection.execute(
                "INSERT INTO schema_migrations ("
                "migration_id, checksum, applied_at, application_version, "
                "origin, outcome_json) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    migration.migration_id,
                    migration.checksum,
                    utc_now(),
                    str(application_version),
                    origin,
                    json.dumps(outcome, sort_keys=True, separators=(",", ":")),
                ),
            )
            if failure_hook:
                failure_hook("before_commit", migration.migration_id)
            connection.commit()
            applied.append(migration.migration_id)
            if failure_hook:
                failure_hook("after_commit", migration.migration_id)
        except Exception:
            connection.rollback()
            raise

    final_recorded = _recorded_migrations(connection)
    validate_ledger(final_recorded, migrations)
    _verify_ledger_schema_state(connection, final_recorded, migrations)
    final_history = protected_history_fingerprints(
        connection,
        reference=before_history,
    )
    verify_protected_history(before_history, final_history)
    _verify_database_invariants(connection)
    return MigrationRun(
        origin=origin,
        applied=tuple(applied),
        already_applied=already_applied,
        backup=backup,
        schema_fingerprint=schema_fingerprint(connection),
    )


__all__ = (
    "MIGRATION_LEDGER_SCHEMA_VERSION",
    "Migration",
    "MigrationError",
    "MigrationRun",
    "PROTECTED_TABLES",
    "SCHEMA_MIGRATIONS_SQL",
    "application_tables",
    "assert_local_database_path",
    "execute_sql_script",
    "protected_history_fingerprints",
    "recognize_origin",
    "run_migrations",
    "schema_fingerprint",
    "validate_ledger",
    "verify_protected_history",
)
