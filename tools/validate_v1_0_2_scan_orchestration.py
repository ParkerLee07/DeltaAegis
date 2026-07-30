#!/usr/bin/env python3
from __future__ import annotations

import inspect
import io
import json
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import deltaaegis
from deltaaegis_core import jobs, migrations


RELEASED_MIGRATION_CHECKSUMS = {
    "0001-v045-foundation": (
        "cc26cd8690f89690c7a90c30c175990e05f92360f90aca1efaba5314187a3879"
    ),
    "0002-v045-telemetry-trust": (
        "8e6c0ebb1a3d47ea9668580ab37d0a2d8d9ec5d615eb46161d8c2bb7614bafc0"
    ),
    "0003-v1-api-security": (
        "70f88e29aaeae839a3f86fd5701dbbc13c320311ba9f4d9dd601f33c52b2598e"
    ),
    "0004-v1-sensor-scope-identity": (
        "877792f3ba91d735a6499b164208d781b68276361f16b6731f547f76810edf17"
    ),
    "0005-v1-deterministic-detection": (
        "af7b55abd79f3b279c844451ee44e0e2cc433f74a2358756d2737c5466f8a214"
    ),
}
NEW_MIGRATION_ID = "0006-v1.0.2-scan-orchestration"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"[FAIL] {message}")


def initialized_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    for migration in deltaaegis.deltaaegis_schema_migrations():
        migration.apply(connection)
        migration.validate(connection)
    return connection


def test_migration_immutability_and_v1_0_1_upgrade() -> None:
    definitions = deltaaegis.deltaaegis_schema_migrations()
    ids = [migration.migration_id for migration in definitions]
    require(
        ids == [*RELEASED_MIGRATION_CHECKSUMS, NEW_MIGRATION_ID],
        f"unexpected migration sequence: {ids}",
    )
    actual = {migration.migration_id: migration.checksum for migration in definitions}
    for migration_id, checksum in RELEASED_MIGRATION_CHECKSUMS.items():
        require(
            actual.get(migration_id) == checksum,
            f"released migration bytes changed: {migration_id}",
        )

    with tempfile.TemporaryDirectory(prefix="deltaaegis-v1.0.2-upgrade-") as temporary:
        root = Path(temporary)
        archive = subprocess.run(
            ["git", "archive", "--format=tar", "v1.0.1"],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
        require(
            archive.returncode == 0,
            "could not export the immutable v1.0.1 source tree: "
            + archive.stderr.decode("utf-8", errors="replace"),
        )
        source_root = root / "v1.0.1"
        source_root.mkdir()
        with tarfile.open(fileobj=io.BytesIO(archive.stdout), mode="r:") as handle:
            members = handle.getmembers()
            for member in members:
                path = PurePosixPath(member.name)
                require(
                    not path.is_absolute() and ".." not in path.parts,
                    f"unsafe path in v1.0.1 source archive: {member.name}",
                )
                require(
                    not member.issym() and not member.islnk(),
                    f"unexpected link in v1.0.1 source archive: {member.name}",
                )
            extract_options = {}
            if "filter" in inspect.signature(handle.extractall).parameters:
                extract_options["filter"] = "data"
            handle.extractall(
                source_root,
                members=members,
                **extract_options,
            )

        database = root / "upgrade.db"
        materialize = subprocess.run(
            [
                sys.executable,
                str(source_root / "deltaaegis.py"),
                "--db",
                str(database),
                "summary",
            ],
            cwd=source_root,
            capture_output=True,
            text=True,
            check=False,
        )
        require(
            materialize.returncode == 0,
            "v1.0.1 could not materialize its database: " + materialize.stderr,
        )

        before = sqlite3.connect(database)
        before.row_factory = sqlite3.Row
        try:
            before_rows = {
                str(row["migration_id"]): str(row["checksum"])
                for row in before.execute(
                    "SELECT migration_id, checksum FROM schema_migrations"
                )
            }
            before_schema = migrations.schema_fingerprint(before)
        finally:
            before.close()
        require(
            before_rows == RELEASED_MIGRATION_CHECKSUMS,
            "v1.0.1 migration ledger no longer matches the pinned checksums",
        )

        upgraded = deltaaegis.connect(database)
        try:
            after_rows = {
                str(row["migration_id"]): str(row["checksum"])
                for row in upgraded.execute(
                    "SELECT migration_id, checksum FROM schema_migrations"
                )
            }
            after_schema = migrations.schema_fingerprint(upgraded)
            index = upgraded.execute(
                "SELECT 1 FROM sqlite_master "
                "WHERE type='index' AND name='uq_scan_jobs_active_workspace'"
            ).fetchone()
        finally:
            upgraded.close()

        require(
            {key: after_rows.get(key) for key in RELEASED_MIGRATION_CHECKSUMS}
            == RELEASED_MIGRATION_CHECKSUMS,
            "v1.0.2 altered a released migration ledger checksum",
        )
        require(NEW_MIGRATION_ID in after_rows, "v1.0.2 additive migration was not recorded")
        require(index is not None, "v1.0.1 upgrade did not create the workspace index")
        require(before_schema != after_schema, "v1.0.2 upgrade did not change the schema")

        fresh = deltaaegis.connect(root / "fresh.db")
        try:
            fresh_schema = migrations.schema_fingerprint(fresh)
        finally:
            fresh.close()
        require(
            fresh_schema == after_schema,
            "fresh v1.0.2 and upgraded v1.0.1 schemas did not converge",
        )


def test_duplicate_upgrade_fails_closed() -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    definitions = deltaaegis.deltaaegis_schema_migrations()
    for migration in definitions[:-1]:
        migration.apply(connection)
        migration.validate(connection)

    now = "2026-07-29T00:00:00Z"
    for suffix in ("a", "b"):
        connection.execute(
            """
            INSERT INTO scan_jobs (
                job_id, target, network_scope, status, created_at, updated_at,
                netsniper_path, runs_dir
            ) VALUES (?, ?, ?, 'RUNNING', ?, ?, ?, ?)
            """,
            (
                f"duplicate-{suffix}",
                "192.168.4.0/24",
                "192.168.4.0/24",
                now,
                now,
                "/opt/NetSniper/netsniper.sh",
                "/opt/NetSniper/runs",
            ),
        )
    try:
        definitions[-1].apply(connection)
    except migrations.MigrationError as exc:
        require(
            "active duplicate jobs exist" in str(exc),
            f"unexpected duplicate-workspace failure: {exc}",
        )
    else:
        raise SystemExit(
            "[FAIL] additive migration accepted duplicate active workspaces"
        )
    index = connection.execute(
        "SELECT 1 FROM sqlite_master "
        "WHERE type='index' AND name='uq_scan_jobs_active_workspace'"
    ).fetchone()
    require(index is None, "failed migration left a partial workspace index")
    connection.close()


def test_schema_and_workspace_lock() -> None:
    connection = initialized_connection()
    index = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='index' AND name='uq_scan_jobs_active_workspace'"
    ).fetchone()
    require(index is not None, "active-workspace unique index is missing")
    require("WHERE status IN ('QUEUED', 'RUNNING')" in str(index[0]), "active-workspace index is not partial")

    first = jobs.create_scan_job(
        connection,
        "192.168.4.0/24",
        Path("/opt/NetSniper/netsniper.sh"),
        Path("/opt/NetSniper/runs"),
    )
    try:
        jobs.create_scan_job(
            connection,
            "192.168.5.0/24",
            Path("/opt/NetSniper/netsniper.sh"),
            Path("/opt/NetSniper/runs"),
        )
    except sqlite3.IntegrityError:
        pass
    else:
        raise SystemExit("[FAIL] second active job in one workspace was accepted")

    jobs.update_scan_job(connection, first["job_id"], status="COMPLETED")
    second = jobs.create_scan_job(
        connection,
        "192.168.5.0/24",
        Path("/opt/NetSniper/netsniper.sh"),
        Path("/opt/NetSniper/runs"),
    )
    require(bool(second["job_id"]), "terminal job did not release workspace")
    connection.close()


def test_schedule_phase_balancing() -> None:
    connection = initialized_connection()
    first = jobs.create_scan_schedule(
        connection,
        "Subnet 4",
        "192.168.4.0/24",
        cadence_minutes=60,
        enabled=True,
    )
    second = jobs.create_scan_schedule(
        connection,
        "Subnet 5",
        "192.168.5.0/24",
        cadence_minutes=60,
        enabled=True,
    )
    rows = connection.execute(
        "SELECT schedule_id, next_run_at FROM scan_schedules ORDER BY next_run_at"
    ).fetchall()
    require(len(rows) == 2, "schedule phase test did not create two rows")
    times = [datetime.fromisoformat(str(row["next_run_at"])) for row in rows]
    gap = (times[1] - times[0]).total_seconds() / 60
    require(29 <= gap <= 31, f"hourly schedules were not balanced 30 minutes apart: {gap}")

    jobs.set_scan_schedule_enabled(connection, first["schedule_id"], False)
    jobs.set_scan_schedule_enabled(connection, second["schedule_id"], False)
    jobs.set_scan_schedule_enabled(connection, first["schedule_id"], True)
    jobs.set_scan_schedule_enabled(connection, second["schedule_id"], True)
    rows = connection.execute(
        "SELECT next_run_at FROM scan_schedules WHERE enabled=1 ORDER BY next_run_at"
    ).fetchall()
    times = [datetime.fromisoformat(str(row[0])) for row in rows]
    gap = (times[1] - times[0]).total_seconds() / 60
    require(29 <= gap <= 31, f"re-enabled schedules were not balanced: {gap}")

    before = (datetime.now(timezone.utc) - timedelta(minutes=1)).replace(microsecond=0).isoformat()
    connection.execute(
        "UPDATE scan_schedules SET next_run_at=? WHERE schedule_id=?",
        (before, first["schedule_id"]),
    )
    jobs.update_scan_schedule_after_job(
        connection,
        first["schedule_id"],
        60,
        {"job_id": "fixture-job", "status": "COMPLETED", "message": "complete"},
    )
    after = connection.execute(
        "SELECT next_run_at FROM scan_schedules WHERE schedule_id=?",
        (first["schedule_id"],),
    ).fetchone()[0]
    delta_minutes = (
        datetime.fromisoformat(str(after)) - datetime.fromisoformat(str(before))
    ).total_seconds() / 60
    require(delta_minutes >= 60, "schedule completion did not advance its existing phase")
    connection.close()


def test_trusted_manifest_followup() -> None:
    connection = initialized_connection()
    with tempfile.TemporaryDirectory(prefix="deltaaegis-v1.0.2-followup-") as temporary:
        root = Path(temporary)
        source = root / "source" / "manifest.json"
        trusted = root / "trusted" / "manifest.json"
        executable = root / "trueaegis.py"
        source.parent.mkdir(parents=True)
        trusted.parent.mkdir(parents=True)
        manifest = {"schema_version": "netsniper-run-v3", "scan_id": "scan-v2-2"}
        source.write_text(json.dumps(manifest), encoding="utf-8")
        trusted.write_text(json.dumps(manifest), encoding="utf-8")
        executable.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        executable.chmod(0o755)

        connection.execute(
            """
            INSERT INTO snapshots (
                scan_id, manifest_path, target, network_scope, scanner_version,
                scan_profile, created_at, imported_at, bundle_status,
                quality_status, quality_reason, xml_exit_status, hosts_up,
                hosts_down, hosts_total, mac_backed_assets, identity_coverage,
                is_accepted_baseline
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "scan-v2-2", str(trusted), "192.168.4.0/24", "192.168.4.0/24",
                "v2.2.0", "balanced", "2026-07-29T00:00:00Z",
                "2026-07-29T00:01:00Z", "COMPLETE", "ACCEPTED", "ok",
                "success", 1, 0, 1, 1, 1.0, 1,
            ),
        )
        schedule = {
            "schedule_id": "fixture-schedule",
            "run_trueaegis_after_ingest": True,
            "auto_ingest": True,
            "network_scope": "192.168.4.0/24",
        }
        job = {
            "job_id": "fixture-job",
            "status": "COMPLETED",
            "auto_ingest": True,
            "network_scope": "192.168.4.0/24",
            "manifest_path": str(source),
            "status_json": {
                "scan_id": "scan-v2-2",
                "manifest_path": str(source),
                "auto_ingest": {
                    "performed": True,
                    "accepted": True,
                    "quality_status": "ACCEPTED",
                    "scan_id": "scan-v2-2",
                },
            },
        }
        plan = deltaaegis.trueaegis_followup_plan_for_schedule(
            connection, schedule, job, executable
        )
        require(plan["outcome"] == "eligible", f"TrueAegis plan not eligible: {plan}")
        require(plan["manifest_path"] == str(trusted), "TrueAegis did not use trusted manifest")
        require(plan.get("source_manifest_path") == str(source), "source manifest audit path missing")

        trusted.write_text(json.dumps({"scan_id": "different"}), encoding="utf-8")
        plan = deltaaegis.trueaegis_followup_plan_for_schedule(
            connection, schedule, job, executable
        )
        require(
            plan["outcome"] == "ingest_manifest_identity_mismatch",
            "mismatched trusted manifest identity did not fail closed",
        )
    connection.close()


def test_candidate_metadata() -> None:
    runtime = (ROOT / "deltaaegis.py").read_text(encoding="utf-8")
    api_source = (ROOT / "deltaaegis_core/api_v1.py").read_text(encoding="utf-8")
    troubleshooter = (ROOT / "tools/deltaaegis_troubleshooter.py").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    openapi = json.loads((ROOT / "contracts/v1/openapi.json").read_text(encoding="utf-8"))
    require('DELTAAEGIS_VERSION = "1.0.2"' in runtime, "runtime version is not 1.0.2")
    require("DeltaAegis v1.0.2 maintenance candidate" in runtime, "runtime candidate header is missing")
    require('<span>Build</span><span>v1.0.2</span>' in runtime, "dashboard Build pill is not v1.0.2")
    require('TOOL_VERSION = "1.0.2"' in troubleshooter, "troubleshooter version is not 1.0.2")
    require('"version": "1.0.2"' in api_source, "runtime OpenAPI version is not 1.0.2")
    require((openapi.get("info") or {}).get("version") == "1.0.2", "tracked OpenAPI version is not 1.0.2")
    require("## Development Candidate — v1.0.2" in readme, "README candidate marker is missing")
    require(changelog.startswith("## v1.0.2 - Unreleased\n"), "CHANGELOG does not begin with v1.0.2")
    require((ROOT / "docs/v1.0.2-scan-orchestration.md").is_file(), "v1.0.2 maintenance documentation is missing")
    require("hotfix/v1.0.2-scan-orchestration" in ci, "CI candidate branch is missing")
    require("validate_v1_0_2_candidate_all.sh" in ci, "CI candidate gate is missing")


def main() -> int:
    test_candidate_metadata()
    print("[PASS] v1.0.2 candidate metadata and CI wiring")
    test_migration_immutability_and_v1_0_1_upgrade()
    print("[PASS] immutable migrations and v1.0.1 additive upgrade")
    test_duplicate_upgrade_fails_closed()
    print("[PASS] duplicate active-workspace upgrades fail closed")
    test_schema_and_workspace_lock()
    print("[PASS] database-enforced NetSniper workspace serialization")
    test_schedule_phase_balancing()
    print("[PASS] automatic schedule phase balancing and preservation")
    test_trusted_manifest_followup()
    print("[PASS] trusted-manifest TrueAegis follow-up correlation")
    print("[PASS] DeltaAegis v1.0.2 scan orchestration validator complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
