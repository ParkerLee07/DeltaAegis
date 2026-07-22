#!/usr/bin/env python3
"""Measure the v1 Stage 5 release thresholds on a synthetic local fixture."""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import deltaaegis  # noqa: E402
from deltaaegis_core import identity, operations  # noqa: E402


ASSET_COUNT = 240
REPETITIONS = 5


def elapsed_ms(callable_):
    started = time.perf_counter()
    value = callable_()
    return (time.perf_counter() - started) * 1000.0, value


def median_ms(callable_, repetitions: int = REPETITIONS) -> float:
    values = [elapsed_ms(callable_)[0] for _ in range(repetitions)]
    return round(statistics.median(values), 3)


def cold_import_ms() -> float:
    code = (
        "import sys; "
        f"sys.path.insert(0, {str(ROOT)!r}); "
        "import deltaaegis; "
        "assert deltaaegis.DELTAAEGIS_VERSION == '1.0.0-stage35'"
    )

    def run() -> None:
        completed = subprocess.run(
            [sys.executable, "-I", "-c", code],
            cwd="/",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if completed.returncode:
            raise RuntimeError(f"cold import failed: {completed.stderr.strip()}")

    return median_ms(run, repetitions=3)


def synthetic_assets() -> dict[str, SimpleNamespace]:
    assets: dict[str, SimpleNamespace] = {}
    for index in range(ASSET_COUNT):
        octet3, octet4 = divmod(index + 1, 254)
        ip_address = f"10.200.{octet3}.{octet4 + 1}"
        asset_key = f"mac:02:00:00:{index // 65536:02x}:{(index // 256) % 256:02x}:{index % 256:02x}"
        assets[asset_key] = SimpleNamespace(
            asset_key=asset_key,
            identity_class="LOCAL_MAC",
            ip_address=ip_address,
            mac_address=asset_key.removeprefix("mac:").upper(),
            hostname=f"synthetic-{index:03d}",
            vendor="DeltaAegis synthetic fixture",
            score=index % 10,
            services=[
                SimpleNamespace(
                    protocol="tcp",
                    port=22,
                    state="open",
                    service_name="ssh",
                    product="fixture",
                    version="1",
                ),
                SimpleNamespace(
                    protocol="tcp",
                    port=443,
                    state="open",
                    service_name="https",
                    product="fixture",
                    version="1",
                ),
                SimpleNamespace(
                    protocol="udp",
                    port=161,
                    state="open",
                    service_name="snmp",
                    product="fixture",
                    version="1",
                ),
            ],
            findings=[],
        )
    return assets


def seed_fixture(database: Path) -> tuple[object, str]:
    connection = deltaaegis.connect(database)
    scope = identity.ensure_scope(
        connection,
        sensor_id=identity.DEFAULT_SENSOR_ID,
        network_scope="10.200.0.0/16",
        allow_default_create=True,
    )
    evidence_identity = {
        "sensor_id": identity.DEFAULT_SENSOR_ID,
        "scope_id": scope["scope_id"],
        "network_scope": scope["network_scope"],
        "source_scan_id": "v1-stage5-performance-001",
        "internal_scan_id": "v1-stage5-performance-001",
        "bundle_digest": "f" * 64,
    }
    snapshot = SimpleNamespace(
        created_at="2026-07-21T19:00:00+00:00",
        assets=synthetic_assets(),
    )
    identity.apply_snapshot_projection(
        connection,
        snapshot=snapshot,
        decision={
            "decision_id": "performance-decision-001",
            "current_state": "ACCEPTED",
        },
        identity=evidence_identity,
    )
    connection.commit()
    return connection, str(scope["scope_id"])


def measure(root: Path) -> dict[str, object]:
    database = root / "performance.db"
    schema_times = []
    for index in range(3):
        path = root / f"schema-{index}.db"
        elapsed, connection = elapsed_ms(lambda path=path: deltaaegis.connect(path))
        connection.close()
        schema_times.append(elapsed)

    connection, scope_id = seed_fixture(database)
    try:
        summary_ms = median_ms(lambda: deltaaegis.dashboard_summary_payload(connection))
        assets_ms = median_ms(
            lambda: identity.list_assets(
                connection,
                scope_id=scope_id,
                limit=ASSET_COUNT,
            )
        )
        readiness_ms = median_ms(
            lambda: operations.readiness_report(
                connection,
                database_path=database,
            )
        )
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.commit()
    finally:
        connection.close()

    reports = root / "reports"
    started = time.perf_counter()
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "deltaaegis.py"),
            "--db",
            str(database),
            "--reports-dir",
            str(reports),
            "report",
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    report_ms = (time.perf_counter() - started) * 1000.0
    if completed.returncode:
        raise RuntimeError(f"report generation failed: {completed.stderr.strip()}")

    sample = {
        "cold_import": cold_import_ms(),
        "fresh_schema_init": round(statistics.median(schema_times), 3),
        "summary_payload": summary_ms,
        "assets_payload": assets_ms,
        "report_generation": round(report_ms, 3),
        "database_bytes_per_asset": round(database.stat().st_size / ASSET_COUNT, 3),
        "readiness": readiness_ms,
    }
    assessment = operations.validate_performance_sample(sample)
    return {
        "schema_version": "deltaaegis-v1-performance-evidence-v1",
        "fixture": {
            "assets": ASSET_COUNT,
            "services_per_asset": 3,
            "network_scope": "10.200.0.0/16 synthetic only",
            "operator_data_used": False,
        },
        "measurements": sample,
        "assessment": assessment,
        "targets": operations.PERFORMANCE_TARGETS,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="deltaaegis-v1-performance-") as temporary:
        payload = measure(Path(temporary))
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if payload["assessment"]["status"] != "PASS":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
