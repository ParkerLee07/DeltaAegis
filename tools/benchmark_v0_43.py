#!/usr/bin/env python3
"""Reproducible synthetic performance baseline for DeltaAegis v0.43."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, Callable


SCHEMA_VERSION = "deltaaegis-performance-baseline-v1"
JSON_PATH = Path("docs/performance-baseline.json")
MARKDOWN_PATH = Path("docs/performance-baseline.md")


def repository_root(value: str | None = None) -> Path:
    root = Path(value).expanduser() if value else Path(__file__).resolve().parents[1]
    root = root.resolve()
    if not (root / "deltaaegis.py").is_file():
        raise SystemExit(f"not a DeltaAegis repository: {root}")
    return root


def elapsed_ms(action: Callable[[], Any]) -> tuple[float, Any]:
    started = time.perf_counter()
    result = action()
    return (time.perf_counter() - started) * 1000.0, result


def repeated(action: Callable[[], Any], repetitions: int) -> dict[str, float]:
    samples = [elapsed_ms(action)[0] for _ in range(repetitions)]
    return {
        "median_ms": round(statistics.median(samples), 3),
        "min_ms": round(min(samples), 3),
        "max_ms": round(max(samples), 3),
        "repetitions": repetitions,
    }


def load_deltaaegis(root: Path) -> ModuleType:
    module_name = "deltaaegis_v043_benchmark_target"
    spec = importlib.util.spec_from_file_location(module_name, root / "deltaaegis.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("could not create DeltaAegis module spec")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(module_name, None)
    return module


def python_import_command(root: Path) -> list[str]:
    code = (
        "import runpy; "
        f"runpy.run_path({str(root / 'deltaaegis.py')!r}, run_name='deltaaegis_baseline_import')"
    )
    return [sys.executable, "-c", code]


def create_synthetic_database(module: ModuleType, path: Path, assets: int, snapshots: int) -> Any:
    connection = module.connect(path)
    created = "2026-01-01T00:00:00+00:00"
    scope = "10.200.0.0/16"
    for scan_number in range(snapshots):
        scan_id = f"v043-baseline-scan-{scan_number + 1:02d}"
        connection.execute(
            "INSERT INTO snapshots ("
            "scan_id, manifest_path, target, network_scope, scanner_version, scan_profile, "
            "created_at, imported_at, bundle_status, quality_status, quality_reason, "
            "xml_exit_status, hosts_up, hosts_down, hosts_total, mac_backed_assets, "
            "identity_coverage, is_accepted_baseline"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                f"/synthetic/{scan_id}/manifest.json",
                scope,
                scope,
                "NetSniper-v2.0.0-synthetic",
                "balanced",
                created,
                created,
                "COMPLETED",
                "ACCEPTED",
                "synthetic benchmark fixture",
                "success",
                assets,
                0,
                assets,
                assets,
                1.0,
                1,
            ),
        )
        for index in range(assets):
            mac = "00:16:3e:%02x:%02x:%02x" % (
                (index >> 16) & 0xFF,
                (index >> 8) & 0xFF,
                index & 0xFF,
            )
            asset_key = f"mac:{mac}"
            ip = f"10.200.{index // 250}.{(index % 250) + 1}"
            connection.execute(
                "INSERT INTO asset_observations ("
                "scan_id, asset_key, identity_confidence, identity_source, ip_address, "
                "mac_address, hostname, classification_type, classification_primary_type, "
                "classification_confidence, classification_confidence_label, "
                "classification_decision, classification_method"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    asset_key,
                    "HIGH",
                    "GLOBAL_MAC",
                    ip,
                    mac,
                    f"synthetic-{index:04d}",
                    "server" if index % 8 == 0 else "workstation",
                    "server" if index % 8 == 0 else "workstation",
                    80,
                    "strong",
                    "classified",
                    "synthetic_fixture",
                ),
            )
            for port, service in ((22, "ssh"), (80, "http"), (443, "https")):
                connection.execute(
                    "INSERT INTO service_observations ("
                    "scan_id, asset_key, protocol, port, state, service_name"
                    ") VALUES (?, ?, 'tcp', ?, 'open', ?)",
                    (scan_id, asset_key, port, service),
                )

    latest_scan = f"v043-baseline-scan-{snapshots:02d}"
    for index in range(assets):
        mac = "00:16:3e:%02x:%02x:%02x" % (
            (index >> 16) & 0xFF,
            (index >> 8) & 0xFF,
            index & 0xFF,
        )
        asset_key = f"mac:{mac}"
        ip = f"10.200.{index // 250}.{(index % 250) + 1}"
        connection.execute(
            "INSERT INTO asset_lifecycle ("
            "network_scope, asset_key, identity_class, state, missing_count, current_ip, "
            "mac_address, hostname, first_seen_scan_id, last_seen_scan_id, "
            "first_seen_at, last_seen_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                scope,
                asset_key,
                "GLOBAL_MAC",
                "ACTIVE",
                0,
                ip,
                mac,
                f"synthetic-{index:04d}",
                "v043-baseline-scan-01",
                latest_scan,
                created,
                created,
            ),
        )
    connection.commit()
    return connection


def report_args(db: Path, output: Path) -> SimpleNamespace:
    return SimpleNamespace(
        db=db,
        reports_dir=output.parent,
        latest=False,
        since=None,
        severity=None,
        limit=100,
        risk_limit=10,
        asset_limit=25,
        scope=None,
        output=output,
    )


def node_version() -> str:
    executable = shutil.which("node")
    if not executable:
        return "not installed"
    completed = subprocess.run(
        [executable, "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return completed.stdout.strip() or completed.stderr.strip() or "unknown"


def git_tree(root: Path) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD^{tree}"],
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip() or "unavailable"


def measure_release_gate(root: Path) -> dict[str, Any]:
    gate = root / "tools/validate_v0_42_release_gate.sh"
    if not gate.is_file():
        raise RuntimeError("v0.42 release gate was not found")
    with tempfile.TemporaryDirectory(prefix="deltaaegis-v043-gate-") as temp_name:
        temp = Path(temp_name)
        checkout = temp / "DeltaAegis"
        clone = subprocess.run(
            ["git", "clone", "--quiet", "--shared", str(root), str(checkout)],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if clone.returncode:
            raise RuntimeError(f"could not create clean release-gate checkout: {clone.stderr.strip()}")
        switch = subprocess.run(
            ["git", "-C", str(checkout), "switch", "-C", "release/v0.42.2", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if switch.returncode:
            raise RuntimeError(f"could not prepare release-gate branch: {switch.stderr.strip()}")
        env = os.environ.copy()
        env["HOME"] = str(temp / "home")
        Path(env["HOME"]).mkdir()
        started = time.perf_counter()
        completed = subprocess.run(
            [str(checkout / "tools/validate_v0_42_release_gate.sh")],
            cwd=checkout,
            env=env,
            check=False,
            capture_output=True,
            text=True,
            timeout=900,
        )
        duration = time.perf_counter() - started
        if completed.returncode:
            tail = "\n".join((completed.stdout + "\n" + completed.stderr).splitlines()[-60:])
            raise RuntimeError(f"clean v0.42 release gate failed:\n{tail}")
        return {
            "status": "passed",
            "duration_seconds": round(duration, 3),
            "command": "tools/validate_v0_42_release_gate.sh",
            "checkout": "disposable clean local clone",
        }


def run_baseline(root: Path, assets: int, snapshots: int, repetitions: int, include_gate: bool) -> dict[str, Any]:
    module_load_ms, module = elapsed_ms(lambda: load_deltaaegis(root))
    import_command = python_import_command(root)

    def cold_import() -> None:
        completed = subprocess.run(import_command, check=False, capture_output=True, text=True, timeout=60)
        if completed.returncode:
            raise RuntimeError(completed.stderr.strip() or "DeltaAegis cold import failed")

    import_metrics = repeated(cold_import, repetitions)

    with tempfile.TemporaryDirectory(prefix="deltaaegis-v043-benchmark-") as temp_name:
        temp = Path(temp_name)
        schema_counter = 0

        def fresh_schema() -> None:
            nonlocal schema_counter
            schema_counter += 1
            connection = module.connect(temp / f"schema-{schema_counter}.db")
            connection.close()

        schema_metrics = repeated(fresh_schema, repetitions)
        db = temp / "synthetic.db"
        generation_ms, connection = elapsed_ms(
            lambda: create_synthetic_database(module, db, assets=assets, snapshots=snapshots)
        )
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.commit()
        db_bytes = db.stat().st_size

        summary_metrics = repeated(lambda: module.dashboard_summary_payload(connection), repetitions)
        assets_metrics = repeated(
            lambda: module.dashboard_assets_payload(connection, min(assets, 250)), repetitions
        )
        output = temp / "synthetic-report.md"
        report_ms, _ = elapsed_ms(lambda: module.command_report(report_args(db, output)))
        report_bytes = output.stat().st_size
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
        connection.close()

    release_gate = (
        measure_release_gate(root)
        if include_gate
        else {
            "status": "skipped",
            "duration_seconds": None,
            "command": "tools/validate_v0_42_release_gate.sh",
            "checkout": "not run in quick/self-test mode",
        }
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "mode": "full" if include_gate else "quick",
        "source": {
            "deltaaegis_version": getattr(module, "DELTAAEGIS_VERSION", "unknown"),
            "git_tree": git_tree(root),
        },
        "environment": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "cpu_count": os.cpu_count(),
            "python": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "sqlite": module.sqlite3.sqlite_version,
            "node": node_version(),
        },
        "fixture": {
            "snapshots": snapshots,
            "assets_per_snapshot": assets,
            "services_per_asset": 3,
            "network_scope": "10.200.0.0/16 synthetic only",
            "real_operator_data_used": False,
        },
        "measurements": {
            "cold_module_import": import_metrics,
            "in_process_module_load_ms": round(module_load_ms, 3),
            "fresh_schema_initialization": schema_metrics,
            "synthetic_database_generation_ms": round(generation_ms, 3),
            "synthetic_database_bytes": db_bytes,
            "bytes_per_asset_observation": round(db_bytes / max(assets * snapshots, 1), 3),
            "dashboard_summary_payload": summary_metrics,
            "dashboard_assets_payload": assets_metrics,
            "markdown_report_generation_ms": round(report_ms, 3),
            "markdown_report_bytes": report_bytes,
            "sqlite_integrity_check": integrity,
            "sqlite_foreign_key_violations": len(foreign_keys),
            "release_gate": release_gate,
        },
        "interpretation": [
            "These are descriptive v0.43 baselines, not release thresholds.",
            "The fixture is synthetic and is created under a temporary directory.",
            "Performance targets are set during v0.49 after module, migration, API, and identity work stabilizes.",
            "Compare future runs only when fixture size, environment, and benchmark schema match.",
        ],
    }


def format_number(value: Any, suffix: str = "") -> str:
    if value is None:
        return "not measured"
    return f"{value}{suffix}"


def render_markdown(result: dict[str, Any]) -> str:
    env = result["environment"]
    fixture = result["fixture"]
    metrics = result["measurements"]
    gate = metrics["release_gate"]
    rows = [
        ("Cold module import (median)", format_number(metrics["cold_module_import"]["median_ms"], " ms")),
        ("Fresh schema initialization (median)", format_number(metrics["fresh_schema_initialization"]["median_ms"], " ms")),
        ("Synthetic database generation", format_number(metrics["synthetic_database_generation_ms"], " ms")),
        ("Synthetic database size", format_number(metrics["synthetic_database_bytes"], " bytes")),
        ("Bytes per asset observation", format_number(metrics["bytes_per_asset_observation"], " bytes")),
        ("Dashboard summary payload (median)", format_number(metrics["dashboard_summary_payload"]["median_ms"], " ms")),
        ("Dashboard assets payload (median)", format_number(metrics["dashboard_assets_payload"]["median_ms"], " ms")),
        ("Markdown report generation", format_number(metrics["markdown_report_generation_ms"], " ms")),
        ("Markdown report size", format_number(metrics["markdown_report_bytes"], " bytes")),
        ("Complete v0.42 release gate", format_number(gate["duration_seconds"], " s")),
    ]
    lines = [
        "# DeltaAegis v0.43 Performance Baseline",
        "",
        f"Schema: `{result['schema_version']}`",
        "",
        f"Generated: `{result['generated_at']}`",
        "",
        "This baseline measures the unchanged v0.42.2 runtime with synthetic temporary data. It establishes comparison evidence; it does not create performance pass/fail thresholds.",
        "",
        "## Environment",
        "",
        "| Property | Value |",
        "|---|---|",
        f"| Platform | `{env['platform']}` |",
        f"| Machine | `{env['machine']}` |",
        f"| Logical CPUs | `{env['cpu_count']}` |",
        f"| Python | `{env['python_implementation']} {env['python']}` |",
        f"| SQLite | `{env['sqlite']}` |",
        f"| Node.js | `{env['node']}` |",
        f"| Source tree | `{result['source']['git_tree']}` |",
        f"| DeltaAegis runtime | `{result['source']['deltaaegis_version']}` |",
        "",
        "## Synthetic fixture",
        "",
        f"- Snapshots: **{fixture['snapshots']}**",
        f"- Assets per snapshot: **{fixture['assets_per_snapshot']}**",
        f"- Services per asset: **{fixture['services_per_asset']}**",
        f"- Scope: `{fixture['network_scope']}`",
        "- Real operator data used: **no**",
        "",
        "## Measurements",
        "",
        "| Measurement | Result |",
        "|---|---:|",
    ]
    lines.extend(f"| {name} | {value} |" for name, value in rows)
    lines.extend(
        [
            "",
            f"SQLite integrity check: `{metrics['sqlite_integrity_check']}`",
            "",
            f"SQLite foreign-key violations: `{metrics['sqlite_foreign_key_violations']}`",
            "",
            f"Release-gate status: `{gate['status']}` using a {gate['checkout']}.",
            "",
            "## Method",
            "",
            "1. Load `deltaaegis.py` without starting its CLI.",
            "2. Measure cold imports in separate Python processes.",
            "3. Initialize fresh temporary SQLite databases.",
            "4. Populate deterministic synthetic snapshots, assets, services, and lifecycle rows.",
            "5. Measure representative summary, asset-list, and Markdown-report paths.",
            "6. Run SQLite integrity and foreign-key checks.",
            "7. Run the complete predecessor release gate in a disposable clean local clone.",
            "",
            "Regenerate both baseline artifacts with:",
            "",
            "```bash",
            "python3 tools/benchmark_v0_43.py --write",
            "```",
            "",
            "## Interpretation",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in result["interpretation"])
    return "\n".join(lines).rstrip() + "\n"


def validate_result(result: dict[str, Any], require_gate: bool) -> None:
    if result.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError("unexpected performance baseline schema")
    measurements = result.get("measurements") or {}
    required = {
        "cold_module_import",
        "fresh_schema_initialization",
        "synthetic_database_generation_ms",
        "synthetic_database_bytes",
        "dashboard_summary_payload",
        "dashboard_assets_payload",
        "markdown_report_generation_ms",
        "release_gate",
    }
    missing = sorted(required - set(measurements))
    if missing:
        raise RuntimeError(f"missing baseline measurements: {', '.join(missing)}")
    if measurements.get("sqlite_integrity_check") != "ok":
        raise RuntimeError("synthetic SQLite integrity check did not pass")
    if measurements.get("sqlite_foreign_key_violations") != 0:
        raise RuntimeError("synthetic SQLite foreign-key check did not pass")
    if require_gate and measurements["release_gate"].get("status") != "passed":
        raise RuntimeError("complete predecessor release-gate timing is required")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", help="DeltaAegis repository root")
    parser.add_argument("--write", action="store_true", help="Write Markdown and JSON baseline artifacts")
    parser.add_argument("--json", action="store_true", help="Print result JSON")
    parser.add_argument("--quick", action="store_true", help="Skip the complete release-gate measurement")
    parser.add_argument("--self-test", action="store_true", help="Run a small temporary fixture and no release gate")
    args = parser.parse_args()
    root = repository_root(args.repo)
    assets = 12 if args.self_test else 240
    snapshots = 2 if args.self_test else 3
    repetitions = 2 if args.self_test else 5
    include_gate = not (args.quick or args.self_test)
    result = run_baseline(root, assets, snapshots, repetitions, include_gate)
    validate_result(result, require_gate=include_gate)

    if args.write:
        if not include_gate:
            raise SystemExit("--write requires the complete release-gate measurement; omit --quick/--self-test")
        (root / JSON_PATH).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (root / MARKDOWN_PATH).write_text(render_markdown(result), encoding="utf-8")
        print(f"WROTE: {root / MARKDOWN_PATH}")
        print(f"WROTE: {root / JSON_PATH}")

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif not args.write:
        print(render_markdown(result), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
