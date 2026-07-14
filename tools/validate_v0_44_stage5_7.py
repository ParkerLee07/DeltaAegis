#!/usr/bin/env python3
"""Validate the combined v0.44 Sites, Jobs, and Reports extraction."""

from __future__ import annotations

import ast
import inspect
import json
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHARACTERIZATION_PATH = ROOT / "docs" / "v0.44-stage5-7-characterization.json"
EXPECTED_SOURCE_TREE = "6d79d5b8a735e544f846b127478f49ebe0fcb777"

import sys

sys.path.insert(0, str(ROOT))

import deltaaegis as facade  # noqa: E402
from deltaaegis_core import jobs, reports, sites  # noqa: E402


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def top_level_functions(path: Path) -> dict[str, ast.FunctionDef]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}


def comparable_parameters(function) -> list[tuple[str, inspect._ParameterKind, str]]:
    result = []
    for parameter in inspect.signature(function).parameters.values():
        if parameter.name == "context":
            continue
        default = "<empty>" if parameter.default is inspect.Parameter.empty else repr(parameter.default)
        result.append((parameter.name, parameter.kind, default))
    return result


def load_characterization() -> dict:
    payload = json.loads(CHARACTERIZATION_PATH.read_text(encoding="utf-8"))
    check(
        payload.get("format") == "deltaaegis-v0.44-stage5-7-characterization-v1",
        "unexpected combined characterization format",
    )
    check(payload.get("source_checkpoint_tree") == EXPECTED_SOURCE_TREE, "source checkpoint changed")
    check(payload.get("schema_change") is False, "extraction must not claim a schema change")
    check(payload.get("web_boundary_changed") is False, "Stage 8 web boundary must remain unchanged")
    return payload


def validate_facade(stage: dict, module, alias: str) -> None:
    root_path = ROOT / "deltaaegis.py"
    module_path = ROOT / stage["module"]
    root_source = root_path.read_text(encoding="utf-8")
    module_source = module_path.read_text(encoding="utf-8")
    root_functions = top_level_functions(root_path)
    module_functions = top_level_functions(module_path)
    check(f"from deltaaegis_core import {alias[1:]} as {alias}" in root_source, f"{alias} import missing")
    check(alias[1:] in __import__("deltaaegis_core").__all__, f"{alias[1:]} package export missing")
    for name in stage["facade_functions"]:
        check(name in root_functions, f"root facade missing: {name}")
        check(name in module_functions, f"module implementation missing: {name}")
        segment = ast.get_source_segment(root_source, root_functions[name]) or ""
        check(f"{alias}." in segment, f"root function is not a thin {alias} facade: {name}")
        check(
            comparable_parameters(getattr(facade, name)) == comparable_parameters(getattr(module, name)),
            f"compatibility parameters changed: {name}",
        )


def validate_sites(stage: dict) -> None:
    validate_facade(stage, sites, "_sites")
    with tempfile.TemporaryDirectory(prefix="deltaaegis-v044-sites-") as temporary:
        connection = facade.connect(Path(temporary) / "sites.db")
        try:
            created = facade.create_logical_site(connection, "Home Lab", "test scope")
            facade.assign_network_scope_to_logical_site(connection, created["site_id"], "192.168.77.0/24")
            payload = facade.logical_site_detail_payload(connection, created["site_id"])
            check(payload["site"]["name"] == "Home Lab", "site name changed")
            check(
                [row["network_scope"] for row in payload["members"]] == ["192.168.77.0/24"],
                "site membership changed",
            )
            try:
                facade.assign_network_scope_to_logical_site(connection, created["site_id"], "192.168.77.0/24")
            except facade.DeltaAegisError:
                pass
            else:
                raise AssertionError("duplicate site membership was accepted")
        finally:
            connection.close()


def validate_jobs(stage: dict) -> None:
    validate_facade(stage, jobs, "_jobs")
    source = (ROOT / stage["module"]).read_text(encoding="utf-8")
    check("subprocess" not in source and "os.kill" not in source, "process orchestration moved into jobs policy")
    check(stage["process_orchestration_owner"] == "deltaaegis.py", "process ownership characterization changed")
    check(
        facade._JOB_CONTEXT.active_scan_job_exists_error_type is facade.ActiveScanJobExistsError,
        "active-job exception identity changed",
    )
    with tempfile.TemporaryDirectory(prefix="deltaaegis-v044-jobs-") as temporary:
        root = Path(temporary)
        connection = facade.connect(root / "jobs.db")
        try:
            job = facade.create_scan_job(connection, "192.168.78.0/24", root / "NetSniper", root / "runs")
            cancelled = facade.request_scan_job_cancellation(connection, job["job_id"], "validator", "test")
            check(cancelled["status"] == "CANCELLED", "queued cancellation transition changed")
            schedule = facade.create_scan_schedule(connection, "Hourly", "192.168.78.0/24")
            check(schedule["enabled"] is True, "schedule creation changed")
            log_payload = facade.scan_job_log_tail_payload(
                "../outside.log", job["job_id"], "stdout", root / "logs"
            )
            check(
                log_payload["available"] is False
                and log_payload["reason"] == "log_path_outside_allowed_root",
                "scan log path traversal confinement changed",
            )
        finally:
            connection.close()


def validate_reports(stage: dict) -> None:
    validate_facade(stage, reports, "_reports")
    source = (ROOT / stage["module"]).read_text(encoding="utf-8")
    check("write_text(" not in source and "open(" not in source, "report file output moved out of root orchestration")
    check(stage["file_output_owner"] == "deltaaegis.py", "report output ownership changed")
    check(facade.safe_markdown("a|b\nc") == "a\\|b c", "Markdown escaping changed")
    lines: list[str] = []
    facade.append_report_risk_section(
        lines,
        [{"level": "HIGH", "score": 80, "subject_key": "ip:192.168.1.10", "reasons": ["test"]}],
    )
    check("## Top Risk Subjects" in lines, "risk report heading changed")
    with tempfile.TemporaryDirectory(prefix="deltaaegis-v044-reports-") as temporary:
        connection = facade.connect(Path(temporary) / "reports.db")
        try:
            check(facade.report_snapshot_count(connection) == 0, "empty snapshot report count changed")
        finally:
            connection.close()


def main() -> int:
    print("DeltaAegis v0.44 Stages 5-7 Backend Boundary Validator")
    print("==========================================================")
    characterization = load_characterization()
    validate_sites(characterization["stages"]["5"])
    print("PASS: Stage 5 Sites storage and scope aggregation boundary")
    validate_jobs(characterization["stages"]["6"])
    print("PASS: Stage 6 durable Jobs and schedule policy boundary")
    validate_reports(characterization["stages"]["7"])
    print("PASS: Stage 7 report query and Markdown generation boundary")
    print("PASS: unchanged schema, root facade, and deferred Stage 8 web boundary")
    print("PASS: DeltaAegis v0.44 Stages 5 through 7")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
