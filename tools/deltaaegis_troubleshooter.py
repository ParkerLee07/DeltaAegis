#!/usr/bin/env python3
"""DeltaAegis repository-aware diagnostics and isolated validator runner."""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterable

TOOL_FORMAT = "deltaaegis-repository-troubleshooter-v4"
TOOL_VERSION = "1.0.0"
REPORT_SCHEMA = "deltaaegis-troubleshooter-report-v4"
VALIDATOR_RE = re.compile(r"validate_[A-Za-z0-9_.-]+\.sh")
VERSION_RE = re.compile(
    r"validate_v(?P<major>\d+)_(?P<minor>\d+)(?:_(?P<patch>\d+))?"
)

ERROR_CODES: dict[str, dict[str, str]] = {
    "DAE-TRB-1001": {
        "severity": "ERROR",
        "title": "Repository not found",
        "meaning": "The selected path is not a DeltaAegis Git checkout.",
        "action": "Run from the checkout or pass --repo PATH.",
    },
    "DAE-TRB-1002": {
        "severity": "ERROR",
        "title": "DeltaAegis source missing",
        "meaning": "deltaaegis.py is absent from the selected repository.",
        "action": "Restore the checkout or select the correct repository.",
    },
    "DAE-TRB-1003": {
        "severity": "ERROR",
        "title": "Database path unresolved",
        "meaning": "The active database path could not be resolved from deltaaegis.py paths.",
        "action": "Run deltaaegis.py paths and correct the configuration error.",
    },
    "DAE-TRB-1101": {
        "severity": "ERROR",
        "title": "Git state unavailable",
        "meaning": "Git metadata could not be read.",
        "action": "Verify Git, repository ownership, and metadata access.",
    },
    "DAE-TRB-1102": {
        "severity": "WARN",
        "title": "Working tree changed",
        "meaning": "Diagnostics are being requested from a checkout with tracked or untracked changes.",
        "action": "Review git status and understand that isolated runs use committed HEAD.",
    },
    "DAE-TRB-1103": {
        "severity": "WARN",
        "title": "Required command unavailable",
        "meaning": "A command used by diagnostics is not installed.",
        "action": "Install the command before running the affected validator.",
    },
    "DAE-TRB-2101": {
        "severity": "ERROR",
        "title": "Validator inventory unavailable",
        "meaning": "The repository validator inventory could not be read.",
        "action": "Restore tools/ and rerun the self-check.",
    },
    "DAE-TRB-2102": {
        "severity": "ERROR",
        "title": "Validator Bash syntax failure",
        "meaning": "At least one tracked validator has invalid Bash syntax.",
        "action": "Repair the first reported validator before running diagnostics.",
    },
    "DAE-TRB-3101": {
        "severity": "WARN",
        "title": "Validator reference missing",
        "meaning": "A validator executes another validator that is absent from the repository.",
        "action": "Restore the dependency or remove the stale execution reference.",
    },
    "DAE-TRB-3102": {
        "severity": "WARN",
        "title": "Validator dependency cycle",
        "meaning": "The executable validator graph contains a cycle.",
        "action": "Flatten recursive suites so each validator is executed deliberately.",
    },
    "DAE-TRB-4001": {
        "severity": "ERROR",
        "title": "Validator returned nonzero",
        "meaning": "A selected validator failed.",
        "action": "Open the retained log and resolve the first failing assertion.",
    },
    "DAE-TRB-4002": {
        "severity": "ERROR",
        "title": "Validator timed out",
        "meaning": "A selected validator exceeded its timeout.",
        "action": "Inspect the log and rerun with a justified larger timeout.",
    },
    "DAE-TRB-4003": {
        "severity": "ERROR",
        "title": "Validator execution error",
        "meaning": "The isolated candidate or validator process could not be created.",
        "action": "Inspect clone, filesystem, command, and environment errors.",
    },
    "DAE-TRB-4101": {
        "severity": "ERROR",
        "title": "Candidate branch rejected",
        "meaning": "A validator rejected its isolated candidate branch.",
        "action": "Use the current release gate or correct obsolete branch policy.",
    },
    "DAE-TRB-4102": {
        "severity": "ERROR",
        "title": "Expected source or fixture missing",
        "meaning": "A validator could not find a required source or fixture.",
        "action": "Restore the file or fix the path assumption.",
    },
    "DAE-TRB-4103": {
        "severity": "ERROR",
        "title": "Source syntax failure",
        "meaning": "Python, JavaScript, Bash, or generated source is invalid.",
        "action": "Fix the first syntax error before downstream diagnosis.",
    },
    "DAE-TRB-5101": {
        "severity": "INFO",
        "title": "Optional database absent",
        "meaning": "No database exists at an optional candidate path.",
        "action": "No action is needed unless that deployment expects it.",
    },
    "DAE-TRB-5102": {
        "severity": "ERROR",
        "title": "SQLite integrity failure",
        "meaning": "SQLite quick_check did not return ok.",
        "action": "Stop writers, preserve a copy, and use the documented recovery workflow.",
    },
    "DAE-TRB-5103": {
        "severity": "ERROR",
        "title": "SQLite foreign-key violation",
        "meaning": "SQLite reported foreign-key violations.",
        "action": "Preserve the database and investigate the reported rows.",
    },
    "DAE-TRB-5104": {
        "severity": "ERROR",
        "title": "Database locked",
        "meaning": "A read-only integrity check could not acquire access.",
        "action": "Let the active writer finish; do not delete lock or journal files.",
    },
    "DAE-TRB-5105": {
        "severity": "ERROR",
        "title": "Active database missing",
        "meaning": "DeltaAegis resolved an active database path, but the file is absent.",
        "action": "Confirm the configured path and initialize or restore the expected database.",
    },
    "DAE-TRB-5106": {
        "severity": "INFO",
        "title": "Additional database discovered",
        "meaning": "Another non-backup database exists near the repository.",
        "action": "Review it so an obsolete database is not mistaken for the active one.",
    },
    "DAE-TRB-5201": {
        "severity": "CRITICAL",
        "title": "Protected database changed",
        "meaning": "A protected database hash changed during diagnostics.",
        "action": "Stop, preserve evidence, and compare against a known-good backup.",
    },
    "DAE-TRB-6101": {
        "severity": "ERROR",
        "title": "Permission denied",
        "meaning": "A required path or command was not accessible.",
        "action": "Check ownership, mode bits, directory access, and mount policy.",
    },
    "DAE-TRB-6102": {
        "severity": "ERROR",
        "title": "Address or port in use",
        "meaning": "A diagnostic could not bind because another listener is active.",
        "action": "Identify and cleanly stop the conflicting listener.",
    },
    "DAE-TRB-6103": {
        "severity": "WARN",
        "title": "Related process active",
        "meaning": "A DeltaAegis, NetSniper, or TrueAegis process is active.",
        "action": "Let work finish or stop it cleanly before intrusive diagnostics.",
    },
    "DAE-TRB-7001": {
        "severity": "ERROR",
        "title": "Report creation failed",
        "meaning": "The diagnostic report directory could not be created or written.",
        "action": "Check storage, permissions, and --report-dir.",
    },
    "DAE-TRB-8001": {
        "severity": "INFO",
        "title": "Operator interrupted run",
        "meaning": "The operator stopped the menu or validator run.",
        "action": "Review completed logs and rerun when ready.",
    },
}


class TroubleshooterError(RuntimeError):
    pass


@dataclasses.dataclass
class Result:
    validator: str
    status: str
    return_code: int | None
    duration_seconds: float
    log_path: str
    tail: list[str]
    diagnostic_codes: list[str]


def run(
    args: list[str],
    *,
    cwd: Path | None = None,
    check: bool = True,
    capture: bool = True,
    env: dict[str, str] | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        env=env,
        timeout=timeout,
    )
    if check and completed.returncode != 0:
        command = " ".join(shlex.quote(part) for part in args)
        raise TroubleshooterError(
            f"command failed ({completed.returncode}): {command}\n"
            f"stdout:\n{completed.stdout or ''}\n"
            f"stderr:\n{completed.stderr or ''}"
        )
    return completed


def resolve_repo(value: Path | None) -> Path:
    if value is not None:
        candidate = value.expanduser().resolve()
    else:
        script_candidate = Path(__file__).resolve().parents[1]
        candidate = (
            script_candidate
            if (script_candidate / "deltaaegis.py").is_file()
            else Path.cwd().resolve()
        )
    if not candidate.is_dir():
        raise TroubleshooterError(f"DeltaAegis project directory not found: {candidate}")
    if not (candidate / "deltaaegis.py").is_file():
        raise TroubleshooterError(f"deltaaegis.py not found in project: {candidate}")
    return candidate


def git(repo: Path, *args: str, check: bool = True) -> str:
    return (run(["git", *args], cwd=repo, check=check).stdout or "").strip()


def validator_inventory(repo: Path) -> list[str]:
    return sorted(
        path.relative_to(repo).as_posix()
        for path in (repo / "tools").glob("validate_*.sh")
        if path.is_file() and not path.is_symlink()
    )


def version_tuple(path: str) -> tuple[int, int, int]:
    match = VERSION_RE.search(Path(path).name)
    if not match:
        return (-1, -1, -1)
    return (
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch") or 0),
    )


def current_release_gate(validators: Iterable[str]) -> str:
    # A partial v1 delivery must be discoverable without mislabeling it as a
    # complete v1 release gate.  Candidate checkpoint gates and completed
    # release gates share the same selection policy; the highest semantic
    # version wins and the filename preserves its actual status.
    gates = [
        path
        for path in validators
        if path.endswith("_release_gate.sh")
        or path.endswith("_stage1_2_gate.sh")
        or path.endswith("_stage3_5_gate.sh")
    ]
    if not gates:
        raise TroubleshooterError("No versioned release or candidate gate exists under tools/")
    return max(gates, key=lambda path: (version_tuple(path), path))


def current_stage_validators(validators: Iterable[str]) -> list[str]:
    inventory = list(validators)
    gate = current_release_gate(inventory)
    major, minor, _ = version_tuple(gate)
    prefix = f"tools/validate_v{major}_{minor}_stage"
    return sorted(
        path
        for path in inventory
        if path.startswith(prefix) and path.endswith("_all.sh")
    )


def _shell_without_heredoc_bodies(text: str) -> list[str]:
    lines = text.splitlines()
    output: list[str] = []
    delimiter: str | None = None
    strip_tabs = False
    pattern = re.compile(
        r"<<(?P<strip>-)?\s*(?P<quote>['\"]?)(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?P=quote)"
    )
    for line in lines:
        if delimiter is not None:
            candidate = line.lstrip("\t") if strip_tabs else line
            if candidate.strip() == delimiter:
                delimiter = None
                strip_tabs = False
            continue
        output.append(line)
        match = pattern.search(line)
        if match:
            delimiter = match.group("name")
            strip_tabs = bool(match.group("strip"))
    return output


def _direct_validator_command(line: str) -> str | None:
    try:
        tokens = shlex.split(line, comments=True, posix=True)
    except ValueError:
        return None
    if not tokens:
        return None
    index = 0
    while index < len(tokens) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[index]):
        index += 1
    while index < len(tokens):
        token = tokens[index]
        if token in {"time", "command", "builtin", "exec", "sudo"}:
            index += 1
            continue
        if token == "env":
            index += 1
            while index < len(tokens) and (
                tokens[index].startswith("-")
                or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[index])
            ):
                index += 1
            continue
        if token in {"bash", "sh", "python3", "python"}:
            index += 1
            break
        if token == "timeout":
            index += 1
            while index < len(tokens) and tokens[index].startswith("-"):
                index += 1
            if index < len(tokens):
                index += 1
            continue
        break
    if index >= len(tokens):
        return None
    candidate = Path(tokens[index]).name
    return candidate if VALIDATOR_RE.fullmatch(candidate) else None


def _logical_shell_commands(lines: list[str]) -> list[tuple[int, str]]:
    commands: list[tuple[int, str]] = []
    current = ""
    start_index = 0
    for index, line in enumerate(lines):
        stripped = line.rstrip()
        if not current:
            start_index = index
            current = stripped
        else:
            current += stripped.lstrip()
        if stripped.endswith("\\"):
            current = current[:-1].rstrip() + " "
            continue
        commands.append((start_index, current))
        current = ""
    if current:
        commands.append((start_index, current))
    return commands


def execution_references(text: str) -> list[str]:
    lines = _shell_without_heredoc_bodies(text)
    references: set[str] = set()
    arrays: dict[str, set[str]] = {}
    declaration_lines: set[int] = set()
    index = 0
    while index < len(lines):
        line = lines[index]
        array_match = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)=\(\s*$", line)
        if array_match:
            variable = array_match.group(1)
            names: set[str] = set()
            declaration_lines.add(index)
            index += 1
            while index < len(lines):
                declaration_lines.add(index)
                names.update(VALIDATOR_RE.findall(lines[index]))
                if re.match(r"^\s*\)\s*(?:#.*)?$", lines[index]):
                    break
                index += 1
            arrays[variable] = names
            index += 1
            continue
        index += 1

    for array_name, names in arrays.items():
        loop_pattern = re.compile(
            rf"\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+[\"']?\$\{{{re.escape(array_name)}\[@\]\}}[\"']?"
        )
        joined = "\n".join(lines)
        for match in loop_pattern.finditer(joined):
            variable = match.group(1)
            command_pattern = re.compile(
                rf"^\s*(?:(?:time|command|exec)\s+)?[\"']?\$(?:\{{{re.escape(variable)}\}}|{re.escape(variable)})[\"']?(?:\s|$|[;&|])"
            )
            if any(command_pattern.search(candidate) for candidate in lines):
                references.update(names)
                break

    for line_number, line in _logical_shell_commands(lines):
        if line_number in declaration_lines:
            continue
        direct = _direct_validator_command(line)
        if direct:
            references.add(direct)
    return sorted(references)


def dependency_inventory(repo: Path, validators: list[str]) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    by_name = {Path(path).name: path for path in validators}
    graph: dict[str, list[str]] = {}
    missing: dict[str, list[str]] = {}
    for path in validators:
        text = (repo / path).read_text(encoding="utf-8", errors="replace")
        dependencies: list[str] = []
        absent: list[str] = []
        for name in execution_references(text):
            target = by_name.get(name)
            if target:
                dependencies.append(target)
            else:
                absent.append(name)
        graph[path] = sorted(set(dependencies))
        if absent:
            missing[path] = sorted(set(absent))
    return graph, missing


def dependency_cycles(graph: dict[str, list[str]]) -> list[list[str]]:
    cycles: set[tuple[str, ...]] = set()
    visiting: list[str] = []
    state: dict[str, int] = {}

    def visit(node: str) -> None:
        state[node] = 1
        visiting.append(node)
        for child in graph.get(node, []):
            if state.get(child, 0) == 0:
                visit(child)
            elif state.get(child) == 1:
                start = visiting.index(child)
                cycle = visiting[start:] + [child]
                body = cycle[:-1]
                rotations = [tuple(body[i:] + body[:i]) for i in range(len(body))]
                cycles.add(min(rotations))
        visiting.pop()
        state[node] = 2

    for node in graph:
        if state.get(node, 0) == 0:
            visit(node)
    return [list(cycle) for cycle in sorted(cycles)]


def self_check(repo: Path) -> dict[str, Any]:
    validators = validator_inventory(repo)
    syntax_failures: list[dict[str, Any]] = []
    for path in validators:
        completed = run(["bash", "-n", path], cwd=repo, check=False)
        if completed.returncode != 0:
            syntax_failures.append(
                {"path": path, "stderr": (completed.stderr or "").strip()}
            )
    graph, missing = dependency_inventory(repo, validators)
    cycles = dependency_cycles(graph)
    try:
        current_gate = current_release_gate(validators)
    except TroubleshooterError:
        current_gate = None
    inventory_available = bool(validators)
    integrity_ok = not syntax_failures and (
        current_gate is not None or not inventory_available
    )
    graph_ok = not missing and not cycles
    return {
        "format": TOOL_FORMAT,
        "tool_version": TOOL_VERSION,
        "repository": str(repo),
        "validator_inventory_available": inventory_available,
        "validator_count": len(validators),
        "current_release_gate": current_gate,
        "syntax_failures": syntax_failures,
        "missing_references": missing,
        "cycles": cycles,
        "integrity_ok": integrity_ok,
        "graph_ok": graph_ok,
    }


def parse_paths_output(repo: Path) -> dict[str, str]:
    completed = run(
        [sys.executable, "deltaaegis.py", "paths"],
        cwd=repo,
        check=False,
    )
    if completed.returncode != 0:
        raise TroubleshooterError((completed.stderr or completed.stdout or "paths failed").strip())
    values: dict[str, str] = {}
    for line in (completed.stdout or "").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        values[key.strip()] = value.strip()
    if not values.get("Database"):
        raise TroubleshooterError("deltaaegis.py paths did not return a Database value")
    return values


def sqlite_read_only_checks(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"path": str(path), "exists": False, "ok": False, "code": "DAE-TRB-5105"}
    uri = f"file:{path.resolve().as_posix()}?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=2.0)
        quick = [row[0] for row in connection.execute("PRAGMA quick_check")]
        foreign = [list(row) for row in connection.execute("PRAGMA foreign_key_check")]
        connection.close()
    except sqlite3.OperationalError as exc:
        text = str(exc)
        code = "DAE-TRB-5104" if "locked" in text.lower() else "DAE-TRB-5102"
        return {"path": str(path), "exists": True, "ok": False, "code": code, "error": text}
    ok = quick == ["ok"] and not foreign
    code = None
    if quick != ["ok"]:
        code = "DAE-TRB-5102"
    elif foreign:
        code = "DAE-TRB-5103"
    return {
        "path": str(path),
        "exists": True,
        "ok": ok,
        "quick_check": quick,
        "foreign_key_violations": foreign,
        "code": code,
    }


def discover_databases(repo: Path, active: Path) -> list[str]:
    found: list[str] = []
    excluded_parts = {"backups", "restore-rehearsals", ".git"}
    for path in repo.rglob("*.db"):
        if any(part in excluded_parts for part in path.parts):
            continue
        try:
            if path.resolve() == active.resolve():
                continue
        except OSError:
            pass
        found.append(str(path))
    return sorted(found)


def related_processes() -> list[str]:
    if not shutil.which("pgrep"):
        return []
    completed = run(
        ["pgrep", "-af", "deltaaegis.py|netsniper.sh|trueaegis"],
        check=False,
    )
    own_pid = str(os.getpid())
    return [
        line for line in (completed.stdout or "").splitlines()
        if line.strip() and not line.startswith(own_pid + " ")
    ]


def environment_report(repo: Path) -> dict[str, Any]:
    codes: list[str] = []
    try:
        branch = git(repo, "branch", "--show-current")
        head = git(repo, "rev-parse", "HEAD")
        status = git(repo, "status", "--porcelain=v1")
    except TroubleshooterError:
        branch, head, status = "", "", ""
        codes.append("DAE-TRB-1101")
    if status:
        codes.append("DAE-TRB-1102")

    commands = {}
    for name in ("bash", "git", "python3", "node", "nmap"):
        path = shutil.which(name)
        commands[name] = path
        if name in {"bash", "git", "python3"} and not path:
            codes.append("DAE-TRB-1103")

    processes = related_processes()
    if processes:
        codes.append("DAE-TRB-6103")

    database_resolution: dict[str, Any]
    try:
        paths = parse_paths_output(repo)
        database_path = Path(paths["Database"]).expanduser()
        if not database_path.is_absolute():
            database_path = (repo / database_path).resolve()
        database = sqlite_read_only_checks(database_path)
        if database.get("code"):
            codes.append(str(database["code"]))
        additional = discover_databases(repo, database_path)
        if additional:
            codes.append("DAE-TRB-5106")
        database_resolution = {
            "resolved": True,
            "command": f"{sys.executable} deltaaegis.py paths",
            "paths": paths,
            "active": database,
            "additional_databases": additional,
        }
    except TroubleshooterError as exc:
        codes.append("DAE-TRB-1003")
        database_resolution = {"resolved": False, "error": str(exc)}

    return {
        "repository": str(repo),
        "branch": branch,
        "head": head,
        "working_tree_clean": not bool(status),
        "working_tree_status": status.splitlines(),
        "commands": commands,
        "active_processes": processes,
        "database_resolution": database_resolution,
        "codes": sorted(set(codes)),
    }


def blocking_codes(codes: Iterable[str]) -> list[str]:
    return [
        code for code in codes
        if ERROR_CODES.get(code, {}).get("severity") in {"ERROR", "CRITICAL"}
    ]


def quick_health_check(repo: Path, *, as_json: bool = False) -> int:
    check = self_check(repo)
    environment = environment_report(repo)
    codes = list(environment["codes"])
    if not check["integrity_ok"]:
        codes.append("DAE-TRB-2102" if check["syntax_failures"] else "DAE-TRB-2101")
    if check["missing_references"]:
        codes.append("DAE-TRB-3101")
    if check["cycles"]:
        codes.append("DAE-TRB-3102")
    codes = sorted(set(codes))
    payload = {
        "overall": "FAIL" if blocking_codes(codes) else ("WARN" if codes else "PASS"),
        "codes": codes,
        "environment": environment,
        "self_check": check,
    }
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("DeltaAegis Quick Health Check")
        print("=" * 40)
        print(f"Overall:            {payload['overall']}")
        print(f"Repository:         {repo}")
        print(f"Branch:             {environment['branch'] or '[unknown]'}")
        print(f"HEAD:               {environment['head'][:12] or '[unknown]'}")
        print(f"Working tree:       {'CLEAN' if environment['working_tree_clean'] else 'CHANGED'}")
        print(f"Current gate:       {check['current_release_gate'] or '[missing]'}")
        print(f"Validators:         {check['validator_count']}")
        print(f"Related processes:  {len(environment['active_processes'])}")
        database = environment["database_resolution"]
        if database.get("resolved"):
            active = database["active"]
            print(f"Active database:    {active['path']}")
            print(f"Database status:    {'PASS' if active.get('ok') else 'FAIL'}")
            print(f"Other databases:    {len(database['additional_databases'])}")
        else:
            print(f"Database status:    UNRESOLVED ({database.get('error', 'unknown')})")
        if codes:
            print("Diagnostic codes:   " + ", ".join(codes))
    return 1 if blocking_codes(codes) else 0


def create_report_dir(value: Path | None) -> Path:
    if value:
        path = value.expanduser().resolve()
        path.mkdir(parents=True, exist_ok=False)
        return path
    base = Path(tempfile.gettempdir()) / "deltaaegis-troubleshooter-reports"
    base.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path(tempfile.mkdtemp(prefix=f"{stamp}-", dir=base))


def latest_report_path() -> Path | None:
    base = Path(tempfile.gettempdir()) / "deltaaegis-troubleshooter-reports"
    if not base.is_dir():
        return None
    reports = sorted(base.glob("*/summary.md"), key=lambda path: path.stat().st_mtime, reverse=True)
    return reports[0] if reports else None


def select_validators(
    repo: Path,
    mode: str,
    match: str | None,
) -> list[str]:
    validators = validator_inventory(repo)
    if match:
        pattern = re.compile(match)
        return [path for path in validators if pattern.search(path)]
    if mode == "current":
        return [current_release_gate(validators)]
    if mode == "stages":
        selected = current_stage_validators(validators)
        return selected or [current_release_gate(validators)]
    if mode == "all":
        return validators
    graph, _ = dependency_inventory(repo, validators)
    referenced = {child for children in graph.values() for child in children}
    return [path for path in validators if path not in referenced]


def clone_candidate(repo: Path, destination: Path) -> tuple[Path, dict[str, str]]:
    if not (repo / ".git").exists():
        raise TroubleshooterError(
            "Isolated validator execution requires a Git checkout; "
            "health and inventory checks remain available in installed copies"
        )
    candidate = destination / "DeltaAegis"
    destination.mkdir(parents=True, exist_ok=True)
    run(["git", "clone", "--quiet", "--no-local", str(repo), str(candidate)], capture=True)
    head = git(repo, "rev-parse", "HEAD")
    run(["git", "checkout", "--quiet", "-B", "main", head], cwd=candidate)
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(destination),
            "CI": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "DELTAAEGIS_TROUBLESHOOTER": "1",
        }
    )
    return candidate, env


def result_codes(status: str, text: str) -> list[str]:
    if status == "TIMEOUT":
        return ["DAE-TRB-4002"]
    if status == "ERROR":
        return ["DAE-TRB-4003"]
    if status == "PASS":
        return []
    lowered = text.lower()
    codes = ["DAE-TRB-4001"]
    if "unsupported" in lowered and "branch" in lowered:
        codes.append("DAE-TRB-4101")
    if "no such file" in lowered or "missing" in lowered:
        codes.append("DAE-TRB-4102")
    if "syntaxerror" in lowered or "syntax error" in lowered:
        codes.append("DAE-TRB-4103")
    if "permission denied" in lowered:
        codes.append("DAE-TRB-6101")
    if "address already in use" in lowered:
        codes.append("DAE-TRB-6102")
    return sorted(set(codes))


def execute_validator(
    repo: Path,
    validator: str,
    run_index: int,
    workspace: Path,
    logs: Path,
    timeout_seconds: int,
    keep_candidates: bool,
) -> Result:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", Path(validator).name)
    run_root = workspace / f"{run_index:04d}-{safe}"
    log_path = logs / f"{validator.replace('/', '__')}.log"
    start = time.monotonic()
    status = "ERROR"
    return_code: int | None = None
    text = ""
    try:
        candidate, env = clone_candidate(repo, run_root)
        completed = run(
            ["bash", validator],
            cwd=candidate,
            check=False,
            env=env,
            timeout=timeout_seconds,
        )
        text = (completed.stdout or "") + (completed.stderr or "")
        return_code = completed.returncode
        status = "PASS" if completed.returncode == 0 else "FAIL"
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        text = stdout + stderr + f"\nTIMEOUT after {timeout_seconds} seconds\n"
        status = "TIMEOUT"
    except Exception as exc:
        text = f"{type(exc).__name__}: {exc}\n"
        status = "ERROR"
    duration = round(time.monotonic() - start, 3)
    log_path.write_text(text, encoding="utf-8")
    if not keep_candidates:
        shutil.rmtree(run_root, ignore_errors=True)
    return Result(
        validator=validator,
        status=status,
        return_code=return_code,
        duration_seconds=duration,
        log_path=str(log_path),
        tail=text.splitlines()[-80:],
        diagnostic_codes=result_codes(status, text),
    )


def write_summary(
    report_dir: Path,
    repo: Path,
    environment: dict[str, Any],
    check: dict[str, Any],
    selected: list[str],
    results: list[Result],
) -> None:
    payload = {
        "schema": REPORT_SCHEMA,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "repository": str(repo),
        "environment": environment,
        "self_check": check,
        "selected": selected,
        "results": [dataclasses.asdict(result) for result in results],
    }
    (report_dir / "summary.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [
        "# DeltaAegis Troubleshooter Report",
        "",
        f"- Repository: `{repo}`",
        f"- HEAD: `{environment.get('head', '')}`",
        f"- Current gate: `{check.get('current_release_gate')}`",
        f"- Selected validators: **{len(selected)}**",
        "",
        "| Validator | Status | Seconds | Diagnostic codes | Log |",
        "|---|---|---:|---|---|",
    ]
    for result in results:
        codes = ", ".join(result.diagnostic_codes) or "none"
        lines.append(
            f"| `{result.validator}` | {result.status} | {result.duration_seconds:.3f} | "
            f"{codes} | `{result.log_path}` |"
        )
    lines += ["", "## Environment codes", ""]
    lines.append(", ".join(environment.get("codes", [])) or "none")
    (report_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_selected_diagnostics(
    repo: Path,
    selected: list[str],
    *,
    timeout_seconds: int,
    keep_candidates: bool,
    report_dir_value: Path | None,
) -> int:
    if not selected:
        raise TroubleshooterError("No validator matched the requested selection")
    check = self_check(repo)
    if not check["integrity_ok"]:
        raise TroubleshooterError("Validator inventory failed self-check")
    environment = environment_report(repo)
    report_dir = create_report_dir(report_dir_value)
    logs = report_dir / "logs"
    workspace = report_dir / "candidates"
    logs.mkdir()
    workspace.mkdir()
    results: list[Result] = []
    print(f"Running {len(selected)} isolated validator{'s' if len(selected) != 1 else ''}.")
    for index, validator in enumerate(selected, start=1):
        print(f"[{index}/{len(selected)}] {validator}", flush=True)
        result = execute_validator(
            repo, validator, index, workspace, logs, timeout_seconds, keep_candidates
        )
        results.append(result)
        suffix = f" | {', '.join(result.diagnostic_codes)}" if result.diagnostic_codes else ""
        print(f"  {result.status} ({result.duration_seconds:.3f}s){suffix}", flush=True)
    write_summary(report_dir, repo, environment, check, selected, results)
    if not keep_candidates:
        shutil.rmtree(workspace, ignore_errors=True)
    failed = [result for result in results if result.status != "PASS"]
    print()
    print("Troubleshooting summary")
    print("-" * 40)
    print(f"Passed:             {len(results) - len(failed)}")
    print(f"Failed/timed out:   {len(failed)}")
    print(f"Report:             {report_dir / 'summary.md'}")
    return 1 if failed else 0


def print_error_catalog() -> None:
    # Keep DAE-TRB-4001 last so shell smoke tests using `grep -q` consume
    # the complete catalog instead of closing the pipe while Python is writing.
    codes = [code for code in sorted(ERROR_CODES) if code != "DAE-TRB-4001"]
    codes.append("DAE-TRB-4001")
    for code in codes:
        record = ERROR_CODES[code]
        print(f"{code}\t{record['severity']}\t{record['title']}")


def print_error_code(code: str) -> int:
    record = ERROR_CODES.get(code.upper())
    if not record:
        print(f"Unknown diagnostic code: {code}", file=sys.stderr)
        return 1
    print(f"{code.upper()} [{record['severity']}] {record['title']}")
    print(f"Meaning: {record['meaning']}")
    print(f"Action:  {record['action']}")
    return 0


def show_latest_report() -> int:
    path = latest_report_path()
    if not path:
        print("No retained troubleshooter report was found.")
        return 1
    print(path.read_text(encoding="utf-8"))
    print(f"Report: {path}")
    return 0


def interactive_menu(repo: Path) -> int:
    while True:
        validators = validator_inventory(repo)
        gate = current_release_gate(validators)
        version = version_tuple(gate)
        release_label = f"v{version[0]}.{version[1]}"
        print()
        print("=" * 62)
        print("DeltaAegis Troubleshooter")
        print(f"Repository: {repo}")
        print("=" * 62)
        print("1. Quick health check")
        print("2. Run current release/candidate diagnostics (recommended)")
        print(f"3. Run {release_label} staged diagnostics")
        print("4. Find and run a specific validator")
        print("5. Verify repository validator inventory")
        print("6. Show latest report")
        print("7. List diagnostic error codes")
        print("8. Explain an error code")
        print("9. Advanced diagnostics")
        print("0. Exit")
        try:
            choice = input("Selection: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        try:
            if choice == "0":
                return 0
            if choice == "1":
                quick_health_check(repo)
            elif choice == "2":
                return run_selected_diagnostics(
                    repo,
                    select_validators(repo, "current", None),
                    timeout_seconds=900,
                    keep_candidates=False,
                    report_dir_value=None,
                )
            elif choice == "3":
                return run_selected_diagnostics(
                    repo,
                    select_validators(repo, "stages", None),
                    timeout_seconds=900,
                    keep_candidates=False,
                    report_dir_value=None,
                )
            elif choice == "4":
                query = input("Validator name or regular expression: ").strip()
                matches = select_validators(repo, "current", query)
                for index, path in enumerate(matches[:30], start=1):
                    print(f"{index:>2}. {path}")
                if not matches:
                    print("No matching validator was found.")
                else:
                    selected = input("Choose a number, or Enter to cancel: ").strip()
                    if selected:
                        position = int(selected) - 1
                        return run_selected_diagnostics(
                            repo,
                            [matches[position]],
                            timeout_seconds=900,
                            keep_candidates=False,
                            report_dir_value=None,
                        )
            elif choice == "5":
                print(json.dumps(self_check(repo), indent=2, sort_keys=True))
            elif choice == "6":
                show_latest_report()
            elif choice == "7":
                print_error_catalog()
            elif choice == "8":
                print_error_code(input("Error code: ").strip())
            elif choice == "9":
                print("1. Run all static roots")
                print("2. Run every historical validator")
                print("3. Strict graph self-check")
                advanced = input("Selection: ").strip()
                if advanced == "1":
                    return run_selected_diagnostics(
                        repo,
                        select_validators(repo, "all-leaves", None),
                        timeout_seconds=900,
                        keep_candidates=False,
                        report_dir_value=None,
                    )
                if advanced == "2":
                    confirm = input("Type RUN ALL to continue: ").strip()
                    if confirm == "RUN ALL":
                        return run_selected_diagnostics(
                            repo,
                            select_validators(repo, "all", None),
                            timeout_seconds=900,
                            keep_candidates=False,
                            report_dir_value=None,
                        )
                if advanced == "3":
                    check = self_check(repo)
                    print(json.dumps(check, indent=2, sort_keys=True))
                    return 0 if check["integrity_ok"] and check["graph_ok"] else 1
            else:
                print("Invalid selection.")
        except (TroubleshooterError, ValueError, IndexError, re.error) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
        input("Press Enter to continue...")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run repository-aware DeltaAegis diagnostics in isolated candidates."
    )
    parser.add_argument("--repo", type=Path, default=None)
    parser.add_argument("--menu", action="store_true")
    parser.add_argument("--quick-check", action="store_true")
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--strict-graph", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--codes", action="store_true")
    parser.add_argument("--explain-code")
    parser.add_argument("--latest-report", action="store_true")
    parser.add_argument(
        "--mode", choices=("current", "stages", "all-leaves", "all"), default="current"
    )
    parser.add_argument("--match")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--report-dir", type=Path)
    parser.add_argument("--keep-candidates", action="store_true")
    parser.add_argument("--list", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.codes:
        print_error_catalog()
        return 0
    if args.explain_code:
        return print_error_code(args.explain_code)
    if args.latest_report:
        return show_latest_report()

    try:
        repo = resolve_repo(args.repo)
    except TroubleshooterError as exc:
        print_error_code("DAE-TRB-1001")
        print(f"Detail: {exc}", file=sys.stderr)
        return 2

    if args.menu or (
        len(sys.argv) == 1 and sys.stdin.isatty() and sys.stdout.isatty()
    ):
        return interactive_menu(repo)
    if args.quick_check:
        return quick_health_check(repo, as_json=args.json)

    check = self_check(repo)
    if args.self_check:
        if args.json:
            print(json.dumps(check, indent=2, sort_keys=True))
        else:
            print("DeltaAegis Validator Inventory Self-Check")
            print("=" * 45)
            print(f"Current gate:       {check['current_release_gate']}")
            print(f"Validators:         {check['validator_count']}")
            print(f"Bash syntax:        {'PASS' if not check['syntax_failures'] else 'FAIL'}")
            print(f"Reference graph:    {'PASS' if check['graph_ok'] else 'WARN'}")
        if not check["integrity_ok"]:
            return 1
        if args.strict_graph and not check["graph_ok"]:
            return 1
        return 0

    selected = select_validators(repo, args.mode, args.match)
    if args.list:
        graph, _ = dependency_inventory(repo, validator_inventory(repo))
        for path in selected:
            digest = hashlib.sha256((repo / path).read_bytes()).hexdigest()
            print(f"{path}\tdeps={len(graph.get(path, []))}\tsha256={digest[:12]}")
        return 0

    return run_selected_diagnostics(
        repo,
        selected,
        timeout_seconds=args.timeout,
        keep_candidates=args.keep_candidates,
        report_dir_value=args.report_dir,
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print()
        print_error_code("DAE-TRB-8001")
        raise SystemExit(130)
    except (TroubleshooterError, OSError, re.error) as exc:
        print_error_code("DAE-TRB-4003")
        print(f"Detail: {exc}", file=sys.stderr)
        raise SystemExit(2)
