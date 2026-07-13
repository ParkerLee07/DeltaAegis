#!/usr/bin/env python3
"""Run predecessor behavior suites in a clean candidate-tree snapshot."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_PARTS = {
    ".git",
    "__pycache__",
    "backups",
    "data",
    "events",
    "reports",
    "restore-rehearsals",
    "scan-logs",
    "trueaegis-logs",
}
COMMANDS = (
    ("rendered dashboard JavaScript", ("tools/validate_v0_40_dashboard_javascript_syntax.sh",)),
    ("client-disconnect response", ("tools/validate_v0_40_broken_pipe_response.sh",)),
    ("v0.42 security and integrity", (sys.executable, "tools/validate_v0_42_security_hotfix.py")),
    ("thirteen v0.42 components", ("tools/validate_v0_42_all.sh",)),
    ("v0.40 operator actions", ("tools/validate_v0_41_v0_40_compatibility.sh",)),
    ("v0.39 functional behavior", ("tools/validate_v0_40_v0_39_compatibility.sh",)),
)


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def safe_relative(value: str) -> Path:
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        fail(f"unsafe repository path in candidate inventory: {value!r}")
    return Path(*pure.parts)


def inventory(root: Path) -> list[Path]:
    completed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        check=False,
        capture_output=True,
    )
    if completed.returncode:
        fail("could not inventory the candidate repository")
    paths = []
    for raw in completed.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            relative = safe_relative(raw.decode("utf-8"))
        except UnicodeDecodeError as exc:
            fail(f"candidate contains a non-UTF-8 path: {exc}")
        if any(part in EXCLUDED_PARTS for part in relative.parts) or relative.suffix == ".pyc":
            continue
        source = root / relative
        if source.is_symlink():
            fail(f"candidate snapshot refuses symlinked repository file: {relative}")
        if source.is_file():
            paths.append(relative)
    return sorted(set(paths), key=lambda item: item.as_posix())


def snapshot_candidate(root: Path, destination: Path) -> None:
    cloned = subprocess.run(
        ["git", "clone", "--quiet", "--shared", str(root), str(destination)],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if cloned.returncode:
        fail(f"could not clone candidate history: {cloned.stderr.strip()}")
    switched = subprocess.run(
        ["git", "-C", str(destination), "switch", "-C", "main", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if switched.returncode:
        fail(f"could not prepare candidate main branch: {switched.stderr.strip()}")
    for relative in inventory(root):
        source = root / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    commands = (
        ("git", "config", "user.name", "DeltaAegis Compatibility"),
        ("git", "config", "user.email", "compatibility@deltaaegis.invalid"),
        ("git", "add", "-A"),
        (
            "git",
            "commit",
            "--quiet",
            "--allow-empty",
            "-m",
            "Candidate compatibility snapshot",
        ),
    )
    for command in commands:
        completed = subprocess.run(command, cwd=destination, check=False, capture_output=True, text=True)
        if completed.returncode:
            fail(f"could not prepare candidate snapshot ({' '.join(command)}): {completed.stderr.strip()}")


def main() -> int:
    print("DeltaAegis v0.43 / v0.42 Candidate Compatibility Validator")
    print("===========================================================")
    with tempfile.TemporaryDirectory(prefix="deltaaegis-v043-compat-") as temp_name:
        temp = Path(temp_name)
        candidate = temp / "DeltaAegis"
        snapshot_candidate(ROOT, candidate)
        env = os.environ.copy()
        env["HOME"] = str(temp / "home")
        Path(env["HOME"]).mkdir()
        env["DELTAAEGIS_V043_COMPATIBILITY"] = "1"
        for label, command in COMMANDS:
            print(f"[v0.43 compatibility] {label}")
            executable = str(candidate / command[0]) if command[0].startswith("tools/") else command[0]
            actual = (executable, *command[1:])
            completed = subprocess.run(
                actual,
                cwd=candidate,
                env=env,
                check=False,
                timeout=1200,
            )
            if completed.returncode:
                fail(f"predecessor compatibility failed: {label} (exit {completed.returncode})")
    print("PASS: v0.43 preserves v0.42 security, component, license, and install contracts")
    print("PASS: v0.43 preserves v0.40 operator-action and v0.39 functional contracts")
    print("PASS: DeltaAegis v0.43 candidate predecessor compatibility")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
