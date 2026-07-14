#!/usr/bin/env python3
"""Run retained v0.41 data-durability validators in isolated main candidates."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
VALIDATORS = (
    "tools/validate_v0_41_backup_foundation.sh",
    "tools/validate_v0_41_backup_manifest.sh",
    "tools/validate_v0_41_restore_rehearsal.sh",
    "tools/validate_v0_41_backup_catalog.sh",
    "tools/validate_v0_41_backup_retention_preview.sh",
    "tools/validate_v0_41_backup_retention_execution.sh",
    "tools/validate_v0_41_restore_cutover_preview.sh",
    "tools/validate_v0_41_restore_cutover_execution.sh",
)


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def run(args: list[str], *, cwd: Path, env: dict[str, str] | None = None, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        env=env,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )


def main() -> int:
    print("DeltaAegis v0.44.1 Data Durability Compatibility Validator")
    print("============================================================")
    for relative in VALIDATORS:
        path = ROOT / relative
        if not path.is_file() or not path.stat().st_mode & 0o111:
            fail(f"missing executable durability validator: {relative}")

    with tempfile.TemporaryDirectory(prefix="deltaaegis-v0441-durability-") as temp_name:
        temporary = Path(temp_name)
        for relative in VALIDATORS:
            name = Path(relative).stem
            candidate = temporary / name / "DeltaAegis"
            home = temporary / name / "home"
            home.mkdir(parents=True)
            cloned = run(
                ["git", "clone", "--quiet", "--no-local", str(ROOT), str(candidate)],
                cwd=ROOT,
                timeout=120,
            )
            if cloned.returncode:
                fail(f"could not clone durability candidate for {relative}: {cloned.stderr.strip()}")
            switched = run(
                ["git", "checkout", "--quiet", "-B", "main", "HEAD"],
                cwd=candidate,
                timeout=30,
            )
            if switched.returncode:
                fail(f"could not prepare candidate main for {relative}: {switched.stderr.strip()}")

            env = os.environ.copy()
            env.update({
                "HOME": str(home),
                "CI": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
            })
            print(f"[v0.44.1 durability] {Path(relative).name}")
            try:
                completed = run(
                    ["bash", str(candidate / relative)],
                    cwd=candidate,
                    env=env,
                    timeout=600,
                )
            except subprocess.TimeoutExpired as exc:
                output = (exc.stdout or "") + (exc.stderr or "")
                if output:
                    print(output, end="" if output.endswith("\n") else "\n")
                fail(f"durability validator timed out: {relative}")
            if completed.stdout:
                print(completed.stdout, end="" if completed.stdout.endswith("\n") else "\n")
            if completed.stderr:
                print(completed.stderr, file=sys.stderr, end="" if completed.stderr.endswith("\n") else "\n")
            if completed.returncode:
                fail(f"durability validator failed: {relative} (exit {completed.returncode})")

    print("PASS: all eight retained v0.41 durability validators ran once")
    print("PASS: DeltaAegis v0.44.1 preserves data durability and recovery behavior")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
