#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "[v0.38 release] checkpoint 7 dependency"
tools/validate_v0_38_due_schedule_followup_intent.sh

echo "[v0.38 release] syntax check"
python3 -m py_compile deltaaegis.py

echo "[v0.38 release] metadata and copy checks"
python3 - <<'PY'
from pathlib import Path
import re

readme = Path("README.md").read_text(encoding="utf-8")
changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
source = Path("deltaaegis.py").read_text(encoding="utf-8")

required_readme = [
    "## Current Release — v0.38.0",
    "**DeltaAegis v0.38.0 — TrueAegis Follow-Up Automation**",
    "run_trueaegis_after_ingest",
    "81 imported validation observations",
    "does not expose arbitrary shell command execution",
]

for needle in required_readme:
    if needle not in readme:
        raise SystemExit(f"README missing v0.38 release marker: {needle}")

if readme.find("## Current Release — v0.38.0") > readme.find("## Current Release — v0.37.0") >= 0:
    raise SystemExit("README still presents v0.37 before the v0.38 current release")

if not changelog.startswith(
    "## DeltaAegis v0.38.0 — TrueAegis Follow-Up Automation"
):
    raise SystemExit("CHANGELOG does not begin with the v0.38 release section")

required_changelog = [
    "structured auto-ingest evidence",
    "persisted `ACCEPTED` snapshot",
    "synchronous CLI execution",
    "TrueAegis job provenance",
    "Fixed due-schedule loading",
    "validate_v0_38_release.sh",
]

for needle in required_changelog:
    if needle not in changelog:
        raise SystemExit(f"CHANGELOG missing v0.38 release detail: {needle}")

source_required = [
    '"""DeltaAegis v0.38.0: TrueAegis Follow-Up Automation.',
    "DeltaAegis v0.38.0 — TrueAegis Follow-Up Automation",
    "Run TrueAegis automatically after a completed scheduled scan is accepted by DeltaAegis",
    "TrueAegis follow-up is eligible for automated queueing and execution.",
    "TrueAegis follow-up job queued for guarded automated execution.",
    "v0.38 TrueAegis Follow-Up Automation",
]

for needle in source_required:
    if needle not in source:
        raise SystemExit(f"deltaaegis.py missing v0.38 release marker: {needle}")

for forbidden in [
    "v0.38.0-dev",
    "follow-up automation planning",
    "eligible to be queued by a later v0.38 checkpoint",
    "execution is deferred to a later v0.38 checkpoint",
    "execution is added in a later v0.38 checkpoint",
    'description="DeltaAegis v0.37.0',
]:
    if forbidden in source:
        raise SystemExit(f"stale pre-release copy remains in deltaaegis.py: {forbidden}")

if "## DeltaAegis v0.37.0 — Operator Evidence Review" not in changelog:
    raise SystemExit("v0.37 changelog history was not preserved")

expected_validators = [
    "tools/validate_v0_38_trueaegis_followup_intent.sh",
    "tools/validate_v0_38_trueaegis_followup_planner.sh",
    "tools/validate_v0_38_trueaegis_followup_queue.sh",
    "tools/validate_v0_38_trueaegis_followup_execution.sh",
    "tools/validate_v0_38_trueaegis_ingest_provenance.sh",
    "tools/validate_v0_38_trueaegis_execution_modes.sh",
    "tools/validate_v0_38_due_schedule_followup_intent.sh",
]

for name in expected_validators:
    path = Path(name)
    if not path.is_file() or not path.stat().st_mode & 0o111:
        raise SystemExit(f"missing or non-executable v0.38 validator: {name}")

print("metadata and copy checks passed")
PY

echo "[v0.38 release] CLI help smoke test"
python3 - <<'PYCLI'
import subprocess


def command_output(*args: str) -> str:
    completed = subprocess.run(
        args,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return " ".join(completed.stdout.split())


help_output = command_output(
    "python3",
    "deltaaegis.py",
    "--help",
)

schedule_help = command_output(
    "python3",
    "deltaaegis.py",
    "schedule-create",
    "--help",
)

checks = [
    (
        "main CLI release title",
        "DeltaAegis v0.38.0 — TrueAegis Follow-Up Automation",
        help_output,
    ),
    (
        "schedule follow-up option",
        "--trueaegis-after-ingest",
        schedule_help,
    ),
    (
        "schedule follow-up help copy",
        (
            "Run TrueAegis automatically after a completed scheduled "
            "scan is accepted by DeltaAegis"
        ),
        schedule_help,
    ),
]

for label, expected, output in checks:
    if expected not in output:
        raise SystemExit(
            f"CLI help missing {label}: {expected}\n"
            f"Normalized output:\n{output}"
        )

print("CLI help smoke test passed")
PYCLI

echo "[v0.38 release] release safety checks"
python3 - <<'PY'
from pathlib import Path

source = Path("deltaaegis.py").read_text(encoding="utf-8")

start = source.find("def build_trueaegis_validation_command(")
end = source.find("\ndef ", start + 5)

if start < 0 or end < 0:
    raise SystemExit("could not isolate build_trueaegis_validation_command")

block = source[start:end]

for forbidden in [
    "shell=True",
    "os.system(",
    "subprocess.Popen(",
]:
    if forbidden in block:
        raise SystemExit(f"unsafe command construction found: {forbidden}")

if "return [" not in block:
    raise SystemExit("TrueAegis command builder does not return a fixed argv list")

print("release safety checks passed")
PY

echo "[v0.38 release] PASS"
