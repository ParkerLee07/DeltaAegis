#!/usr/bin/env python3
"""Validate the v0.44.1 historical-validator retirement contract."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "docs/v0.44.1-validator-retirement.json"
VALIDATOR_TOKEN = re.compile(r"validate_[A-Za-z0-9_.+-]+\.(?:sh|py)")


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def run(args: list[str], *, binary: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        cwd=ROOT,
        check=False,
        text=not binary,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def main() -> int:
    print("DeltaAegis v0.44.1 Validator Retirement Validator")
    print("====================================================")
    if not MANIFEST_PATH.is_file():
        fail("retirement manifest is missing")
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if manifest.get("format") != "deltaaegis-validator-retirement-v1":
        fail("retirement manifest format changed")
    if manifest.get("source_release") != "0.44.0" or manifest.get("archive_tag") != "v0.44.0":
        fail("retirement archive lineage changed")

    entries = manifest.get("retired_files")
    if not isinstance(entries, list) or not entries:
        fail("retired file inventory is empty")
    paths = [entry.get("path") for entry in entries]
    if any(not isinstance(path, str) or not path.startswith("tools/") for path in paths):
        fail("retired inventory contains an invalid path")
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        fail("retired inventory must be sorted and unique")
    if manifest.get("retired_file_count") != len(entries):
        fail("retired file count does not match the inventory")
    retired_validator_count = sum(Path(path).name.startswith("validate") for path in paths)
    if retired_validator_count != manifest.get("retired_validator_count"):
        fail("retired validator count does not match the inventory")

    present = [path for path in paths if (ROOT / path).exists()]
    if present:
        fail(f"retired files remain in the current tree: {present[:5]}")
    print(f"PASS: {len(paths)} retired tool files are absent from the current tree")

    archive = run(["git", "archive", "--format=tar", "v0.44.0", "--", *paths], binary=True)
    if archive.returncode:
        error = archive.stderr.decode(errors="replace")
        fail(f"could not read retirement archive tag: {error}")
    archived: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(archive.stdout), mode="r:") as bundle:
        for member in bundle.getmembers():
            if not member.isfile():
                continue
            extracted = bundle.extractfile(member)
            if extracted is not None:
                archived[member.name] = extracted.read()
    if set(archived) != set(paths):
        missing = sorted(set(paths) - set(archived))
        extra = sorted(set(archived) - set(paths))
        fail(f"archive inventory mismatch; missing={missing[:5]} extra={extra[:5]}")
    for entry in entries:
        path = entry["path"]
        content = archived[path]
        if len(content) != entry.get("bytes"):
            fail(f"archived byte count changed: {path}")
        if hashlib.sha256(content).hexdigest() != entry.get("sha256"):
            fail(f"archived SHA-256 changed: {path}")
    print("PASS: v0.44.0 tag preserves every retired file byte-for-byte")

    actual_validators = sorted(
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "tools").iterdir()
        if path.is_file() and path.name.startswith("validate")
    )
    if len(actual_validators) != manifest.get("expected_retained_validator_count"):
        fail(
            "retained validator count changed: "
            f"expected {manifest.get('expected_retained_validator_count')} "
            f"found {len(actual_validators)}"
        )
    shell_validators = sorted(
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "tools").glob("validate_*.sh")
        if path.is_file() and not path.is_symlink()
    )
    if len(shell_validators) != manifest.get("expected_shell_validator_count"):
        fail(
            "retained shell-validator count changed: "
            f"expected {manifest.get('expected_shell_validator_count')} "
            f"found {len(shell_validators)}"
        )
    print("PASS: retained validator inventory matches the retirement contract")

    replacement = manifest.get("replacement_contract")
    if not isinstance(replacement, str) or not (ROOT / replacement).is_file():
        fail("consolidated report replacement contract is missing")
    stage_path = ROOT / "tools/validate_v0_44_stage5_7_all.sh"
    stage = stage_path.read_text(encoding="utf-8")
    if stage.count(f"python3 {replacement}") != 1:
        fail("Stage 5-7 wrapper does not invoke the replacement report contract exactly once")
    for old_path in manifest.get("replaced_stage_contracts", []):
        if old_path in stage or Path(old_path).name in stage:
            fail(f"Stage 5-7 wrapper still references retired report root: {old_path}")
    replacement_run = run([sys.executable, replacement])
    if replacement_run.returncode:
        fail(f"replacement report contract failed: {replacement_run.stderr or replacement_run.stdout}")
    print("PASS: consolidated report contract replaces five retired report roots")

    retired_names = {Path(path).name for path in paths}
    for source in sorted((ROOT / "tools").iterdir()):
        if not source.is_file() or source.suffix not in {".sh", ".py"}:
            continue
        tokens = set(VALIDATOR_TOKEN.findall(source.read_text(encoding="utf-8", errors="replace")))
        overlap = sorted(tokens & retired_names)
        if overlap:
            fail(f"retained tool {source.relative_to(ROOT)} references retired validators: {overlap[:5]}")
    print("PASS: retained tools contain no validator references to retired paths")

    graph = run([
        sys.executable,
        "tools/deltaaegis_troubleshooter.py",
        "--repo",
        str(ROOT),
        "--self-check",
        "--strict-graph",
        "--json",
    ])
    if graph.returncode:
        fail(f"strict troubleshooter graph failed: {graph.stderr or graph.stdout}")
    payload = json.loads(graph.stdout)
    if payload.get("graph_ok") is not True or payload.get("cycles") != [] or payload.get("missing_references") != {}:
        fail(f"troubleshooter graph is not clean: {payload}")
    if payload.get("validator_count") != manifest.get("expected_shell_validator_count"):
        fail("troubleshooter inventory does not match the manifest")
    if payload.get("current_release_gate") != manifest.get("current_release_gate"):
        fail("troubleshooter current release gate changed")
    print("PASS: current validator graph is complete and acyclic")

    for relative, marker in (
        ("README.md", "docs/validation-retention-policy.md"),
        ("docs/TROUBLESHOOTER.md", "retained validator inventory"),
        ("docs/validation-retention-policy.md", "v0.44.0` tag preserves"),
    ):
        text = (ROOT / relative).read_text(encoding="utf-8")
        if marker not in text:
            fail(f"{relative} is missing retention-policy marker: {marker}")
    print("PASS: operator documentation explains validator retention")

    audit = run([sys.executable, "tools/audit_v0_44_repository.py", "--check"])
    if audit.returncode:
        fail(f"deterministic repository audit failed: {audit.stderr or audit.stdout}")
    whitespace = run(["git", "diff", "--check"])
    if whitespace.returncode:
        fail(f"whitespace check failed: {whitespace.stderr or whitespace.stdout}")
    print("PASS: historical-validator retirement contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
