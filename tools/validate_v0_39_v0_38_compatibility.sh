#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

baseline_commit="df29cc9"

echo "DeltaAegis v0.39 / v0.38 Compatibility Validator"
echo "=================================================="

if ! git cat-file -e "${baseline_commit}^{commit}" 2>/dev/null; then
  echo "ERROR: required v0.39 feature baseline is unavailable: ${baseline_commit}" >&2
  exit 1
fi

echo "[compatibility] verifying release-only source delta"

python3 - "$baseline_commit" <<'PY'
from pathlib import Path
import subprocess
import sys


baseline_commit = sys.argv[1]

baseline = subprocess.run(
    ["git", "show", f"{baseline_commit}:deltaaegis.py"],
    check=True,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
).stdout

current = Path("deltaaegis.py").read_text(encoding="utf-8")

replacements = [
    (
        '"""DeltaAegis v0.38.0: TrueAegis Follow-Up Automation.',
        '"""DeltaAegis v0.39.0: Scan Job Lifecycle Observability.',
        "module release title",
    ),
    (
        (
            '<div class="executive-status-pill"><span>Release</span>'
            '<span>v0.38 TrueAegis Follow-Up Automation</span></div>'
        ),
        (
            '<div class="executive-status-pill"><span>Release</span>'
            '<span>v0.39 Scan Job Lifecycle Observability</span></div>'
        ),
        "dashboard release pill",
    ),
    (
        'server_version = "DeltaAegisDashboard/0.5.0"',
        'server_version = "DeltaAegisDashboard/0.39.0"',
        "dashboard server version",
    ),
    (
        (
            'parser = argparse.ArgumentParser(description="DeltaAegis v0.38.0 — '
            'TrueAegis Follow-Up Automation, guarded scheduled validation, strict '
            'accepted-ingest gating, provenance-linked jobs, validation correlation, '
            'reporting, RBAC, and the current-state SIEM dashboard")'
        ),
        (
            'parser = argparse.ArgumentParser(description="DeltaAegis v0.39.0 — '
            'Scan Job Lifecycle Observability, live NetSniper execution evidence, '
            'authenticated cancellation, non-destructive schedule deletion, guarded '
            'TrueAegis follow-up automation, reporting, RBAC, and the current-state '
            'SIEM dashboard")'
        ),
        "CLI release description",
    ),
]

expected = baseline

for old, new, label in replacements:
    count = expected.count(old)

    if count != 1:
        raise SystemExit(
            f"feature baseline has unexpected {label} count: {count}"
        )

    expected = expected.replace(old, new, 1)

if current != expected:
    raise SystemExit(
        "deltaaegis.py contains changes beyond the four approved v0.39 "
        "release-metadata replacements relative to df29cc9"
    )

print("PASS: current source differs from df29cc9 only by approved release metadata")
PY

temporary_worktree="$(mktemp -d -t deltaaegis-v039-v038-compat.XXXXXX)"
worktree_added=0

cleanup() {
  if [[ "$worktree_added" -eq 1 ]]; then
    git worktree remove --force "$temporary_worktree" >/dev/null 2>&1 || true
  fi

  rm -rf "$temporary_worktree"
}
trap cleanup EXIT

git worktree add --quiet --detach "$temporary_worktree" "$baseline_commit"
worktree_added=1

compatibility_validators=(
  tools/validate_v0_38_trueaegis_followup_intent.sh
  tools/validate_v0_38_trueaegis_followup_planner.sh
  tools/validate_v0_38_trueaegis_followup_queue.sh
  tools/validate_v0_38_trueaegis_followup_execution.sh
  tools/validate_v0_38_trueaegis_ingest_provenance.sh
  tools/validate_v0_38_trueaegis_execution_modes.sh
  tools/validate_v0_38_due_schedule_followup_intent.sh
)

for validator in "${compatibility_validators[@]}"; do
  validator_path="$temporary_worktree/$validator"

  if [[ ! -x "$validator_path" ]]; then
    echo "ERROR: missing executable compatibility validator: $validator" >&2
    exit 1
  fi

  echo "[v0.38 compatibility sandbox] $(basename "$validator")"
  (
    cd "$temporary_worktree"
    "$validator"
  )
done

echo "PASS: isolated v0.38 TrueAegis follow-up compatibility suite"
