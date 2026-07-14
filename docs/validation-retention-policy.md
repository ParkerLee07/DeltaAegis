# Validator Retention Policy

Status: DeltaAegis v0.44.1 repository-hygiene maintenance

DeltaAegis keeps validators required by the current release gate, current staged
checkpoint wrappers, supported compatibility floor, installation lifecycle
checks, and repository diagnostics. The default branch is not an archive of
every validator ever published.

## Current compatibility floor

The retained automated floor covers:

- v0.39 scan lifecycle, HTTP, cancellation, and schedule behavior;
- v0.40 operator-action behavior;
- v0.41 data-durability, backup, retention, restore-rehearsal, and guarded-cutover behavior;
- v0.42 security, logical-site, installation, and license contracts;
- the complete v0.44 modular-core boundary suite; and
- the v0.44.1 repository-hygiene and retention release gate.

The v0.44.1 report-contract validator replaces the five pre-v0.39 report roots
formerly called by `tools/validate_v0_44_stage5_7_all.sh`:

- `tools/validate_v0_15_port_behavior_report.sh`
- `tools/validate_v0_16_investigation_center_report.sh`
- `tools/validate_v0_20_report_ticket_evidence.sh`
- `tools/validate_v0_22_report_triage_summary.sh`
- `tools/validate_v0_34_report_correlation.sh`

Their current behavior is consolidated in
`tools/validate_v0_44_1_report_contracts.py`, which checks MAC-port report
rendering, Investigation Command Center triage output, ticket-evidence appendix
collection and rendering, and TrueAegis correlation reporting without carrying
obsolete recursive release chains.

## Retired historical validators

The v0.44.1 hygiene maintenance removes 200
validator scripts and 1 legacy
verifier outside the current compatibility composition. Exact paths, byte
sizes, line counts, and SHA-256 digests are recorded in
`docs/v0.44.1-validator-retirement.json`.

The verified `v0.44.0` tag preserves the exact pre-retirement contents. Inspect
a retired file without changing the working tree:

```bash
git show v0.44.0:tools/<retired-file>
```

Run historical suites from a detached worktree at the relevant release tag
rather than restoring obsolete scripts to current `main`:

```bash
temporary="$(mktemp -d)"
git worktree add --detach "$temporary" v0.44.0
# Run the historical command inside "$temporary".
git worktree remove --force "$temporary"
```

## Further retirement

Later cleanup may remove additional v0.40-v0.43 release-only scaffolding, but
only after the v0.44.1 release gate, retained functional compatibility suites,
troubleshooter graph, CI, and deterministic audit prove that no executable
dependency remains. Every
retirement change must update the manifest and preserve the prior tree in an
immutable release tag.
