# Validator Retention Policy

Status: current through DeltaAegis v0.45.0; v0.44.1 repository-hygiene policy retained

DeltaAegis keeps validators required by the current release gate, current staged
checkpoint diagnostics, the supported compatibility floor, installation
lifecycle checks, and repository troubleshooting. The default branch is not an
archive of every release gate or validator ever published.

## Current compatibility floor

The retained automated floor covers:

- v0.39 scan lifecycle, HTTP, cancellation, and schedule behavior;
- v0.40 operator-action behavior;
- v0.41 data-durability, backup, retention, restore-rehearsal, and guarded-cutover behavior;
- v0.42 security, logical-site, installation, and license contracts;
- the complete v0.44 modular-core boundary suite and staged diagnostics; and
- the v0.44.1 repository-hygiene, retention, and durability release gate.

The v0.44.1 report-contract validator replaces five pre-v0.39 report roots:

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

## Retired historical tooling

The v0.44.1 hygiene maintenance retires 219 tool files:

- 216 validator scripts; and
- 3 non-validator historical tools.

The second retirement wave removes superseded v0.40 through v0.44 release-only
gates, release metadata, release documentation validators, and the v0.43 audit
and benchmark generators. Current functional validators and v0.44 staged
checkpoint wrappers remain available in the working tree.

Exact paths, byte sizes, line counts, and SHA-256 digests are recorded in
`docs/v0.44.1-validator-retirement.json`.

The verified `v0.44.0` tag preserves every retired file byte-for-byte. Inspect a
retired file without changing the working tree:

```bash
git show v0.44.0:tools/<retired-file>
```

Run a historical release-only suite from a detached worktree instead of
restoring obsolete files to current `main`:

```bash
temporary="$(mktemp -d)"
git worktree add --detach "$temporary" v0.44.0
# Run the historical command inside "$temporary".
git worktree remove --force "$temporary"
```

The frozen v0.43 performance artifacts remain under `docs/`. Their retired
benchmark generator is available from the same tag when exact historical
regeneration is required.

## Future retirement requirements

Additional retirement is allowed only when all of the following are true:

1. a current release gate owns the replacement behavior;
2. the strict troubleshooter graph remains complete and acyclic;
3. CI and the deterministic repository audit reflect the retained inventory;
4. exact retired bytes remain available from an immutable release tag; and
5. the complete disposable release gate passes before commit or publication.
