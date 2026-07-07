# DeltaAegis v0.40.0 — Human-Readable Operator Actions

DeltaAegis v0.40.0 makes dashboard actions understandable by default without removing the structured JSON interfaces needed for automation, diagnostics, and evidence review.

## Highlights

### Stable action receipts

Successful dashboard mutations now return a shared `deltaaegis-dashboard-action-receipt-v1` contract with a stable action identifier, severity, human-readable message, concise summary, identifiers, and optional diagnostic detail.

Receipt coverage includes:

- NetSniper import, scan start, and scan cancellation.
- Scan schedule creation, enable/disable, deletion, run-due execution, hourly monitoring, and stale-job recovery.
- TrueAegis validation launch and result ingestion.
- Ticket status and asset investigation actions.
- Administrative user actions and telemetry cleanup.

### Human-readable operator output

Mutation results render concise outcomes instead of automatically displaying complete JSON payloads. Error messages remain visible and actionable.

Raw API responses and copied JSON remain available only through explicit technical controls such as raw endpoint links, Copy JSON, or expandable detail panels.

### Progressive technical disclosure

Command previews, filesystem paths, latest-run metadata, cancellation evidence, bounded stdout/stderr tails, and audit-event JSON are collapsed by default under technical-detail controls.

This keeps the normal operator workflow readable while preserving complete diagnostic evidence when it is deliberately requested.

### Mutation and read-model separation

Mutation responses no longer embed refreshed schedule, scan-job, validation-observation, or administrative-user collections when the dashboard already reloads those resources through dedicated GET endpoints.

Action-specific objects and identifiers remain available. Asset investigation detail and telemetry cleanup table models remain intentional exceptions because their interfaces consume the immediate mutation result directly.

### Release safety

The v0.40 release gate validates:

- The shared receipt schema and functional receipt generation.
- NetSniper, schedule, TrueAegis, workflow, and administrative action coverage.
- Progressive disclosure and payload/list-detail separation.
- Scan-cancellation receipt completion.
- README, changelog, source, dashboard, and CLI release metadata.
- Rendered dashboard JavaScript syntax across the main, NetSniper, user-management, and telemetry-reset pages.
- Client-disconnect handling for abandoned JSON responses, including normal-response preservation and narrow exception coverage.
- The complete v0.39 lifecycle, cancellation, HTTP, and schedule-deletion functional suite in an isolated compatibility clone.
- Repository cleanliness, source compilation, and branch-path accuracy.

## Security boundaries preserved

- No arbitrary shell command execution is exposed through the dashboard.
- NetSniper and TrueAegis execution remain fixed argument-vector operations.
- The browser never supplies a process ID or sends operating-system signals.
- Destructive telemetry cleanup remains ADMIN-only, confirmation-gated, and audited.
- Schedule deletion never implies scan-job cancellation.
- Secrets, passwords, password hashes, API-token hashes, and raw session tokens are not rendered in receipts or audit tables.
- Risk scoring and event-generation policy are unchanged.

## Validation

Run the complete automated gate:

```bash
./tools/validate_v0_40_release_gate.sh
```

For the pre-commit release-hardening checkpoint only:

```bash
./tools/validate_v0_40_release_gate.sh --allow-dirty
```

Complete `MANUAL_VERIFICATION_v0.40.0.md` before merging, tagging, or publishing the release.
