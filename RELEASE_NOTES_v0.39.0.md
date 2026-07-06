# DeltaAegis v0.39.0 — Scan Job Lifecycle Observability

DeltaAegis v0.39.0 makes dashboard-launched and scheduled NetSniper scans observable and controllable throughout their complete lifecycle without weakening the existing fixed-command or role-based security boundaries.

## Highlights

### Persistent lifecycle state

Scan jobs now persist explicit `QUEUED`, `RUNNING`, `COMPLETED`, `FAILED`, and `CANCELLED` states together with creation, start, heartbeat, cancellation, and finish metadata.

### Live execution evidence

The dashboard and read-only job-detail API expose the worker-owned process ID, heartbeat, bounded live stdout, and bounded live stderr while a scan is active. Automatic detail polling stops when the job reaches a terminal state.

### Authenticated cancellation

ADMIN-authorized operators can request cancellation through the dedicated scan-cancel API and dashboard control. Cancellation reasons and server-derived requester identity are preserved. The worker owns process-group termination, including graceful termination and escalation when necessary.

### Non-destructive schedule deletion

Deleting a saved schedule removes the active schedule definition but preserves every linked scan job and its original schedule evidence. A deletion tombstone keeps the removed schedule definition, linked-job status summary, and history visible. Active jobs are not implicitly cancelled.

## Security boundaries

- NetSniper execution continues to use a fixed argument vector rather than raw shell commands.
- There is no browser-supplied PID and no browser-side signal control.
- Cancellation is a dedicated authenticated action and is not implied by schedule deletion.
- Job-detail log reads remain bounded and confined to the configured scan-log root.
- Only one active NetSniper scan job is permitted at a time.

## Upgrade notes

Existing databases are upgraded through normal DeltaAegis schema initialization. The v0.39 validators cover fresh schema creation, legacy migration, migration idempotence, lifecycle serialization, cancellation metadata, and schedule-deletion tombstones.

No runtime-data reset is required.

## Validation

Run the complete release gate from a clean checkout:

```bash
./tools/validate_v0_39_release_gate.sh
```

For the pre-commit release-hardening checkpoint only:

```bash
./tools/validate_v0_39_release_gate.sh --allow-dirty
```
