# ADR 0006: Persist jobs and keep workers responsible for processes

- Status: Accepted
- Date: 2026-07-13
- Applies to: scan, schedule, and TrueAegis execution

## Context

NetSniper scans and TrueAegis validations outlive individual HTTP requests. DeltaAegis already records lifecycle, PID, heartbeat, logs, cancellation, watchdog, and finalization evidence. Weakening that boundary would reintroduce orphaned work and browser-controlled process risk.

## Decision

Every external execution is represented by a durable job before process launch. Workers use fixed argument vectors, isolated process groups, confined log paths, bounded output, and explicit terminal states. The worker—not the browser—owns PID signaling, cancellation escalation, completion evidence, ingest, and schedule reconciliation.

Startup and scheduler passes reconcile stale or orphaned jobs using PID identity, heartbeat age, expected command, and trusted completion artifacts. Reconciliation is idempotent and auditable. Queue reservation and active-job invariants are transactional.

## Consequences

- Arbitrary command text and shell execution remain prohibited.
- v0.44 extracts job ownership without changing state semantics.
- v0.47 changes active-scan concurrency from global to per-sensor only after sensor identity exists.
- Future service managers integrate at the worker boundary rather than bypassing the job ledger.
