# DeltaAegis v0.40.0 Manual Verification

**Release:** Human-Readable Operator Actions
**Publication status:** **HOLD — do not merge, tag, or publish until this checklist is completed.**

## Session and roles

- [ ] Sign in as an ADMIN and confirm the dashboard, operator session, user-management page, telemetry-reset page, and NetSniper page load normally.
- [ ] Confirm ADMIN-only controls are visible only to ADMIN users.
- [ ] Confirm ANALYST and VIEWER permissions remain unchanged.
- [ ] Confirm unauthorized requests continue to return the expected 401 or 403 responses.
- [ ] Confirm Copy JSON remains hidden until explicitly selected.

## NetSniper actions

- [ ] Import the latest completed NetSniper run and verify a concise receipt.
- [ ] Start a guarded scan and verify target, profile, job ID, and status are readable.
- [ ] Open live job detail and verify technical paths, cancellation evidence, stdout, and stderr are collapsed by default.
- [ ] Cancel a disposable test scan and verify the backend receipt appears without relying on a raw payload.
- [ ] Confirm the scan ledger and selected job detail refresh after cancellation.
- [ ] Confirm explicit raw status and job-detail links still work.

## Schedules

- [ ] Create a disposable schedule.
- [ ] Enable and disable the schedule.
- [ ] Run due schedules and confirm schedules, scan jobs, and history refresh.
- [ ] Enable and disable hourly balanced monitoring.
- [ ] Delete the disposable schedule with the exact confirmation phrase.
- [ ] Confirm linked scan jobs and schedule history remain preserved.
- [ ] Run stale-job recovery only against safe test data and confirm readable counts.

## TrueAegis

- [ ] Launch a disposable TrueAegis validation and verify the readable launch receipt.
- [ ] Confirm the command preview and technical paths are collapsed by default.
- [ ] Import a known validation result and verify the receipt.
- [ ] Confirm validation summary and observations refresh through their GET endpoints.
- [ ] Confirm explicit raw validation JSON links still work.

## Investigation workflow

- [ ] Change a disposable ticket state and verify the receipt.
- [ ] Change an asset investigation status and confirm the asset detail panel refreshes immediately.
- [ ] Confirm no full investigation-center collection is displayed as an action result.

## Administrative workflows

- [ ] Create a disposable user.
- [ ] Change the disposable user’s role.
- [ ] Disable and re-enable the disposable user.
- [ ] Rotate the disposable user’s password.
- [ ] Confirm the user table reloads after each action.
- [ ] Confirm the last-ADMIN guard remains enforced.
- [ ] Confirm user-management and access-audit details are collapsed and secrets are redacted.

## Telemetry cleanup

- [ ] Review the telemetry-cleanup preview.
- [ ] Confirm `DELETE TELEMETRY` is still required exactly.
- [ ] Use only disposable telemetry for destructive testing.
- [ ] Confirm deleted-row counts, protected-table counts, the receipt, and the audit event.
- [ ] Confirm users, sessions, API tokens, schedules, audit logs, and operator-authored context remain protected.

## Readability and technical disclosure

- [ ] Review every successful mutation surface for readable default text.
- [ ] Confirm no complete JSON payload appears automatically after an action.
- [ ] Confirm command previews, paths, metadata, logs, cancellation evidence, and audit JSON remain closed by default.
- [ ] Confirm explicit raw links and Copy JSON controls remain available.
- [ ] Confirm errors retain enough technical context to diagnose failures.

## Final local checks

- [ ] Run `./tools/validate_v0_40_release_gate.sh`.
- [ ] Run `python3 -W error::SyntaxWarning -m py_compile deltaaegis.py`.
- [ ] Run `git diff --check`.
- [ ] Confirm `git status --short` is empty.
- [ ] Restart the normal DeltaAegis service.
- [ ] Review the browser console and server logs while exercising the workflows above.
- [ ] Review `README.md`, `CHANGELOG.md`, and `RELEASE_NOTES_v0.40.0.md`.

## Approval

- [ ] Parker approves the dashboard behavior.
- [ ] Parker approves the release notes.
- [ ] Only after approval: merge the feature branch into `main`.
- [ ] Run the release gate again on merged `main`.
- [ ] Only after the merged gate passes: create and push tag `v0.40.0`.
- [ ] Only after tag verification: publish the GitHub release.

## Client-disconnect response handling

- [ ] Start a dashboard refresh and immediately refresh again or close the tab.
- [ ] Confirm the dashboard process does not print a `BrokenPipeError` traceback.
- [ ] Confirm a subsequent clean refresh still returns dashboard API responses normally.
- [ ] Confirm unexpected server errors are not silently hidden.
