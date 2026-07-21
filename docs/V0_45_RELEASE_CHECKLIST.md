# DeltaAegis v0.45.0 Release Checklist

Release: **DeltaAegis v0.45.0 — Telemetry Trust**

Automated validation does not replace manual operator review.

## Automated candidate requirements

- [ ] Clean working tree.
- [ ] `tools/validate_v0_45_release_gate.sh` passes on the feature branch.
- [ ] The same gate passes in a disposable clean checkout.
- [ ] Runtime, CLI, dashboard badge, HTTP server, and troubleshooter identify
      `0.45.0`.
- [ ] README and CHANGELOG identify v0.45.0 as current.
- [ ] Focused telemetry-trust and predecessor compatibility gates each run once.
- [ ] Deep bug-fix regression validator passes for evidence confinement, transaction atomicity, capability fail-closed behavior, zero-host semantics, dashboard escaping, scope-aware risk, and snapshot ordering.
- [ ] Deterministic repository audit is current.
- [ ] CI invokes the release gate exactly once.

## Manual dashboard verification

- [ ] Login and first-admin behavior remain correct.
- [ ] Release badge reads `v0.45.0 Telemetry Trust`.
- [ ] Telemetry Quality Center requires authentication.
- [ ] VIEWER cannot review or override.
- [ ] ANALYST can add an allowed review annotation.
- [ ] Only ADMIN can apply a policy-permitted override.
- [ ] `REJECTED` cannot be overridden.
- [ ] Accepted, degraded, quarantined, and rejected fixtures show expected
      reasons and effect boundaries.
- [ ] Degraded evidence cannot remove assets or services.
- [ ] Quarantined and rejected evidence cannot mutate current state.
- [ ] Reviewed-scope rebuild is deterministic.
- [ ] Asset detail shows NetSniper v2.1 evidence context without exposing it in
      compact list payloads.
- [ ] Telemetry-quality Markdown report renders.
- [ ] Existing Sites, NetSniper, TrueAegis, schedules, investigations, reports,
      backup, and restore workflows remain accessible.

## Explicit approval holds

Each action requires separate explicit maintainer approval:

- [ ] Staging and committing the release-hardening candidate.
- [ ] Pushing the feature branch.
- [ ] Creating or updating the pull request.
- [ ] Merging the pull request into `main`.
- [ ] Creating or moving the annotated `v0.45.0` tag.
- [ ] Pushing the `v0.45.0` tag.
- [ ] Publishing the GitHub Release.
- [ ] Deleting the local or remote feature branch.

A broad instruction such as “finish the release” does not satisfy these holds.
