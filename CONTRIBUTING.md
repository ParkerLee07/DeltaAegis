# Contributing to DeltaAegis

DeltaAegis accepts focused, reviewable changes that preserve evidence integrity and the supported upgrade path.

## Before changing code

- Open or document the problem, expected behavior, and affected trust boundary.
- For storage, API, identity, authentication, job, backup, compatibility, or deprecation changes, update or add an architecture decision before implementation.
- Keep each change scoped to one release objective. Broad rewrites require an approved incremental extraction plan.
- Never include real credentials, tokens, customer data, private scan bundles, or identifying network evidence in tests.

## Validation expectations

- Add a focused automated validator for every defect fix or contract change.
- Use synthetic or temporary data and fixed argument vectors.
- Run `git diff --check`, Python syntax checks, the focused validator, and the current release gate.
- Preserve predecessor compatibility until a documented deprecation has completed.
- Keep CHANGELOG cumulative. Do not add tracked manual checklists or version-specific release-note files.

## Review priorities

Reviewers prioritize data preservation, authorization, path confinement, safe process execution, deterministic behavior, migration safety, and clear operator evidence over feature volume.

## Licensing boundary

The repository's `LICENSE` and `LICENSING.md` remain authoritative. This contribution guide does not add a contributor agreement, change the AGPL-3.0-only license, or create commercial-license terms. Any alternative commercial arrangement is handled separately in writing by the project owner.
