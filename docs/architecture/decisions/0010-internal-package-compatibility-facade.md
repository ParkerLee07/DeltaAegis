# ADR 0010: Internal package and compatibility facade

- Status: Accepted
- Date: 2026-07-13
- Applies to: v0.44 modular extraction through the v1.0 compatibility window

## Context

DeltaAegis historically exposes a repository-root `deltaaegis.py` executable
that is also imported directly by tests and operator integrations.  Creating a
regular Python package named `deltaaegis` beside that file would make import
resolution choose the package in common environments, silently shadowing the
existing module.  A namespace directory does not solve the inverse problem:
once `deltaaegis.py` is imported, it is not a package that can own
`deltaaegis.config` submodules.

Moving the complete application into a same-named package in one release would
also invalidate source-characterization validators and combine a packaging
transition with the extraction of security- and evidence-sensitive behavior.

## Decision

v0.44 extracts implementation into the non-conflicting internal package
`deltaaegis_core`.  The repository-root `deltaaegis.py` remains the executable
and compatibility facade, re-exporting established constants and callables.
Each extraction checkpoint must characterize the old contract before moving
ownership and must retain behavior-level predecessor validation.

The first checkpoint moves default-path construction and low-level SQLite
connection creation.  `SCHEMA_SQL`, schema bootstrap, compatibility additions,
and the public `connect` function remain in the facade until the forward-only
migration ledger has its own checkpoint.

No directory named `deltaaegis` may be introduced while `deltaaegis.py` remains
the supported import target.  A future same-named package transition requires a
separate ADR, deprecation plan, and import-compatibility release.

## Consequences

- Existing `python3 deltaaegis.py`, `import deltaaegis`, CLI, and validator
  entry points keep resolving to the historical facade.
- Internal ownership can move incrementally without import shadowing.
- The internal package name is not a promised third-party API.
- Some facade aliases remain intentionally until their consumers and static
  compatibility checks have migrated.
- v0.45 can introduce migration ownership without coupling that change to the
  initial connection extraction.
