# DeltaAegis v1 Stage 1–2 compatibility evidence

The combined checkpoint preserves released behavior while intentionally replacing two historical test-fixture assumptions that are unsafe for a ledgered migration system.

## Retained contracts

The combined gate directly reruns:

- v0.45 deep-hardening, NetSniper context, telemetry decision, durable storage, projection/effects, ingest-transition, and review contracts;
- the v0.44 authentication and Sites/Jobs/Reports modular boundaries;
- the v0.42 security and integrity hotfix contract;
- the v0.40 dashboard JavaScript and broken-pipe response contracts; and
- the core unit regression suite.

Two additive transition validators preserve the characterized v0.45 Quality Center and private route/rendering inventory while proving that stable routes exactly match the v1 OpenAPI inventory.

## Superseded fixture assumptions

The frozen v0.42 component suite creates isolated partial-table SQLite fixtures and then asks the application connection path to fill in the rest. Stage 1 deliberately rejects partial, ambiguous, and definition-drifted unledgered databases. Supported upgrades instead start from exact complete v0.42.0, v0.42.1, or v0.42.2 schemas and are exhaustively exercised by `validate_v1_stage1_migrations.py`.

The frozen v0.42 install lifecycle also copies only the eight v0.44 extraction modules, and the v0.45 Quality Center validator expects two later modules to remain optional. Stage 1 makes `current_state`, `telemetry_quality`, `migrations`, and `api_v1` required install components so a supported installation cannot silently create a partial database. `validate_v1_stage1_2_install_lifecycle.sh` replaces that fixture with a complete disposable install, migration, bootstrap, reinstall, uninstall, purge, and evidence-preservation exercise.

These are explicit transition replacements, not silent waivers. Immutable historical validators remain unchanged and available for their original release tags.

## Gate

Run the complete checkpoint gate from a clean candidate checkout:

```bash
./tools/validate_v1_0_stage1_2_gate.sh
```

`--allow-dirty` exists only for disposable development and guarded-installer validation. It snapshots the exact dirty inventory and fails if validation changes it.
