# DeltaAegis v1.0 combined Stage 1–2 checklist

This checklist approves only the combined migration and stable-API checkpoint. It is not authorization to tag `v1.0.0`; all ten items in `V1_SCOPE.md` remain mandatory for GA.

## Baseline

- [ ] Candidate is a descendant of released v0.45.0 commit `493df20dabed527757381e3cbae7cad3201b9c57`, or a disposable source witness proves the exact released tree before a live-main application.
- [ ] NetSniper v2.1.0 remains pinned and unchanged at `0624a36550f6eb62ed0daa6862e5cc25a0d93236`.
- [ ] TrueAegis remains an explicit later GA compatibility blocker until a semantic-version contract is published or pinned.
- [ ] Candidate validation runs in a disposable checkout with no live database, runtime, NetSniper, TrueAegis, tag, release, or remote mutation.

## Stage 1 — migrations and recovery

- [ ] Exact v0.42.0, v0.42.1, and v0.42.2 tag commits and source hashes match the documented pins.
- [ ] Clean and telemetry-expanded databases built from the exact v0.45.0 release tree upgrade successfully.
- [ ] Fresh and all supported upgrade origins converge on the same schema.
- [ ] The ordered ledger validates IDs, checksums, timestamps, origin, application version, and outcome evidence.
- [ ] Recorded schema fingerprints form a contiguous chain and the latest outcome matches the live schema.
- [ ] A verified SQLite-consistent pre-migration backup precedes all legacy schema mutation.
- [ ] Each migration and its ledger row commit atomically.
- [ ] Interruption injection passes after backup and at apply, validation, ledger, and commit boundaries.
- [ ] Protected evidence/operator history, foreign keys, and SQLite integrity remain valid.
- [ ] Restore rehearsal reproduces the exact pre-migration logical fingerprint.
- [ ] Concurrent startup applies the migration sequence once and creates one backup.
- [ ] Unsupported, ambiguous, symlinked, and tampered database cases fail closed.

## Stage 2 — stable API and web security

- [ ] Runtime OpenAPI 3.1 equals `contracts/v1/openapi.json`.
- [ ] Stable endpoint, permission, request, response, pagination, and error inventories validate.
- [ ] Programmatic access accepts only one scoped Authorization Bearer token.
- [ ] Default and maximum token lifetimes, role caps, scope caps, demotion, revocation, expiration, and malformed scopes pass.
- [ ] Cookie mutations require same-origin double-submit CSRF backed by server session state.
- [ ] GET remains read-only, including logout.
- [ ] Host validation ignores untrusted forwarding headers, rejects invalid authority, and accepts only an explicitly configured HTTPS proxy origin when secure cookies are enabled.
- [ ] Security headers cover JSON, HTML, text, redirect, success, and error responses.
- [ ] UTF-8 JSON object, media type, content length, transfer encoding, and 65,536-byte body boundaries pass.
- [ ] Exact, conflicting, failed, and concurrent idempotency cases pass without duplicate domain rows.
- [ ] Unversioned `/api/*` routes remain private compatibility interfaces and are not implicitly stable.

## Combined gate

```bash
./tools/validate_v1_0_stage1_2_gate.sh
```

- [ ] Shell and Python syntax pass.
- [ ] Stage 1 validator passes.
- [ ] Stage 2 real-HTTP validator passes.
- [ ] OpenAPI artifact matches runtime generation byte-for-byte.
- [ ] Applicable v0.45 telemetry-trust and predecessor compatibility tests pass or have explicit transition evidence.
- [ ] `docs/v1-stage1-2-compatibility.md` matches the exact frozen-fixture replacements used by the gate.
- [ ] Core unit regressions and the v1 install/uninstall lifecycle pass.
- [ ] Deterministic repository audit matches.
- [ ] Validation leaves the checkout clean.

## Handoff

- [ ] Review the exact diff and validator logs before applying any guarded installer to the live repository.
- [ ] Record backup paths and checksums in the installer receipt.
- [ ] Do not merge, tag, publish, delete branches, or touch live runtime state without a separate explicit authorization step.
- [ ] Carry unresolved Definition-of-Done items 4, 5, 7, 8, 9, and 10 into the next v1 stages.
