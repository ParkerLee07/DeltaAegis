# DeltaAegis v1 combined Stage 3–5 implementation

Status: implementation candidate; the 24-hour GA soak is not yet claimed

The release soak must start from a database copy whose origin passes Stage 1.
Long-lived v0.45 databases may carry the exact audited historical additive
schema fingerprint `5c777b2a731133a8793c6710eda3e1a18b15deb9ffa416bed71ffd70e11581ef`;
that complete fingerprint is supported while all partial or unknown drift still
fails closed.

## Upgrade boundary

This upgrade is additive to the completed Stage 1–2 tree. It introduces two
forward migrations and three internal modules:

| Migration/module | Responsibility |
|---|---|
| `0004-v1-sensor-scope-identity` / `identity.py` | Durable sensors and scopes, explicit legacy attribution, source/internal scan identity, evidence receipts, scope heads, isolated current state, and scope/site membership |
| `0005-v1-deterministic-detection` / `detection.py` | Versioned rules, deterministic immutable results, canonical provenance and explanations, and separate append-only review state |
| `operations.py` | Public liveness, authenticated readiness and diagnostics, compatibility pins, performance thresholds, and soak policy |

Migration IDs and checksums are recorded in `schema_migrations`. The checksums
for migrations 0001–0003 remain frozen. Migration 0004 assigns all supported
legacy records to `sensor-legacy-local`; rows without attributable CIDR use
`scope-legacy-unassigned`. It never infers that equal CIDRs observed by two
managed sensors represent the same network.

## Sensor and scope rules

- A managed sensor must be enrolled with at least one private IPv4 CIDR.
- `scope_id` is a deterministic hash of `sensor_id` and canonical CIDR.
- Source scan IDs remain traceable. A managed sensor receives a namespaced
  internal scan ID so two sensors may use the same producer run ID safely.
- A sensor/source-scan pair is bound to one bundle digest. Exact replay is
  idempotent; a different digest fails closed.
- Current-state ordering uses evidence time plus internal scan identity. Older
  evidence is retained but cannot replace the scope head.
- Logical sites group scope IDs. They never replace technical evidence identity.
- Scan reservation is serialized and limited to one queued/running job per
  sensor, allowing independent sensors to work concurrently.
- Assigned TrueAegis result hosts must be IP addresses contained by the
  selected scope. Validation run and observation IDs include sensor/scope
  provenance.

## Detection rules and review state

`contracts/v1/detection-rules.json` is the tracked ruleset. Each result stores:

- `rule_id`, `rule_version`, and result schema version;
- sensor, scope, source scan, internal scan, quality decision, and bundle digest;
- canonical event evidence and its SHA-256;
- a structured human explanation; and
- a deterministic result ID derived from those immutable inputs.

Database triggers reject update or delete of results and reviews. `REVIEWED`,
`SUPPRESSED`, and `UNSUPPRESSED` actions append to `detection_reviews`; they do
not modify source evidence or the detection record. Stable HTTP mutations use
the Stage 2 idempotency contract in addition to domain-level replay safety.

## Operations and integration contracts

`GET /api/v1/health` is public and reports process liveness only.
`GET /api/v1/readiness` and `/api/v1/diagnostics` require `operations.read`.
Readiness checks the complete migration ledger, SQLite quick and foreign-key
checks, write capability, job states, identity and detection schemas,
configured integrations, and database capacity. Diagnostics are bounded and
redact credential-bearing keys.

The exact integration contract is tracked at
`contracts/v1/integration-compatibility.json`:

- NetSniper v2.1.0 commit
  `0624a36550f6eb62ed0daa6862e5cc25a0d93236`;
- TrueAegis `>=1.2.0,<2.0.0`, witness commit
  `16b9e88b232aac568859ab8d68e2eaa26558c4e7`; and
- `trueaegis-validation-results-v1` JSON-array result shape.

## Validation

Run the complete implementation gate from a clean Stage 3–5 branch:

```bash
./tools/validate_v1_0_stage3_5_gate.sh
```

The gate preserves the complete Stage 1–2 and v0.45 predecessor floor, then
tests identity conflict/ordering/overlap, per-sensor jobs, TrueAegis scope
containment, immutable detection replay and reviews, new stable endpoints,
readiness failure injection, bounded diagnostics, low-resource operation,
install lifecycle, and v0.43-derived performance thresholds.

The short soak run inside the gate validates the harness only. It is not GA
evidence. Collect the release receipt separately:

```bash
python3 tools/run_v1_stage5_soak.py \
  --db data/deltaaegis.db \
  --output reports/v1-soak-receipt.json \
  --duration-hours 24 \
  --interval-seconds 60 \
  --release-evidence
```

Interrupted, shortened, not-ready, integrity-failing, or newly failed-worker
runs exit nonzero and cannot set `release_eligible`.
