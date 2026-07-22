# DeltaAegis Supported Versions

Status: v0.45.0 release plus v1.0 combined Stage 3–5 candidate

This matrix defines the environment DeltaAegis intends to validate on the path to v1.0. A listed platform is supported only when its operating-system vendor still supplies security maintenance and the installed components remain within the ranges below.

## Runtime matrix

| Component | Supported baseline | Policy |
|---|---|---|
| Operating system | Debian 12 and 13; Ubuntu 22.04 LTS and 24.04 LTS; Kali Linux rolling snapshots whose packages satisfy this matrix | 64-bit Linux only. Clean-install and upgrade gates must cover Debian and Ubuntu. Kali is validated at release time because it is rolling. |
| Python | CPython 3.10 through 3.14 | The system/vendor Python is preferred. The lowest and highest supported minor versions must pass syntax and focused compatibility validation before v1.0. Python 3.10 remains supported on vendor-maintained distributions even after upstream security-only support ends. |
| SQLite | 3.37 or newer through Python's standard `sqlite3` module | Foreign keys must be enabled by DeltaAegis. WAL/sidecar handling, backup, integrity, and migration behavior are release-gated. No external SQLite server is required. |
| NetSniper | v2.1.0 pinned at `0624a36550f6eb62ed0daa6862e5cc25a0d93236`; v2.0 evidence remains degraded-compatible | Finalized manifest-v3 bundles, compatibility aliases, checksums, profile evidence, bundle-readiness evidence, and the complete v2.1 capability contract are required for accepted telemetry. |
| TrueAegis | Optional `>=1.2.0,<2.0.0`; witness commit `16b9e88b232aac568859ab8d68e2eaa26558c4e7` | The checkout must support fixed-argv validation and the pinned `trueaegis-validation-results-v1` JSON-array contract. Assigned result hosts must be contained by the selected sensor scope. |
| Node.js | Active LTS or Maintenance LTS; Node 20, 22, and 24 are the v0.44 validation range | Node.js is a validator dependency for rendered dashboard JavaScript, not a DeltaAegis runtime service. |
| Browser | Current and previous stable Firefox, Chrome/Chromium, or Edge | JavaScript, cookies, Fetch, and same-origin behavior are required. Safari and mobile browsers are best-effort until a release gate explicitly adds them. |
| Git | 2.39 or newer | Required for source installation, release gates, source-state verification, and operator-managed upgrades. |

## Integration contracts

- DeltaAegis consumes only finalized NetSniper run directories whose manifest and referenced evidence pass confinement, checksum, readiness, and compatibility validation.
- `sensor_id` plus deterministic `scope_id` is the authoritative v1 technical identity. `network_scope` remains its compatibility attribute. Logical-site names are presentation groupings, never evidence identity.
- TrueAegis observations are evidence-only until correlated by DeltaAegis. A validation result does not silently mutate NetSniper observations.
- Node.js and a browser do not receive direct filesystem or database access.

## v1 combined upgrade and API support

- Exact database origins created by v0.42.0, v0.42.1, and v0.42.2 are covered
  by the automated migration gate. Their schema is byte-identical; tag source
  hashes remain separate validation evidence.
- Clean and telemetry-runtime-expanded databases built from the exact released
  v0.45.0 tree are independently upgraded and checked for convergence and
  protected-history preservation.
- The active SQLite database must be on a local filesystem and must not be a
  symlink. Pending legacy upgrades create and verify a pre-migration backup.
- The initial supported programmatic namespace is `/api/v1` as documented in
  `docs/api-v1.md` and `contracts/v1/openapi.json`.
- Browser support requires SameSite cookies, Fetch, Origin headers, and the
  Stage 2 CSRF boundary. HTTPS proxy deployments must configure both
  `dashboard --secure-cookies` and the exact HTTPS `--public-origin`; the
  proxy must preserve that authority in `Host`.
- Frozen partial-schema and minimal-module fixtures are superseded only as
  documented in `docs/v1-stage1-2-compatibility.md`; immutable release-tag
  copies remain unchanged.
- Migration 0004 assigns legacy rows to `sensor-legacy-local` and an explicit
  deterministic or unassigned scope; it never guesses that reused CIDRs across
  managed sensors are the same observation domain.
- Migration 0005 creates immutable detection and review ledgers. Result IDs
  include rule version, sensor scope, source evidence, and canonical event
  evidence so replay is stable and cross-scope collision is prevented.
- The implementation gate includes low-resource operation and the tracked
  performance targets. Production v1.0 support remains release-candidate-only
  until a clean 24-hour soak receipt and final blocker audit are reviewed.

## Version policy before v1.0

- Minor `0.x` releases may add planned architecture and behavior while retaining the documented upgrade path from v0.42.x.
- Patch releases contain compatible defect, security, documentation, installer, or validator corrections.
- A breaking storage, API, identity, or evidence-contract change requires an ADR, migration/compatibility tests, and cumulative CHANGELOG entry.
- Current and future support claims are enforced by automated gates where practical and by operator-managed environment verification where a matrix cannot run locally.

## Version policy after v1.0

- DeltaAegis follows semantic versioning for public API, supported storage/upgrade, and integration contracts.
- The latest minor release receives fixes. The previous minor receives critical security and data-integrity fixes for at least 90 days after its successor.
- Deprecation follows ADR 0009. Emergency removal of an unsafe interface may shorten the notice period and must be documented in the cumulative CHANGELOG.

## Unsupported configurations

- End-of-life operating systems or Python versions outside the declared range.
- Windows or macOS as production hosts.
- Network filesystems for the active SQLite database.
- Public, multicast, unspecified, loopback, or otherwise non-private scan targets.
- Unversioned or modified sensor output that fails the bundle contract.
- Multiple DeltaAegis processes writing the same active database unless a release explicitly validates that topology.

## Release evidence

`docs/performance-baseline.md` records the exact interpreter, SQLite, platform, and Node.js versions used for the v0.43 measurements. Release publication must report which supported environments were actually exercised; this document does not claim that an untested environment was tested.
