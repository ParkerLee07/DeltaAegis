# DeltaAegis Supported Versions

Status: v0.45.0 telemetry trust

This matrix defines the environment DeltaAegis intends to validate on the path to v1.0. A listed platform is supported only when its operating-system vendor still supplies security maintenance and the installed components remain within the ranges below.

## Runtime matrix

| Component | Supported baseline | Policy |
|---|---|---|
| Operating system | Debian 12 and 13; Ubuntu 22.04 LTS and 24.04 LTS; Kali Linux rolling snapshots whose packages satisfy this matrix | 64-bit Linux only. Clean-install and upgrade gates must cover Debian and Ubuntu. Kali is validated at release time because it is rolling. |
| Python | CPython 3.10 through 3.14 | The system/vendor Python is preferred. The lowest and highest supported minor versions must pass syntax and focused compatibility validation before v1.0. Python 3.10 remains supported on vendor-maintained distributions even after upstream security-only support ends. |
| SQLite | 3.37 or newer through Python's standard `sqlite3` module | Foreign keys must be enabled by DeltaAegis. WAL/sidecar handling, backup, integrity, and migration behavior are release-gated. No external SQLite server is required. |
| NetSniper | v2.0.0 for DeltaAegis v0.43 through v0.46 | Finalized manifest-v3 bundles, compatibility aliases, checksums, profile evidence, and bundle-readiness evidence are required. NetSniper changes are defect-driven until sensor identity work begins with DeltaAegis v0.47. |
| TrueAegis | Contract-compatible local checkout | TrueAegis is optional. The checkout must support fixed-argv `trueaegis.py MANIFEST --validate --quiet` execution and the validation JSON contract covered by DeltaAegis fixtures. A semantic-version pin is required before v1.0; the absence of one is tracked architecture debt, not permission to accept arbitrary output. |
| Node.js | Active LTS or Maintenance LTS; Node 20, 22, and 24 are the v0.44 validation range | Node.js is a validator dependency for rendered dashboard JavaScript, not a DeltaAegis runtime service. |
| Browser | Current and previous stable Firefox, Chrome/Chromium, or Edge | JavaScript, cookies, Fetch, and same-origin behavior are required. Safari and mobile browsers are best-effort until a release gate explicitly adds them. |
| Git | 2.39 or newer | Required for source installation, release gates, source-state verification, and operator-managed upgrades. |

## Integration contracts

- DeltaAegis consumes only finalized NetSniper run directories whose manifest and referenced evidence pass confinement, checksum, readiness, and compatibility validation.
- `network_scope` remains the authoritative technical CIDR key through v0.44. Logical-site names are presentation groupings, not evidence identity.
- TrueAegis observations are evidence-only until correlated by DeltaAegis. A validation result does not silently mutate NetSniper observations.
- Node.js and a browser do not receive direct filesystem or database access.

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
