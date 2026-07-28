# DeltaAegis v1.0 Product Scope

Status: finalized for DeltaAegis v1.0.1 Maintenance Release
## Delivery status — 2026-07-27

DeltaAegis v1.0.0 delivers the completed Stage 1–5 migration, recovery, stable
API, web-security, sensor/scope identity, deterministic detection, operations,
performance, and integration scope defined below.

The uninterrupted 24-hour release-evidence soak completed with 1,431 samples
and zero integrity, readiness, or unplanned-worker failures. The final blocker
audit found no open security, integrity, migration, data-loss, authorization,
supported-platform, or release-evidence blocker. Main CI and the supported
release matrix passed on the exact merged runtime candidate, and every
post-soak correction was confined to CI or release metadata with runtime and
operational Git objects unchanged.

## Maintenance status — 2026-07-28

DeltaAegis v1.0.1 does not expand the v1.0 product scope. It corrects dashboard
SQLite connection ownership so forward migrations execute once before the
threaded server starts and ordinary runtime connections do not enter the
migration transaction.

Pull request #9 merged the exact validated hotfix as main commit
`836b2ac25e27c344f292e2a9cacbe0a4f757fe1f`. The 12-check focused regression,
clean-main complete gate, and exact-main CI run `30393445773` passed. The
database schema, migration checksums, stable API, identity, detection, evidence,
and integration promises below remain unchanged. No additional 24-hour soak was
required.

## Product definition

DeltaAegis v1.0 is a self-hosted, single-node network-state monitoring and investigation console. It accepts finalized evidence from authorized NetSniper sensors, preserves normalized history in SQLite, explains meaningful changes, and gives a local operator durable investigation, validation, backup, and reporting workflows.

DeltaAegis is the history, correlation, orchestration, and analyst-workflow layer. NetSniper remains the telemetry sensor. TrueAegis remains an optional defensive validation producer.

## v1.0 promises

### Stable storage and upgrades

- A documented and tested upgrade path from every DeltaAegis v0.42.x database to v1.0.
- Forward-only, transactional schema migrations with durable migration identity.
- A verified pre-migration backup and a rehearsable recovery path.
- Preservation of accepted snapshots, asset history, events, alerts, investigations, logical sites, audit evidence, and job history during supported upgrades.

### Stable API

- A documented `/api/v1` namespace with machine-readable schemas and consistent success and error envelopes.
- Authentication and authorization rules documented per endpoint.
- Compatibility and deprecation rules defined by ADR 0009.
- Existing unversioned dashboard endpoints remain implementation interfaces until explicitly promoted or deprecated.

### Identity and evidence

- Durable sensor and scope identities that safely distinguish reused or overlapping CIDRs.
- Traceability from normalized observations to the sensor bundle and scan that supplied them.
- Replay and duplicate-ingest protection for sensor evidence.
- Logical sites remain operator-defined groupings and never replace technical scope identity.

### Deterministic detection

- Versioned, explainable rules evaluated from preserved evidence.
- Idempotent evaluation with rule version and evidence provenance in every result.
- Explicit suppression and review state; no silent autonomous response.

### Security

- Loopback-only default dashboard binding.
- Local users, bounded sessions, API tokens, role-based authorization, CSRF protection, secure response headers, and auditable administrative actions.
- No arbitrary shell command execution. External tools run with fixed argument vectors and confined paths.
- Secrets, password material, and raw tokens are excluded from reports and routine diagnostics.

### Operations and recovery

- Durable scan and validation job states with restart reconciliation and bounded log visibility.
- Health, readiness, structured diagnostics, backup verification, restore rehearsal, and safe uninstall behavior.
- Documented installation, upgrade, rollback, troubleshooting, and support boundaries.
- A reproducible release gate and a supported-version matrix.

## Supported deployment shape

- One DeltaAegis application/database node operated by one organization or household.
- One or more enrolled NetSniper v2.1 sensors, each with explicit authorized scope identities.
- Private IPv4 network monitoring; every scan requires an operator-authorized target.
- Local filesystem storage with SQLite and local process execution.
- Browser access from a trusted administrative network when LAN binding is explicitly enabled.

## Explicit v1.0 exclusions

- Multi-node high availability, database clustering, or cloud control-plane service.
- A generic enterprise log-ingestion or full SOC data-lake platform.
- Arbitrary remote command execution, exploitation, persistence, or autonomous remediation.
- Public-Internet scanning or targets outside the private IPv4 policy boundary.
- Native IPv6 discovery and identity unless a later approved scope amendment adds and validates it.
- Enterprise SSO, hosted multi-tenancy, mobile applications, and third-party plugin execution.
- Guaranteed compatibility with undocumented NetSniper or TrueAegis output.

## Definition of done

All ten definition-of-done items are complete for DeltaAegis v1.0.0:

1. [x] A clean install and every supported v0.42.x upgrade path pass on the supported platform matrix.
2. [x] Migration interruption, backup verification, restore rehearsal, and rollback tests pass without loss of protected history.
3. [x] `/api/v1` is documented, schema-validated, authenticated, authorized, and covered by compatibility tests.
4. [x] Sensor/scope identity and overlapping-CIDR fixtures pass without cross-scope evidence leakage.
5. [x] Detection results are deterministic, versioned, explainable, idempotent, and traceable to source evidence.
6. [x] CSRF, session, token, security-header, bind-boundary, path-confinement, and privilege-revocation tests pass.
7. [x] Health/readiness, structured diagnostics, clean install, service operation, uninstall, and low-resource tests pass.
8. [x] Performance targets are defined from the v0.43 baseline, met by the release, and confirmed by the required 24-hour release-evidence soak.
9. [x] NetSniper and TrueAegis compatibility contracts are pinned and verified with fixtures.
10. [x] No open release-blocking security, integrity, migration, data-loss, authorization, supported-platform, or release-evidence defect remains.
## Scope change control

A proposed v1.0 addition must identify which promise or definition-of-done item it enables. Additions that do not advance one of those outcomes are deferred. Changes to this file require a documented architecture decision or an explicit maintainer-approved scope amendment.
