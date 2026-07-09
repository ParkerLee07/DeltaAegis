# DeltaAegis v0.42.0 — Logical Site Scopes

DeltaAegis v0.42.0 introduces operator-facing logical sites above the existing CIDR network scopes. The release lets an operator group related private subnets into a building or site without weakening the technical boundaries used for scanning, snapshot history, asset identity, events, alerts, risk, and evidence.

## Dead-scan watchdog and scheduler self-healing

The dashboard scheduler now checks active NetSniper ledger rows before applying the one-active-scan lock. The check runs at dashboard startup, on every schedule-worker pass, and before manual or CLI due-schedule execution.

The watchdog uses the most recent heartbeat as the primary liveness timestamp and verifies the recorded PID against `/proc/<pid>/cmdline`. It automatically fails only stale rows whose process is missing or whose PID now belongs to an unrelated command. It does not kill or fail a still-live expected NetSniper process.

Recovery evidence is stored under `status_json.watchdog`, including the original PID, heartbeat, update time, stdout and stderr paths, classification, and recovery actor. After safe recovery, the same worker pass may start the oldest overdue schedule.



## Dashboard evidence freshness

A shared freshness strip now remains visible across every main dashboard tab. It exposes accepted evidence time, import time, evidence age, and the browser's last refresh as separate clocks. Site and all-scopes views show their newest and oldest scope timestamps and warn when evidence ages are mixed or any selected scope is stale or lacks an accepted scan.

This checkpoint is presentation-only: it does not delete historical evidence, alter risk scores, or silently downgrade stored findings.

The mixed-age warning no longer appears solely because selected
subnets were scanned at different times. It appears only when at least one
subnet is backed by evidence more than 24 hours old or has no accepted scan.
Every affected subnet is identified with its supporting scan ID and evidence
age.

## Sites dashboard UX

Sites management now presents styled dashboard controls and an explicit
unassigned-subnet catalog instead of requiring operators to infer which
subnet scopes are available. ADMIN users may select subnet checkboxes
during site creation, and the backend creates the site and memberships in
one transaction. The site-name field no longer contains an
organization-specific example.

## Scheduled scan finalization recovery

A dashboard shutdown during a scheduled scan could terminate the daemon
worker while the independent NetSniper process continued. NetSniper could
then finish successfully while DeltaAegis retained a stale `RUNNING` row,
omitted the bundle from schedule history, and repeatedly restarted the
same oldest-overdue subnet.

The recovery path now validates trusted completion evidence, reconciles
the original job, performs idempotent auto-ingest, advances the linked
schedule, and permits the next overdue subnet to run. Failed dead-job
recovery also advances schedule history. A normal dashboard shutdown waits
for an active scheduled scan to finish finalization.

## TrueAegis tab containment

A delayed TrueAegis orchestration render previously created a new top-level tab panel after the dashboard had already applied the active-tab visibility state. That panel could therefore remain visible while Executive was selected.

The orchestration renderer now mounts its full controls and job table inside the existing static TrueAegis foundation panel. Its parent tab controls visibility from the beginning of the page lifecycle. Executive receives a separate compact readiness card with no run controls, paths, receipts, job table, imports, observations, or correlations.

No TrueAegis execution, RBAC, safety, ingestion, polling, API, receipt, or subnet-boundary semantics changed.

## Sites dashboard management

A dedicated **Sites** tab now exposes the logical-site model as an operator workflow instead of requiring CLI-only administration. VIEWER and ANALYST accounts receive read-only site, membership, coverage, archive, and unassigned-scope visibility. ADMIN accounts can create, rename, describe, archive, assign, and remove through fixed JSON routes.

The browser never accepts caller-selected actors, database paths, shell commands, SQL, or arbitrary route names. The authenticated session supplies the audit actor. Existing private-CIDR validation, case-insensitive site-name uniqueness, one-site-per-subnet membership, archived-site assignment rejection, and historical-evidence retention remain authoritative.

The Executive selector remains a compact navigation surface for site-wide aggregation and member-subnet drilldown.

## Logical-site model

A logical site is an additive parent object:

```text
one logical site -> many private CIDR subnet scopes
one subnet scope -> zero or one logical site
```

Canonical CIDR `network_scope` values remain authoritative. NetSniper still scans private CIDRs, and asset lifecycle identity remains scoped by `(network_scope, asset_key)`.

Logical sites have:

- Stable generated site IDs.
- Case-insensitive unique names.
- Optional descriptions.
- Active and archived states.
- Retained memberships when archived.
- Membership removal without telemetry deletion.

Archived sites cannot receive new subnet assignments.

## CLI management

v0.42 adds:

```text
site-list
site-show
site-create
site-rename
site-description
site-archive
site-assign-scope
site-remove-scope
```

The existing `scopes` command now supports logical-site assignment information, `--unassigned`, and JSON output.

Mutating commands write structured access-audit events. Membership assignment accepts private CIDR scopes only. Commands support human-readable output and structured `--json` receipts.

For a non-production rehearsal, use an explicit temporary database:

```bash
python3 deltaaegis.py --db /tmp/deltaaegis-site-rehearsal.db \
  site-create "Rehearsal Site"
```

## Dashboard and API

Authenticated viewers can use:

```text
GET /api/sites
GET /api/site-detail?site_id=...
```

The main dashboard selector displays logical sites and their member subnet scopes. Selecting a site carries `site_id` to supported read-only endpoints.

Core site aggregation covers:

- Summary metrics.
- Latest accepted current state from each observed member subnet.
- Scan context and scan-job history.
- Assets.
- Events and alerts.
- Annotations.
- MAC-port behavior.
- Current and historical risk.
- Investigation Center.
- Latest network changes.
- Scan freshness.

Aggregated rows retain `network_scope`, `site_id`, and a collision-safe scope-qualified key. Identical MAC or IP identities in different subnet scopes are not silently collapsed.

A request containing both `scope` and `site_id` is rejected. Unknown sites return an error, and site-selected endpoints without a defined aggregation contract fail closed instead of falling back to global data.

Asset detail and ticket evidence require subnet drilldown when an identifier matches more than one member scope.

## Operational boundaries

NetSniper scan creation remains CIDR-targeted. A logical site is not passed to Nmap as a synthetic scan target.

TrueAegis execution also remains subnet-specific. The site view may aggregate read-only evidence and status, but the operator must select one member subnet before starting an operational validation workflow.

No logical-site dashboard mutation endpoint is included in v0.42. Site management remains an audited local CLI workflow.

## Guarded LAN dashboard access

The dashboard gains:

```bash
python3 deltaaegis.py dashboard --lan --port 8090
```

`--lan` binds to `0.0.0.0` only when an active password user exists or an explicit token is supplied. Unauthenticated LAN exposure is rejected.

The built-in server uses HTTP. Use it only on a trusted LAN or place DeltaAegis behind an HTTPS reverse proxy for broader deployment.

## Validation

The v0.42 release gate verifies:

- Clean-tree enforcement, with an explicit pre-commit `--allow-dirty` mode.
- Feature-branch and merged-`main` release paths.
- Python syntax and repository hygiene.
- Source, README, changelog, release-note, and manual-verification metadata.
- Rendered dashboard JavaScript syntax.
- Client-disconnect response handling.
- Logical-site schema, migration, and invariants.
- Guarded LAN binding.
- CLI behavior, JSON receipts, and access-audit events.
- Authenticated site APIs and selector behavior.
- Site aggregation totals, latest-per-member current state, provenance, identity-collision safety, unrelated-subnet exclusion, and fail-closed HTTP routing.
- Isolated v0.40 operator-action and v0.39 functional compatibility suites.
- Protection of the active and ignored legacy root databases during checkpoint validation.

Run:

```bash
tools/validate_v0_42_release_gate.sh
```

Complete `MANUAL_VERIFICATION_v0.42.0.md` before merge, tag, or publication.

## Publication hold

Passing the automated gate does not authorize publication. Merge, tag, push, and GitHub Release creation require Parker's explicit approval.
