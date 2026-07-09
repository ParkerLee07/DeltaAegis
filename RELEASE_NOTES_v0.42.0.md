# DeltaAegis v0.42.0 — Logical Site Scopes

DeltaAegis v0.42.0 introduces operator-facing logical sites above the existing CIDR network scopes. The release lets an operator group related private subnets into a building or site without weakening the technical boundaries used for scanning, snapshot history, asset identity, events, alerts, risk, and evidence.

## Dead-scan watchdog and scheduler self-healing

The dashboard scheduler now checks active NetSniper ledger rows before applying the one-active-scan lock. The check runs at dashboard startup, on every schedule-worker pass, and before manual or CLI due-schedule execution.

The watchdog uses the most recent heartbeat as the primary liveness timestamp and verifies the recorded PID against `/proc/<pid>/cmdline`. It automatically fails only stale rows whose process is missing or whose PID now belongs to an unrelated command. It does not kill or fail a still-live expected NetSniper process.

Recovery evidence is stored under `status_json.watchdog`, including the original PID, heartbeat, update time, stdout and stderr paths, classification, and recovery actor. After safe recovery, the same worker pass may start the oldest overdue schedule.

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
