# DeltaAegis v0.42.0 Manual Verification

Use this checklist after the release-candidate commit and before merge, tag, or publication.

## 1. Repository state

- [ ] Confirm the branch is `feature/v0.42-logical-site-scopes`.
- [ ] Confirm the working tree is clean.
- [ ] Record the release-candidate commit.
- [ ] Confirm `main`, `origin/main`, and tag `v0.41.0` still point to the prior release.
- [ ] Confirm no local or remote `v0.42.0` tag exists.

```bash
git status --short
git branch --show-current
git rev-parse HEAD
git rev-parse main
git rev-parse origin/main
git tag --list 'v0.42*'
```

## 2. Complete automated release gate

- [ ] Run the clean release gate.
- [ ] Confirm every v0.42 component validator runs exactly once through `validate_v0_42_all.sh`.
- [ ] Confirm the gate ends with a publication hold.

```bash
tools/validate_v0_42_release_gate.sh
```

## 3. Version and documentation

- [ ] Confirm `deltaaegis.py --help` identifies `DeltaAegis v0.42.0 — Logical Site Scopes`.
- [ ] Review `README.md`.
- [ ] Review `CHANGELOG.md`.
- [ ] Review `RELEASE_NOTES_v0.42.0.md`.
- [ ] Confirm the README Current Release section does not still advertise v0.41.0.
- [ ] Confirm the docs state that CIDR `network_scope` remains authoritative.
- [ ] Confirm the docs state the one-site-per-subnet invariant.
- [ ] Confirm NetSniper and TrueAegis operational workflows remain subnet-specific.
- [ ] Confirm rehearsal examples use an explicit temporary database.

```bash
python3 deltaaegis.py --help
```

## 4. Safe CLI rehearsal

Use a temporary database. Do not use the active evidence database for this rehearsal.

```bash
tmp_dir="$(mktemp -d -t deltaaegis-v042-manual-XXXXXX)"
tmp_db="$tmp_dir/deltaaegis.db"

python3 deltaaegis.py --db "$tmp_db" \
  site-create \
  "Manual Verification Site" \
  --description "Temporary v0.42 manual verification site." \
  --json
```

- [ ] Record the returned stable site ID.
- [ ] Assign `192.168.44.0/24`.
- [ ] Assign `192.168.45.0/24`.
- [ ] Confirm both appear in `site-show`.
- [ ] Confirm `scopes --unassigned --json` excludes assigned members.
- [ ] Confirm a duplicate assignment fails clearly.
- [ ] Confirm a public CIDR assignment fails.
- [ ] Rename the site and update its description.
- [ ] Archive the site and confirm memberships remain.
- [ ] Confirm a new assignment to the archived site fails.
- [ ] Remove one membership and confirm no site record is deleted.

```bash
python3 deltaaegis.py --db "$tmp_db" site-list --json
python3 deltaaegis.py --db "$tmp_db" site-show SITE_ID --json
python3 deltaaegis.py --db "$tmp_db" \
  site-assign-scope SITE_ID 192.168.44.0/24 --json
python3 deltaaegis.py --db "$tmp_db" \
  site-assign-scope SITE_ID 192.168.45.0/24 --json
```

## 5. Authenticated dashboard rehearsal

Create a temporary password user or use an explicit temporary token with the temporary database.

```bash
python3 deltaaegis.py --db "$tmp_db" dashboard \
  --host 127.0.0.1 \
  --port 8091 \
  --token v042-manual-token \
  --no-enable-scheduled-scans
```

- [ ] Confirm unauthenticated `/api/sites` returns `401`.
- [ ] Confirm authenticated `/api/sites` lists the rehearsal site.
- [ ] Confirm authenticated `/api/site-detail?site_id=SITE_ID` lists both members.
- [ ] Confirm the dashboard renders logical-site navigation.
- [ ] Confirm the site view states that core aggregation is active.
- [ ] Confirm selecting a member subnet produces subnet-specific drilldown.
- [ ] Confirm an unknown site returns `404`.
- [ ] Confirm a request containing both `scope` and `site_id` returns `400`.
- [ ] Confirm an unsupported site-selected endpoint fails closed rather than showing global data.

## 6. Aggregation semantics

Using temporary fixtures or an approved non-production database:

- [ ] Confirm a site view includes only member subnet scopes.
- [ ] Confirm an unrelated subnet is excluded.
- [ ] Confirm current state combines one latest accepted state per observed member subnet.
- [ ] Confirm unobserved members remain visible in coverage metadata.
- [ ] Confirm every aggregated asset/event/alert/risk row retains `network_scope`.
- [ ] Confirm duplicate MAC or IP identities in separate subnets remain separate.
- [ ] Confirm asset detail becomes ambiguous when one identifier matches multiple member scopes.
- [ ] Confirm scan freshness reflects the least healthy member subnet.

## 7. Guarded LAN binding

Use a trusted test LAN and an authenticated temporary database.

```bash
python3 deltaaegis.py --db "$tmp_db" dashboard \
  --lan \
  --port 8092 \
  --token v042-lan-manual-token \
  --no-enable-scheduled-scans
```

- [ ] Confirm the listener binds to `0.0.0.0:8092`.
- [ ] Confirm another authorized LAN device can reach the login/token-protected dashboard.
- [ ] Confirm `--lan` without a password user or token is rejected.
- [ ] Confirm the dashboard is not exposed beyond the intended trusted network.

```bash
ss -ltnp | grep ':8092'
```

## 8. Active database protection

- [ ] Hash `data/deltaaegis.db` before and after the release gate.
- [ ] Hash the ignored root `deltaaegis.db` before and after the release gate if present.
- [ ] Confirm both hashes are unchanged.
- [ ] Confirm all manual mutation rehearsals used `--db "$tmp_db"`.

## 9. Merge and merged-main gate

Only after the feature-branch gate and manual checks pass:

- [ ] Obtain Parker's explicit approval to merge.
- [ ] Merge the release candidate into `main`.
- [ ] Run the clean release gate again on merged `main`.
- [ ] Confirm the release gate accepts `main`.
- [ ] Confirm `main` and `origin/main` are synchronized only after explicit push approval.

## 10. Tag and publication hold

Only after the merged-main gate passes and Parker explicitly approves publication:

- [ ] Create annotated tag `v0.42.0`.
- [ ] Confirm the dereferenced tag points to the final main release commit.
- [ ] Push the tag only with explicit approval.
- [ ] Create the GitHub Release only with explicit approval.
- [ ] Use the title `DeltaAegis v0.42.0 — Logical Site Scopes`.
- [ ] Use `RELEASE_NOTES_v0.42.0.md` as the release body.

Passing this checklist does not itself authorize merge, push, tagging, or publication.
