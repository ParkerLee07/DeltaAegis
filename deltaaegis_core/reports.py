from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

PORT_BEHAVIOR_HIGH_SIGNAL_PORTS = {21, 23, 445, 1433, 1521, 2375, 2376, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017}
PORT_BEHAVIOR_MEDIUM_SIGNAL_PORTS = {22, 111, 135, 139, 161, 389, 636, 2049, 5985, 5986, 8080, 8443}
PORT_BEHAVIOR_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


@dataclass(frozen=True)
class ReportContext:
    dashboard_enrich_classification_rows: Callable[..., Any]
    dashboard_ticket_evidence_payload: Callable[..., Any]
    dashboard_validation_summary_payload: Callable[..., Any]
    dashboard_validations_payload: Callable[..., Any]
    fetch_latest_accepted_snapshot: Callable[..., Any]
    investigation_center_signal_summary: Callable[..., Any]
    investigation_center_workflow_summary: Callable[..., Any]
    load_mac_open_ports_for_scans: Callable[..., Any]
    operator_triage_summary: Callable[..., Any]


def safe_markdown(value):
    if value is None:
        return '-'
    return str(value).replace('|', '\\|').replace('\n', ' ').strip() or '-'


def collect_report_alert_notes(connection, alert_ids):
    alert_ids = [alert_id for alert_id in alert_ids if alert_id is not None]
    if not alert_ids:
        return {}
    placeholders = ', '.join(['?'] * len(alert_ids))
    rows = connection.execute(f'\n        SELECT note_id, alert_id, action, reason, created_at\n        FROM alert_notes\n        WHERE alert_id IN ({placeholders})\n        ORDER BY alert_id ASC, note_id ASC\n        ', tuple(alert_ids)).fetchall()
    notes_by_alert = {}
    for row in rows:
        notes_by_alert.setdefault(row['alert_id'], []).append(row)
    return notes_by_alert


def report_alert_review_rows(connection, subjects, limit):
    subjects = [str(subject or '').strip() for subject in subjects]
    subjects = [subject for subject in subjects if subject]
    if not subjects:
        return []
    unique_subjects = []
    for subject in subjects:
        if subject not in unique_subjects:
            unique_subjects.append(subject)
    placeholders = ', '.join(['?'] * len(unique_subjects))
    rows = connection.execute(f'\n        SELECT\n            a.alert_id,\n            a.status,\n            a.severity,\n            a.event_type,\n            a.subject_key,\n            a.summary,\n            n.note_id,\n            n.action,\n            n.reason,\n            n.created_at\n        FROM alerts a\n        JOIN alert_notes n ON n.alert_id = a.alert_id\n        WHERE a.subject_key IN ({placeholders})\n        ORDER BY n.created_at DESC, n.note_id DESC\n        LIMIT ?\n        ', tuple(unique_subjects) + (limit,)).fetchall()
    return rows


def append_report_alert_notes(lines, notes):
    lines.append('')
    lines.append('**Review notes:**')
    lines.append('')
    if not notes:
        lines.append('- No review notes have been recorded for this alert.')
        return
    for note in notes:
        lines.append(f"- `{safe_markdown(note['created_at'])}` **{safe_markdown(note['action'])}** — {safe_markdown(note['reason'])}")


def report_annotation_candidates(subject_key):
    raw = str(subject_key or '').strip()
    candidates = []

    def add(value):
        value = str(value or '').strip()
        if value and value not in candidates:
            candidates.append(value)
    add(raw)
    service_match = re.match('^(.+):(tcp|udp)/\\d+$', raw, re.IGNORECASE)
    if service_match:
        base = service_match.group(1)
        add(base)
        if base.startswith('ip:'):
            add(base[3:])
    if raw.startswith('ip:'):
        add(raw[3:])
    return candidates


def fetch_report_asset_annotation(connection, subject_key):
    for candidate in report_annotation_candidates(subject_key):
        annotation = connection.execute('\n            SELECT asset_key, owner, role, criticality, notes, updated_at\n            FROM asset_annotations\n            WHERE asset_key = ?\n            ', (candidate,)).fetchone()
        if annotation is not None:
            return (annotation, candidate)
    return None


def collect_report_asset_context(connection, subjects):
    context = {}
    for subject in subjects:
        subject = str(subject or '').strip()
        if not subject or subject in context:
            continue
        match = fetch_report_asset_annotation(connection, subject)
        if match is not None:
            context[subject] = match
    return context


def append_report_asset_context(lines, annotation, matched_key):
    lines.append('')
    lines.append('**Asset context:**')
    lines.append('')
    lines.append(f'- Matched annotation: `{safe_markdown(matched_key)}`')
    lines.append(f"- Owner: **{safe_markdown(annotation['owner'] or '-')}**")
    lines.append(f"- Role: **{safe_markdown(annotation['role'] or '-')}**")
    lines.append(f"- Criticality: **{safe_markdown(annotation['criticality'] or '-')}**")
    lines.append(f"- Notes: {safe_markdown(annotation['notes'] or '-')}")
    lines.append(f"- Annotation updated: `{safe_markdown(annotation['updated_at'])}`")


def report_event_rows(connection, latest_only, since, severity, limit, scope=None):
    clauses = []
    params = []
    if latest_only:
        if scope:
            latest = connection.execute("\n                SELECT scan_id\n                FROM snapshots\n                WHERE quality_status = 'ACCEPTED'\n                  AND network_scope = ?\n                ORDER BY created_at DESC, imported_at DESC\n                LIMIT 1\n                ", (scope,)).fetchone()
        else:
            latest = connection.execute("\n                SELECT scan_id\n                FROM snapshots\n                WHERE quality_status = 'ACCEPTED'\n                ORDER BY created_at DESC, imported_at DESC\n                LIMIT 1\n                ").fetchone()
        if latest is None:
            return []
        clauses.append('e.scan_id = ?')
        params.append(latest['scan_id'])
    if since:
        clauses.append('e.created_at >= ?')
        params.append(since)
    if severity:
        clauses.append('e.severity = ?')
        params.append(severity.upper())
    if scope:
        clauses.append('s.network_scope = ?')
        params.append(scope)
    where = 'WHERE ' + ' AND '.join(clauses) if clauses else ''
    params.append(limit)
    return connection.execute(f'\n        SELECT\n            e.event_id,\n            e.scan_id,\n            e.baseline_scan_id,\n            e.created_at,\n            e.severity,\n            e.event_type,\n            e.subject_key,\n            e.previous_value,\n            e.current_value,\n            e.summary,\n            s.network_scope\n        FROM delta_events e\n        JOIN snapshots s ON s.scan_id = e.scan_id\n        {where}\n        ORDER BY e.event_id DESC\n        LIMIT ?\n        ', tuple(params)).fetchall()


def port_behavior_key(protocol, port):
    protocol_text = str(protocol or 'tcp').strip().lower() or 'tcp'
    try:
        port_number = int(port)
    except (TypeError, ValueError):
        port_number = -1
    return f'{protocol_text}/{port_number}'


def port_behavior_signal_severity(behavior, port, currently_open):
    if behavior == 'PORT_FLAPPING':
        if currently_open and port in PORT_BEHAVIOR_HIGH_SIGNAL_PORTS:
            return 'HIGH'
        return 'MEDIUM'
    if behavior == 'UNEXPECTED_PORT_OPENED':
        if port in PORT_BEHAVIOR_HIGH_SIGNAL_PORTS:
            return 'HIGH'
        if port in PORT_BEHAVIOR_MEDIUM_SIGNAL_PORTS:
            return 'MEDIUM'
        return 'LOW'
    if behavior == 'PORT_NO_LONGER_OBSERVED':
        return 'INFO'
    return 'INFO'


def accepted_snapshots_for_port_behavior(connection, scope=None, limit=6):
    clauses = ["(is_accepted_baseline = 1 OR quality_status = 'ACCEPTED')"]
    params = []
    if scope:
        clauses.append('network_scope = ?')
        params.append(scope)
    params.append(limit)
    return connection.execute(f"\n        SELECT scan_id, network_scope, created_at, imported_at\n        FROM snapshots\n        WHERE {' AND '.join(clauses)}\n        ORDER BY created_at DESC, imported_at DESC, scan_id DESC\n        LIMIT ?\n        ", tuple(params)).fetchall()


def mac_port_behavior_rows(connection, limit=50, scope=None, lookback=5, *, context: ReportContext):
    lookback = max(1, int(lookback or 5))
    latest_candidates = accepted_snapshots_for_port_behavior(connection, scope=scope, limit=1)
    if not latest_candidates:
        return []
    latest = latest_candidates[0]
    effective_scope = scope or latest['network_scope']
    snapshots = accepted_snapshots_for_port_behavior(connection, scope=effective_scope, limit=lookback + 1)
    if not snapshots:
        return []
    ordered_snapshots = list(reversed(snapshots))
    latest_scan = snapshots[0]
    latest_scan_id = latest_scan['scan_id']
    scan_ids = [row['scan_id'] for row in ordered_snapshots]
    prior_scan_ids = [scan_id for scan_id in scan_ids if scan_id != latest_scan_id]
    ports_by_scan = context.load_mac_open_ports_for_scans(connection, scan_ids)
    latest_ports_by_mac = ports_by_scan.get(latest_scan_id, {})
    rows = []
    for mac_identity, latest_entry in latest_ports_by_mac.items():
        current_ports = set(latest_entry.get('ports') or set())
        historical_ports = set()
        for scan_id in prior_scan_ids:
            historical_ports.update(ports_by_scan.get(scan_id, {}).get(mac_identity, {}).get('ports', set()))
        candidate_ports = set(current_ports) | historical_ports
        if not prior_scan_ids:
            for port_key in sorted(current_ports):
                detail = latest_entry['port_details'].get(port_key, {})
                rows.append({'behavior': 'PORT_BASELINE_ESTABLISHED', 'severity': 'INFO', 'mac_identity': mac_identity, 'asset_key': latest_entry.get('asset_key'), 'ip_address': latest_entry.get('ip_address'), 'hostname': latest_entry.get('hostname'), 'vendor': latest_entry.get('vendor'), 'device_type': latest_entry.get('device_type'), 'port_key': port_key, 'protocol': detail.get('protocol', 'tcp'), 'port': detail.get('port'), 'current_state': 'OPEN', 'baseline_state': 'NO_PRIOR_BASELINE', 'seen_count': 1, 'missing_count': 0, 'transition_count': 0, 'latest_scan_id': latest_scan_id, 'baseline_scan_ids': prior_scan_ids, 'reason': f'{port_key} is part of the first accepted MAC-port baseline for {mac_identity}.'})
            continue
        for port_key in sorted(candidate_ports):
            states = [port_key in ports_by_scan.get(scan_id, {}).get(mac_identity, {}).get('ports', set()) for scan_id in scan_ids]
            currently_open = states[-1]
            was_seen_before = any(states[:-1])
            seen_count = sum((1 for state in states if state))
            missing_count = len(states) - seen_count
            transition_count = sum((1 for previous, current in zip(states, states[1:]) if previous != current))
            behavior = None
            if currently_open and (not was_seen_before):
                behavior = 'UNEXPECTED_PORT_OPENED'
            elif transition_count >= 2:
                behavior = 'PORT_FLAPPING'
            elif was_seen_before and (not currently_open):
                behavior = 'PORT_NO_LONGER_OBSERVED'
            if behavior is None:
                continue
            detail = latest_entry.get('port_details', {}).get(port_key, {})
            if not detail:
                for scan_id in reversed(prior_scan_ids):
                    detail = ports_by_scan.get(scan_id, {}).get(mac_identity, {}).get('port_details', {}).get(port_key, {})
                    if detail:
                        break
            port_number = int(detail.get('port') or str(port_key).split('/')[-1])
            severity = port_behavior_signal_severity(behavior, port_number, currently_open)
            if behavior == 'UNEXPECTED_PORT_OPENED':
                reason = f'{port_key} is open in latest scan {latest_scan_id} but was not observed for {mac_identity} across {len(prior_scan_ids)} prior accepted scan(s).'
                baseline_state = 'NOT_PREVIOUSLY_OBSERVED'
                current_state = 'OPEN'
            elif behavior == 'PORT_FLAPPING':
                reason = f'{port_key} changed open/not-observed state {transition_count} time(s) across {len(scan_ids)} accepted scan(s) for {mac_identity}.'
                baseline_state = 'VOLATILE'
                current_state = 'OPEN' if currently_open else 'NOT_OBSERVED'
            else:
                reason = f'{port_key} was previously observed for {mac_identity} but is not open in latest scan {latest_scan_id}.'
                baseline_state = 'PREVIOUSLY_OBSERVED'
                current_state = 'NOT_OBSERVED'
            rows.append({'behavior': behavior, 'severity': severity, 'mac_identity': mac_identity, 'asset_key': latest_entry.get('asset_key'), 'ip_address': latest_entry.get('ip_address'), 'hostname': latest_entry.get('hostname'), 'vendor': latest_entry.get('vendor'), 'device_type': latest_entry.get('device_type'), 'port_key': port_key, 'protocol': detail.get('protocol', 'tcp'), 'port': port_number, 'current_state': current_state, 'baseline_state': baseline_state, 'seen_count': seen_count, 'missing_count': missing_count, 'transition_count': transition_count, 'latest_scan_id': latest_scan_id, 'baseline_scan_ids': prior_scan_ids, 'reason': reason})
    rows.sort(key=lambda row: (PORT_BEHAVIOR_SEVERITY_ORDER.get(row['severity'], 99), row['behavior'], row['mac_identity'], int(row['port'] or 0)))
    return rows[:limit]


def report_snapshot_count(connection, scope=None, accepted_only=False):
    sql = 'SELECT COUNT(*) FROM snapshots WHERE 1 = 1'
    params = []
    if accepted_only:
        sql += " AND quality_status = 'ACCEPTED'"
    if scope:
        sql += ' AND network_scope = ?'
        params.append(scope)
    return connection.execute(sql, tuple(params)).fetchone()[0]


def report_latest_snapshot(connection, scope=None, *, context: ReportContext):
    if scope:
        return connection.execute("\n            SELECT *\n            FROM snapshots\n            WHERE quality_status = 'ACCEPTED'\n              AND network_scope = ?\n            ORDER BY created_at DESC, imported_at DESC\n            LIMIT 1\n            ", (scope,)).fetchone()
    return context.fetch_latest_accepted_snapshot(connection)


def report_open_alert_rows(connection, limit, scope=None):
    sql = "\n        SELECT DISTINCT\n            a.alert_id,\n            a.severity,\n            a.event_type,\n            a.subject_key,\n            a.summary,\n            a.opened_at\n        FROM alerts a\n        LEFT JOIN delta_events e ON e.event_id = a.last_event_id\n        LEFT JOIN snapshots s ON s.scan_id = e.scan_id\n        WHERE a.status = 'OPEN'\n    "
    params = []
    if scope:
        sql += ' AND s.network_scope = ?'
        params.append(scope)
    sql += ' ORDER BY a.alert_id DESC LIMIT ?'
    params.append(limit)
    return connection.execute(sql, tuple(params)).fetchall()


def report_asset_lifecycle_summary(connection, scope=None):
    sql = '\n        SELECT\n            state,\n            identity_class,\n            COUNT(*) AS asset_count\n        FROM asset_lifecycle\n        WHERE 1 = 1\n    '
    params = []
    if scope:
        sql += ' AND network_scope = ?'
        params.append(scope)
    sql += '\n        GROUP BY state, identity_class\n        ORDER BY state ASC, identity_class ASC\n    '
    return connection.execute(sql, tuple(params)).fetchall()


def report_asset_inventory_rows(connection, limit, scope=None, *, context: ReportContext):
    sql = '\n        SELECT\n            al.network_scope,\n            al.asset_key,\n            al.identity_class,\n            al.state,\n            al.current_ip,\n            al.mac_address,\n            al.hostname,\n            al.first_seen_at,\n            al.last_seen_at,\n            ao.device_type,\n            ao.device_type_confidence,\n            ao.classification_type,\n            ao.classification_primary_type,\n            ao.classification_confidence,\n            ao.classification_confidence_label,\n            ao.classification_decision,\n            ao.classification_method,\n            ao.classification_evidence_json,\n            ao.classification_contradictions_json,\n            ao.classification_candidates_json\n        FROM asset_lifecycle al\n        LEFT JOIN asset_observations ao\n          ON ao.scan_id = al.last_seen_scan_id\n         AND ao.asset_key = al.asset_key\n        WHERE 1 = 1\n    '
    params = []
    if scope:
        sql += ' AND al.network_scope = ?'
        params.append(scope)
    sql += '\n        ORDER BY al.network_scope ASC, al.state ASC, al.current_ip ASC, al.asset_key ASC\n        LIMIT ?\n    '
    params.append(limit)
    rows = connection.execute(sql, tuple(params)).fetchall()
    return context.dashboard_enrich_classification_rows(rows)


def append_report_network_scope_summary(lines, connection, scope=None):
    lines.append('## Network Scope Summary')
    lines.append('')
    rows = connection.execute("\n        SELECT\n            network_scope,\n            COUNT(*) AS snapshots,\n            SUM(CASE WHEN quality_status = 'ACCEPTED' THEN 1 ELSE 0 END) AS accepted_snapshots,\n            MAX(created_at) AS latest_scan_at\n        FROM snapshots\n        WHERE (? IS NULL OR network_scope = ?)\n        GROUP BY network_scope\n        ORDER BY network_scope ASC\n        ", (scope, scope)).fetchall()
    if not rows:
        lines.append('No network scope data matched this report.')
        lines.append('')
        return
    lines.append('| Network Scope | Snapshots | Accepted | Latest Scan |')
    lines.append('|---|---:|---:|---|')
    for row in rows:
        lines.append(f"| `{safe_markdown(row['network_scope'])}` | {row['snapshots']} | {row['accepted_snapshots'] or 0} | `{safe_markdown(row['latest_scan_at'] or '-')}` |")
    lines.append('')
    lines.append('Network scope isolation prevents baselines, lifecycle state, and reports from mixing unrelated subnets.')
    lines.append('')


def append_report_dashboard_usage_section(lines, scope=None):
    lines.append('## Dashboard and API Usage Notes')
    lines.append('')
    if scope:
        lines.append(f'- Dashboard scope view: `deltaaegis dashboard --scope {safe_markdown(scope)}`')
        lines.append(f'- Asset inventory API: `/api/assets?scope={safe_markdown(scope)}&limit=25`')
        lines.append(f'- Asset detail API: `/api/asset?scope={safe_markdown(scope)}&identifier=<asset-or-ip>`')
    else:
        lines.append('- Dashboard: `deltaaegis dashboard`')
        lines.append('- Asset inventory API: `/api/assets?limit=25`')
        lines.append('- Asset detail API: `/api/asset?identifier=<asset-or-ip>`')
    lines.append('- The dashboard remains read-only and is intended for local or trusted-access investigation.')
    lines.append('- Port behavior API: `/api/port-behavior?limit=25&lookback=5`')
    lines.append('- Investigation Center API: `/api/investigation-center?limit=25`')
    lines.append('- TrueAegis validation summary API: `/api/validation-summary`')
    lines.append('- TrueAegis validation observation API: `/api/validations?limit=25`')
    lines.append('- TrueAegis validation correlation API: `/api/validation-correlations?limit=25`')
    lines.append('- Investigation Center workflow filter API: `/api/investigation-center?limit=25&ticket_status=OPEN`')
    lines.append('- Investigation Center signal filter API: `/api/investigation-center?limit=25&ticket_signal=ACTIONABLE`')
    lines.append('- Combined ticket filters are supported with `ticket_status` and `ticket_signal` query parameters.')
    lines.append('- Use the Asset Inventory table, asset selector, or clickable risk/event/alert subjects to open Asset Detail.')
    lines.append('')


def append_report_recommended_next_actions(lines, risk_rows, open_alerts, asset_rows):
    lines.append('## Recommended Next Actions')
    lines.append('')
    if open_alerts:
        lines.append(f'- Review and triage **{len(open_alerts)}** open alert(s), starting with the highest-severity subjects.')
    else:
        lines.append('- No open alerts were included in this report.')
    if risk_rows:
        top = risk_rows[0]
        lines.append(f"- Investigate the highest-risk subject first: `{safe_markdown(top.get('subject_key'))}` with score **{safe_markdown(top.get('score'))}**.")
    else:
        lines.append('- No risk subjects were calculated for this report.')
    if asset_rows:
        lines.append('- Use the asset inventory section to identify unknown hosts, missing identity context, and unannotated important devices.')
    else:
        lines.append('- No asset inventory rows were included; verify accepted snapshots and lifecycle data exist for this scope.')
    lines.append('- Add asset annotations for known infrastructure, owners, roles, and criticality to improve future risk prioritization.')
    lines.append('')


def append_report_asset_lifecycle_section(lines, lifecycle_rows):
    lines.append('## Asset Lifecycle Summary')
    lines.append('')
    if not lifecycle_rows:
        lines.append('No asset lifecycle rows matched this report.')
        lines.append('')
        return
    lines.append('| State | Identity Class | Assets |')
    lines.append('|---|---|---:|')
    for row in lifecycle_rows:
        lines.append(f"| {safe_markdown(row['state'])} | {safe_markdown(row['identity_class'])} | {row['asset_count']} |")
    lines.append('')
    lines.append('Lifecycle state tracks whether assets are active, missing, removed, or temporarily absent across accepted scans.')
    lines.append('')


def append_report_classification_summary_section(lines, classification_summary):
    lines.append('## NetSniper Intelligence Summary')
    lines.append('')
    if not classification_summary:
        lines.append('No NetSniper classification summary was available for this report.')
        lines.append('')
        return
    lines.append("This section summarizes NetSniper's evidence-based device classification for the selected network scope.")
    lines.append('')
    summary_rows = [('Total assets', classification_summary.get('total_assets', 0)), ('Classified assets', classification_summary.get('classified_assets', 0)), ('Possible / weak classifications', classification_summary.get('possible_assets', 0)), ('Unknown assets', classification_summary.get('unknown_assets', 0)), ('Evidence-backed assets', classification_summary.get('evidence_backed_assets', 0)), ('Classification contradictions', classification_summary.get('contradiction_assets', 0)), ('High-confidence assets', classification_summary.get('high_confidence_assets', 0)), ('Classified percentage', f"{classification_summary.get('classified_percent', 0)}%")]
    lines.append('| Metric | Value |')
    lines.append('|---|---:|')
    for label, value in summary_rows:
        lines.append(f'| {safe_markdown(label)} | {safe_markdown(value)} |')
    lines.append('')
    top_classifications = classification_summary.get('top_classifications') or []
    lines.append('### Top Classifications')
    lines.append('')
    if not top_classifications:
        lines.append('No classified device categories were available.')
        lines.append('')
    else:
        lines.append('| Classification | Assets |')
        lines.append('|---|---:|')
        for row in top_classifications:
            lines.append(f"| {safe_markdown(row.get('classification'))} | {safe_markdown(row.get('count'))} |")
        lines.append('')
    review_queue = classification_summary.get('review_queue') or []
    lines.append('### Classification Review Queue')
    lines.append('')
    if not review_queue:
        lines.append('No weak, unknown, or contradictory classifications require review.')
        lines.append('')
    else:
        lines.append('| Priority Reason | Asset | IP Address | Classification | Decision | Confidence | Evidence | Contradictions |')
        lines.append('|---|---|---|---|---|---:|---:|---:|')
        for row in review_queue:
            lines.append(f"| {safe_markdown(row.get('reason'))} | `{safe_markdown(row.get('asset_key'))}` | `{safe_markdown(row.get('ip_address'))}` | {safe_markdown(row.get('classification'))} | {safe_markdown(row.get('decision'))} | {safe_markdown(row.get('confidence'))} | {safe_markdown(row.get('evidence_count'))} | {safe_markdown(row.get('contradiction_count'))} |")
        lines.append('')
    lines.append('Use weak, unknown, or contradictory classifications as review targets. They usually require vendor confirmation, service validation, or asset annotation.')
    lines.append('')


def report_trueaegis_validation_summary(connection, *, context: ReportContext):
    return context.dashboard_validation_summary_payload(connection)


def report_trueaegis_validation_rows(connection, limit=10, *, context: ReportContext):
    payload = context.dashboard_validations_payload(connection, limit=limit)
    return list(payload.get('observations') or [])


def append_report_trueaegis_validation_section(lines, validation_summary, validation_rows):
    lines.append('## TrueAegis Validation Evidence')
    lines.append('')
    lines.append('This section summarizes imported TrueAegis validation output. These correlations remain evidence-only and this evidence is stored and displayed as a foundation layer only; it does does not alter DeltaAegis risk scoring. Correlated NetSniper service evidence appears in the next section. service observations.')
    lines.append('')
    if not validation_summary or int(validation_summary.get('observation_count') or 0) == 0:
        lines.append('No TrueAegis validation observations have been imported yet.')
        lines.append('')
        lines.append('Import validation output with:')
        lines.append('')
        lines.append('```bash')
        lines.append('python3 deltaaegis.py validation-ingest /path/to/validation_results.json')
        lines.append('```')
        lines.append('')
        return
    lines.append('| Metric | Value |')
    lines.append('|---|---:|')
    lines.append(f"| Validation runs | {safe_markdown(validation_summary.get('validation_run_count') or 0)} |")
    lines.append(f"| Observations | {safe_markdown(validation_summary.get('observation_count') or 0)} |")
    lines.append(f"| Validated observations | {safe_markdown(validation_summary.get('validated_count') or 0)} |")
    lines.append(f"| Confirmed observations | {safe_markdown(validation_summary.get('confirmed_count') or 0)} |")
    lines.append(f"| Protected observations | {safe_markdown(validation_summary.get('protected_count') or 0)} |")
    lines.append('')
    status_counts = list(validation_summary.get('status_counts') or [])
    lines.append('### Validation Status Counts')
    lines.append('')
    if status_counts:
        lines.append('| Status | Count |')
        lines.append('|---|---:|')
        for row in status_counts:
            lines.append(f"| {safe_markdown(row.get('status') or 'UNKNOWN')} | {safe_markdown(row.get('count') or 0)} |")
        lines.append('')
    else:
        lines.append('No validation status counts were available.')
        lines.append('')
    latest_run = validation_summary.get('latest_run') or {}
    if latest_run:
        lines.append('### Latest Imported Validation Run')
        lines.append('')
        lines.append(f"- Run ID: `{safe_markdown(latest_run.get('validation_run_id') or '-')}`")
        lines.append(f"- Source file: `{safe_markdown(latest_run.get('source_filename') or '-')}`")
        lines.append(f"- Imported at: `{safe_markdown(latest_run.get('imported_at') or '-')}`")
        lines.append(f"- Results: **{safe_markdown(latest_run.get('result_count') or 0)}**")
        lines.append('')
    rows = list(validation_rows or [])
    lines.append('### Recent Validation Observations')
    lines.append('')
    if not rows:
        lines.append('No validation observation rows were available.')
        lines.append('')
        return
    lines.append('| Host | Port | Finding | Status | Validated | Safe | Confidence | Summary |')
    lines.append('|---|---:|---|---|---|---|---|---|')
    for row in rows:
        validated = row.get('validated')
        safe = row.get('safe')
        validated_text = 'yes' if validated is True else 'no' if validated is False else 'unknown'
        safe_text = 'yes' if safe is True else 'no' if safe is False else 'unknown'
        lines.append(f"| `{safe_markdown(row.get('host') or '-')}` | {safe_markdown(row.get('port') or '-')} | {safe_markdown(row.get('finding_id') or '-')} | {safe_markdown(row.get('status') or '-')} | {safe_markdown(validated_text)} | {safe_markdown(safe_text)} | {safe_markdown(row.get('confidence') or '-')} | {safe_markdown(row.get('summary') or '-')} |")
    lines.append('')


def report_trueaegis_validation_correlation_summary(connection):
    row = connection.execute('\n        SELECT\n            COUNT(*) AS correlation_count,\n            COUNT(DISTINCT observation_id) AS correlated_observation_count,\n            COUNT(DISTINCT scan_id) AS scan_count,\n            COUNT(DISTINCT asset_key) AS asset_count\n        FROM validation_correlations\n        ').fetchone()
    status_rows = connection.execute('\n        SELECT validation_status, COUNT(*) AS count\n        FROM validation_correlations\n        GROUP BY validation_status\n        ORDER BY validation_status ASC\n        ').fetchall()
    summary = dict(row) if row else {'correlation_count': 0, 'correlated_observation_count': 0, 'scan_count': 0, 'asset_count': 0}
    summary['status_counts'] = {str(item['validation_status'] or 'UNKNOWN'): int(item['count'] or 0) for item in status_rows}
    return summary


def report_trueaegis_validation_correlation_rows(connection, limit=10):
    rows = connection.execute('\n        SELECT\n            correlation_id,\n            observation_id,\n            validation_run_id,\n            scan_id,\n            asset_key,\n            network_scope,\n            host,\n            ip_address,\n            port,\n            service_protocol,\n            service_name,\n            product,\n            version,\n            finding_id,\n            validation_status,\n            validated,\n            safe,\n            confidence,\n            match_method,\n            matched_at\n        FROM validation_correlations\n        ORDER BY matched_at DESC, network_scope ASC, host ASC, port ASC\n        LIMIT ?\n        ', (limit,)).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item['validated'] = None if item.get('validated') is None else bool(item.get('validated'))
        item['safe'] = None if item.get('safe') is None else bool(item.get('safe'))
        result.append(item)
    return result


def append_report_trueaegis_validation_correlation_section(lines, correlation_summary, correlation_rows):
    lines.append('## TrueAegis Validation Correlations')
    lines.append('')
    lines.append('This section lists TrueAegis validation observations that currently match NetSniper-observed services. These correlations are evidence only and do not alter DeltaAegis risk scoring.')
    lines.append('')
    correlation_count = int(correlation_summary.get('correlation_count') or 0)
    correlated_observation_count = int(correlation_summary.get('correlated_observation_count') or 0)
    asset_count = int(correlation_summary.get('asset_count') or 0)
    scan_count = int(correlation_summary.get('scan_count') or 0)
    if correlation_count <= 0:
        lines.append('No TrueAegis validation observations are currently correlated with NetSniper services.')
        lines.append('')
        return
    lines.append(f'- Correlations: **{correlation_count}**')
    lines.append(f'- Correlated observations: **{correlated_observation_count}**')
    lines.append(f'- Correlated assets: **{asset_count}**')
    lines.append(f'- Current scans represented: **{scan_count}**')
    status_counts = correlation_summary.get('status_counts') or {}
    if status_counts:
        status_text = ', '.join((f'`{safe_markdown(status)}`={int(count)}' for status, count in sorted(status_counts.items())))
        lines.append(f'- Status counts: {status_text}')
    lines.append('')
    if not correlation_rows:
        lines.append('No recent correlated validation rows were available.')
        lines.append('')
        return
    lines.append('| Asset | Host | Service | Finding | Status | Validated | Safe | Confidence | Match |')
    lines.append('|---|---:|---:|---|---|---:|---:|---|---|')
    for row in correlation_rows:
        service = f"{row.get('service_protocol') or 'tcp'}/{row.get('port') or '-'}"
        lines.append(f"| `{safe_markdown(row.get('asset_key') or '-')}` | `{safe_markdown(row.get('host') or row.get('ip_address') or '-')}` | `{safe_markdown(service)}` | {safe_markdown(row.get('finding_id') or '-')} | {safe_markdown(row.get('validation_status') or '-')} | {safe_markdown(row.get('validated'))} | {safe_markdown(row.get('safe'))} | {safe_markdown(row.get('confidence') or '-')} | {safe_markdown(row.get('match_method') or '-')} |")
    lines.append('')


def append_report_asset_inventory_section(lines, asset_rows, limit):
    lines.append('## Asset Inventory')
    lines.append('')
    if not asset_rows:
        lines.append('No assets matched this report.')
        lines.append('')
        return
    lines.append(f'Showing up to **{limit}** assets.')
    lines.append('')
    lines.append('| Scope | State | Identity | IP Address | MAC Address | Hostname | Classification | Decision | Confidence | Evidence | Contradictions | Asset Key | Last Seen |')
    lines.append('|---|---|---|---|---|---|---|---|---:|---:|---:|---|---|')
    for row in asset_rows:
        classification = row.get('classification_display_type') or row.get('device_type') or 'Unknown'
        decision = row.get('classification_display_decision') or 'unknown'
        confidence = row.get('classification_display_confidence')
        evidence_count = row.get('classification_evidence_count', 0)
        contradiction_count = row.get('classification_contradiction_count', 0)
        lines.append(f"| `{safe_markdown(row['network_scope'])}` | {safe_markdown(row['state'])} | {safe_markdown(row['identity_class'])} | `{safe_markdown(row['current_ip'])}` | `{safe_markdown(row['mac_address'] or '-')}` | {safe_markdown(row['hostname'] or '-')} | {safe_markdown(classification)} | {safe_markdown(decision)} | {safe_markdown(confidence)} | {safe_markdown(evidence_count)} | {safe_markdown(contradiction_count)} | `{safe_markdown(row['asset_key'])}` | `{safe_markdown(row['last_seen_at'])}` |")
    lines.append('')


def append_report_role_aware_recommendations_section(lines, risk_rows):
    lines.append('## Role-Aware Recommended Actions')
    lines.append('')
    rows = [record for record in risk_rows if record.get('recommended_actions')]
    if not rows:
        lines.append('No role-aware recommended actions were generated for this report.')
        lines.append('')
        return
    lines.append('These actions use NetSniper classification context to make follow-up guidance more specific to the suspected asset role.')
    lines.append('')
    for record in rows[:10]:
        lines.append(f"### `{safe_markdown(record.get('subject_key'))}` — {safe_markdown(record.get('classification') or 'Unknown')} ({safe_markdown(record.get('classification_decision') or 'unknown')}, confidence {safe_markdown(record.get('classification_confidence') or 0)})")
        lines.append('')
        lines.append(f"- Risk level: **{safe_markdown(record.get('level'))}** with score **{safe_markdown(record.get('score'))}**.")
        points = int(record.get('classification_risk_points') or 0)
        if points:
            lines.append(f'- Classification-aware risk contribution: **+{points}**.')
        for action in record.get('recommended_actions') or []:
            lines.append(f'- Recommended action: {safe_markdown(action)}')
        lines.append('')


def append_report_investigation_center_section(lines, investigation_rows, *, context: ReportContext):
    lines.append('## Investigation Command Center')
    lines.append('')
    lines.append('This section summarizes the highest-priority investigation queue from the same Command Center logic used by the dashboard and `investigation-center` CLI.')
    lines.append('')
    lines.append('Queue priority combines current risk, open alerts, recent delta events, MAC-port behavior, identity context, classification context, recommended actions, and v0.22 operator triage state.')
    lines.append('')
    rows = list(investigation_rows or [])
    workflow_summary = context.investigation_center_workflow_summary(rows)
    signal_summary = context.investigation_center_signal_summary(rows)
    triage_summary = context.operator_triage_summary(rows)
    lines.append('### Investigation Queue Operator Summary')
    lines.append('')
    lines.append(f"- Workflow states: OPEN={workflow_summary.get('open', 0)}, IN_REVIEW={workflow_summary.get('in_review', 0)}, RESOLVED={workflow_summary.get('resolved', 0)}, SUPPRESSED={workflow_summary.get('suppressed', 0)}")
    lines.append(f"- Signal labels: ACTIONABLE={signal_summary.get('actionable', 0)}, MEANINGFUL_CHANGE={signal_summary.get('meaningful_change', 0)}, BASELINE_CONTEXT={signal_summary.get('baseline_context', 0)}")
    lines.append(f"- Operator triage buckets: NEEDS_REVIEW={triage_summary.get('needs_review', 0)}, CHANGED_SINCE_REVIEW={triage_summary.get('changed_since_review', 0)}, NEEDS_CONTEXT={triage_summary.get('needs_context', 0)}, STALE_CLOSED={triage_summary.get('stale_closed', 0)}, BASELINE_CONTEXT={triage_summary.get('baseline_context', 0)}, MONITOR={triage_summary.get('monitor', 0)}")
    lines.append(f"- Operator triage urgency: IMMEDIATE={triage_summary.get('immediate', 0)}, HIGH={triage_summary.get('high', 0)}, NORMAL={triage_summary.get('normal', 0)}, LOW={triage_summary.get('low', 0)}")
    lines.append(f"- Missing context flags: owner={triage_summary.get('missing_owner', 0)}, role_or_criticality={triage_summary.get('missing_context', 0)}")
    lines.append('')
    if not rows:
        lines.append('No Investigation Command Center queue items matched this report scope.')
        lines.append('')
        return
    lines.append('| Priority | Score | Workflow | Signal | Subject | Triage | Triage Score | IP Address | MAC Address | Device / Role | Triggers | Why Review? | Recommended Action | Counts |')
    lines.append('|---|---:|---|---|---|---|---:|---|---|---|---|---|---|---|')
    for row in rows:
        role = row.get('role') or row.get('classification') or row.get('device_type') or 'Unknown'
        device = row.get('device_type') or 'Unknown'
        if device != role:
            device_role = f'{device} / {role}'
        else:
            device_role = role
        triggers = ', '.join(row.get('triggers') or []) or '-'
        workflow = str(row.get('ticket_status') or 'OPEN').upper()
        signal = str(row.get('ticket_signal_state') or 'ACTIONABLE').upper()
        triage_bucket = str(row.get('triage_bucket') or 'MONITOR').upper()
        triage_label = str(row.get('triage_urgency_label') or 'LOW').upper()
        triage_score = int(row.get('triage_urgency_score') or 0)
        triage_display = f'{triage_bucket} / {triage_label}'
        counts = f"alerts={int(row.get('open_alerts') or 0)}, events={int(row.get('recent_events') or 0)}, ports={int(row.get('port_behavior_count') or 0)}, findings={int(row.get('current_finding_count') or 0)}"
        lines.append(f"| {safe_markdown(row.get('priority_level') or 'INFO')} | {safe_markdown(row.get('priority_score') or 0)} | {safe_markdown(workflow)} | {safe_markdown(signal)} | `{safe_markdown(row.get('subject_key'))}` | {safe_markdown(triage_display)} | {safe_markdown(triage_score)} | `{safe_markdown(row.get('ip_address') or '-')}` | `{safe_markdown(row.get('mac_address') or '-')}` | {safe_markdown(device_role)} | {safe_markdown(triggers)} | {safe_markdown(row.get('primary_reason') or '-')} | {safe_markdown(row.get('recommended_action') or '-')} | `{safe_markdown(counts)}` |")
    lines.append('')
    lines.append('Use this queue as the starting point for review. The detailed Risk, MAC-Port Behavior, Active Alerts, Delta Events, Ticket Evidence, and Asset Inventory sections provide supporting evidence for each item.')
    lines.append('')


def append_report_risk_section(lines, risk_rows):
    lines.append('## Top Risk Subjects')
    lines.append('')
    if not risk_rows:
        lines.append('No risk subjects were calculated for this report.')
        lines.append('')
        return
    lines.append('| Level | Score | Subject | IP Address | MAC Address | Owner | Role | Criticality | Open Alerts | Events | Primary Reason |')
    lines.append('|---|---:|---|---|---|---|---|---|---:|---:|---|')
    for record in risk_rows:
        reasons = record.get('reasons') or []
        primary_reason = reasons[0] if reasons else '-'
        lines.append(f"| {safe_markdown(record['level'])} | {record['score']} | `{safe_markdown(record['subject_key'])}` | `{safe_markdown(record.get('ip_address') or 'unknown')}` | `{safe_markdown(record.get('mac_address') or 'unknown')}` | {safe_markdown(record.get('owner') or '-')} | {safe_markdown(record.get('role') or '-')} | {safe_markdown(record.get('criticality') or '-')} | {record.get('open_alerts', 0)} | {record.get('event_count', 0)} | {safe_markdown(primary_reason)} |")
    lines.append('')
    lines.append('Risk scores are explainable and are calculated from recent delta events, alert state, repeated activity, asset criticality, missing asset context, and classification-aware role context.')
    lines.append('')


def append_report_port_behavior_section(lines, port_behavior_rows):
    lines.append('## MAC-Port Behavior Changes')
    lines.append('')
    lines.append('This section correlates stable MAC-backed device identity with open-port history across accepted scans. It highlights ports that appeared unexpectedly, disappeared, or repeatedly changed open/not-observed state.')
    lines.append('')
    lines.append('Normal infrastructure ports can fluctuate because of scan timing, device sleep states, or printer/web management behavior. Treat volatile printer ports such as `tcp/631` and `tcp/9100` as review context unless combined with unusual remote-access or file-sharing services.')
    lines.append('')
    rows = list(port_behavior_rows or [])
    if not rows:
        lines.append('No MAC-port behavior changes were detected for this report scope.')
        lines.append('')
        return
    lines.append('| Severity | Behavior | MAC Identity | IP Address | Device | Port | Current State | Seen | Missing | Transitions | Reason |')
    lines.append('|---|---|---|---|---|---|---|---:|---:|---:|---|')
    for row in rows:
        lines.append(f"| {safe_markdown(row.get('severity'))} | {safe_markdown(row.get('behavior'))} | `{safe_markdown(row.get('mac_identity'))}` | `{safe_markdown(row.get('ip_address'))}` | {safe_markdown(row.get('device_type') or 'Unknown')} | `{safe_markdown(row.get('port_key'))}` | {safe_markdown(row.get('current_state'))} | {safe_markdown(row.get('seen_count'))} | {safe_markdown(row.get('missing_count'))} | {safe_markdown(row.get('transition_count'))} | {safe_markdown(row.get('reason'))} |")
    lines.append('')
    lines.append('High-signal unexpected ports, such as Telnet, SMB, RDP, exposed databases, or container-management services, should be validated before treating the device as normal.')
    lines.append('')


def report_ticket_evidence_rows(connection, investigation_rows, scope=None, limit=5, evidence_limit=5, *, context: ReportContext):
    evidence_rows = []
    for row in list(investigation_rows or [])[:limit]:
        subject_key = row.get('subject_key')
        if not subject_key:
            continue
        payload = context.dashboard_ticket_evidence_payload(connection, subject_key=subject_key, scope=scope, limit=evidence_limit)
        if payload.get('available', False):
            evidence_rows.append(payload)
    return evidence_rows


def append_report_ticket_evidence_appendix(lines, evidence_payloads):
    lines.append('## Ticket Evidence Appendix')
    lines.append('')
    lines.append('This appendix preserves the operator-facing evidence package behind top Investigation Command Center tickets. Each entry ties workflow state, risk reasoning, recent delta events, MAC-port behavior, and ticket history back to the same subject key used by the dashboard and CLI.')
    lines.append('')
    payloads = list(evidence_payloads or [])
    if not payloads:
        lines.append('No ticket evidence payloads were available for this report scope.')
        lines.append('')
        return
    for index, payload in enumerate(payloads, start=1):
        summary = payload.get('summary') or {}
        ticket_state = payload.get('ticket_state') or {}
        subject_key = payload.get('subject_key') or summary.get('subject_key') or '-'
        lines.append(f'### Ticket Evidence {index}: `{safe_markdown(subject_key)}`')
        lines.append('')
        lines.append(f"- Workflow: **{safe_markdown(summary.get('ticket_status') or ticket_state.get('ticket_status') or 'OPEN')}**")
        lines.append(f"- Signal: **{safe_markdown(summary.get('ticket_signal') or 'ACTIONABLE')}**")
        lines.append(f"- Priority: **{safe_markdown(summary.get('priority_level') or 'INFO')}** ({safe_markdown(summary.get('priority_score') or 0)})")
        lines.append(f"- Primary reason: {safe_markdown(summary.get('primary_reason') or '-')}")
        lines.append(f"- Why now: {safe_markdown(summary.get('why_now') or '-')}")
        lines.append(f"- Recommended action: {safe_markdown(summary.get('recommended_action') or '-')}")
        lines.append(f"- Evidence counts: risk `{safe_markdown(summary.get('risk_count') or 0)}`, alerts `{safe_markdown(summary.get('alert_count') or 0)}`, events `{safe_markdown(summary.get('event_count') or 0)}`, ports `{safe_markdown(summary.get('port_behavior_count') or 0)}`, history `{safe_markdown(summary.get('ticket_history_count') or 0)}`, timeline `{safe_markdown(summary.get('timeline_count') or 0)}`")
        lines.append('')
        timeline = list(payload.get('timeline') or [])[:8]
        lines.append('#### Evidence Timeline Sample')
        lines.append('')
        if not timeline:
            lines.append('No timeline evidence was available for this ticket.')
            lines.append('')
        else:
            lines.append('| Time | Category | Severity | Source | Summary |')
            lines.append('|---|---|---|---|---|')
            for item in timeline:
                lines.append(f"| {safe_markdown(item.get('timestamp') or '-')} | {safe_markdown(item.get('category') or '-')} | {safe_markdown(item.get('severity') or '-')} | {safe_markdown(item.get('source') or '-')} | {safe_markdown(item.get('summary') or '-')} |")
            lines.append('')
        risk_rows = list(payload.get('risk') or [])[:3]
        lines.append('#### Current Risk Evidence')
        lines.append('')
        if not risk_rows:
            lines.append('No current risk rows were attached to this ticket evidence package.')
            lines.append('')
        else:
            lines.append('| Level | Score | Subject | Primary Reason |')
            lines.append('|---|---:|---|---|')
            for risk in risk_rows:
                reasons = risk.get('reasons') or []
                primary_reason = risk.get('primary_reason') or (reasons[0] if reasons else '-')
                lines.append(f"| {safe_markdown(risk.get('level') or '-')} | {safe_markdown(risk.get('score') or 0)} | `{safe_markdown(risk.get('subject_key') or subject_key)}` | {safe_markdown(primary_reason)} |")
            lines.append('')
        event_rows = list(payload.get('events') or [])[:5]
        lines.append('#### Delta Events')
        lines.append('')
        if not event_rows:
            lines.append('No delta events were attached to this ticket evidence package.')
            lines.append('')
        else:
            lines.append('| Event | Time | Severity | Type | Summary |')
            lines.append('|---:|---|---|---|---|')
            for event in event_rows:
                lines.append(f"| {safe_markdown(event.get('event_id') or event.get('id') or '-')} | {safe_markdown(event.get('created_at') or '-')} | {safe_markdown(event.get('severity') or '-')} | {safe_markdown(event.get('event_type') or event.get('type') or '-')} | {safe_markdown(event.get('summary') or '-')} |")
            lines.append('')
        port_rows = list(payload.get('port_behavior') or [])[:5]
        lines.append('#### MAC-Port Behavior')
        lines.append('')
        if not port_rows:
            lines.append('No MAC-port behavior rows were attached to this ticket evidence package.')
            lines.append('')
        else:
            lines.append('| Severity | Behavior | Port | Reason |')
            lines.append('|---|---|---|---|')
            for port in port_rows:
                port_label = port.get('port_key')
                if not port_label:
                    proto = port.get('protocol') or 'tcp'
                    port_number = port.get('port') or '-'
                    port_label = f'{proto}/{port_number}'
                lines.append(f"| {safe_markdown(port.get('severity') or '-')} | {safe_markdown(port.get('behavior') or '-')} | `{safe_markdown(port_label)}` | {safe_markdown(port.get('reason') or '-')} |")
            lines.append('')
        history_rows = list(payload.get('ticket_history') or [])[:5]
        lines.append('#### Ticket History')
        lines.append('')
        if not history_rows:
            lines.append('No ticket workflow history was attached to this evidence package.')
            lines.append('')
        else:
            lines.append('| Time | Previous | New | Analyst | Note |')
            lines.append('|---|---|---|---|---|')
            for history in history_rows:
                lines.append(f"| {safe_markdown(history.get('created_at') or '-')} | {safe_markdown(history.get('previous_status') or '-')} | {safe_markdown(history.get('new_status') or '-')} | {safe_markdown(history.get('analyst') or '-')} | {safe_markdown(history.get('note') or '-')} |")
            lines.append('')


def port_behavior_risk_points(row):
    behavior = str(row.get('behavior') or '').upper()
    current_state = str(row.get('current_state') or '').upper()
    try:
        port = int(row.get('port') or 0)
    except (TypeError, ValueError):
        port = 0
    if behavior == 'UNEXPECTED_PORT_OPENED':
        if port in PORT_BEHAVIOR_HIGH_SIGNAL_PORTS:
            return (20, f"MAC-port behavior detected unexpected high-signal port {row.get('port_key')}: +20")
        if port in PORT_BEHAVIOR_MEDIUM_SIGNAL_PORTS:
            return (10, f"MAC-port behavior detected unexpected monitored port {row.get('port_key')}: +10")
        return (5, f"MAC-port behavior detected unexpected open port {row.get('port_key')}: +5")
    if behavior == 'PORT_FLAPPING':
        if current_state == 'OPEN' and port in PORT_BEHAVIOR_HIGH_SIGNAL_PORTS:
            return (15, f"MAC-port behavior detected volatile high-signal port {row.get('port_key')}: +15")
        if current_state == 'OPEN':
            return (5, f"MAC-port behavior detected volatile open port {row.get('port_key')}: +5")
    return (0, '')
