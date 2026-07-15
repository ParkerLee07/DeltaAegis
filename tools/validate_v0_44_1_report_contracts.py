#!/usr/bin/env python3
"""Consolidated report-contract coverage for DeltaAegis v0.44.1."""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import deltaaegis as da  # noqa: E402


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def require(rendered: str, *fragments: str) -> None:
    missing = [fragment for fragment in fragments if fragment not in rendered]
    check(not missing, f"missing report fragments: {missing}")


def validate_port_behavior() -> None:
    lines: list[str] = []
    da.append_report_port_behavior_section(
        lines,
        [
            {
                "severity": "MEDIUM",
                "behavior": "UNEXPECTED_PORT_OPENED",
                "mac_identity": "aa:bb:cc:dd:ee:ff",
                "ip_address": "192.168.5.11",
                "device_type": "Workstation",
                "port_key": "tcp/23",
                "current_state": "open",
                "seen_count": 1,
                "missing_count": 0,
                "transition_count": 1,
                "reason": "Synthetic Telnet exposure.",
            }
        ],
    )
    rendered = "\n".join(lines)
    require(
        rendered,
        "## MAC-Port Behavior Changes",
        "UNEXPECTED_PORT_OPENED",
        "tcp/23",
        "aa:bb:cc:dd:ee:ff",
        "Synthetic Telnet exposure.",
    )
    empty: list[str] = []
    da.append_report_port_behavior_section(empty, [])
    require("\n".join(empty), "No MAC-port behavior changes were detected")


def validate_investigation_center() -> None:
    rows = [
        da.operator_triage_enrich_row(
            {
                "subject_key": "mac:aa",
                "priority_level": "HIGH",
                "priority_score": 74,
                "ticket_status": "OPEN",
                "ticket_signal_state": "MEANINGFUL_CHANGE",
                "ip_address": "192.168.5.10",
                "mac_address": "aa:aa:aa:aa:aa:aa",
                "device_type": "Linux Server",
                "role": "Server",
                "triggers": ["CURRENT_RISK", "RECENT_EVENT"],
                "primary_reason": "Synthetic high-priority reason",
                "recommended_action": "Synthetic action",
                "latest_event_at": "2026-06-24T17:00:00+00:00",
            }
        ),
        da.operator_triage_enrich_row(
            {
                "subject_key": "mac:bb",
                "priority_level": "LOW",
                "priority_score": 22,
                "ticket_status": "OPEN",
                "ticket_signal_state": "BASELINE_CONTEXT",
                "ip_address": "192.168.5.11",
                "mac_address": "bb:bb:bb:bb:bb:bb",
                "device_type": "Network Printer / Multifunction Printer",
                "role": "Printer",
                "triggers": ["CURRENT_RISK"],
                "primary_reason": "Synthetic baseline reason",
                "recommended_action": "Synthetic baseline action",
                "latest_event_at": "2026-06-24T16:00:00+00:00",
            }
        ),
    ]
    lines: list[str] = []
    da.append_report_investigation_center_section(lines, rows)
    rendered = "\n".join(lines)
    require(
        rendered,
        "## Investigation Command Center",
        "Operator triage buckets",
        "Operator triage urgency",
        "Missing context flags",
        "| Priority | Score | Workflow | Signal | Subject | Triage | Triage Score |",
        "mac:aa",
        "CURRENT_RISK, RECENT_EVENT",
        "Synthetic action",
    )


def validate_ticket_evidence() -> None:
    subject = "mac:AA:AA:AA:AA:AA:01"
    stable_subject = da.stable_ticket_key(subject)
    payload = {
        "available": True,
        "subject_key": stable_subject,
        "selected_subject": subject,
        "selected_scope": "192.168.5.0/24",
        "summary": {
            "subject_key": stable_subject,
            "scope": "192.168.5.0/24",
            "ticket_status": "IN_REVIEW",
            "ticket_signal": "ACTIONABLE",
            "priority_level": "HIGH",
            "priority_score": 88,
            "risk_count": 1,
            "alert_count": 1,
            "event_count": 1,
            "port_behavior_count": 1,
            "ticket_history_count": 1,
            "timeline_count": 5,
            "primary_reason": "Synthetic report reason.",
            "recommended_action": "Synthetic report next action.",
        },
        "ticket_state": {"ticket_status": "IN_REVIEW"},
        "timeline": [
            {
                "timestamp": "2026-06-24T15:00:00+00:00",
                "category": "current_risk",
                "severity": "HIGH",
                "source": "risk_register",
                "summary": "Synthetic report timeline.",
            }
        ],
        "risk": [
            {
                "level": "HIGH",
                "score": 88,
                "subject_key": stable_subject,
                "reasons": ["Synthetic report reason."],
            }
        ],
        "events": [
            {
                "event_id": 10,
                "created_at": "2026-06-24T14:00:00+00:00",
                "severity": "MEDIUM",
                "event_type": "MONITORED_SERVICE_OPENED",
                "summary": "Synthetic report event.",
            }
        ],
        "port_behavior": [
            {
                "severity": "MEDIUM",
                "behavior": "PORT_FLAPPING",
                "protocol": "tcp",
                "port": 9100,
                "reason": "Synthetic report port behavior.",
            }
        ],
        "ticket_history": [
            {
                "created_at": "2026-06-24T13:00:00+00:00",
                "previous_status": "OPEN",
                "new_status": "IN_REVIEW",
                "analyst": "Parker",
                "note": "Synthetic report history.",
            }
        ],
    }

    original = da.dashboard_ticket_evidence_payload
    calls: list[tuple[str, str | None, int]] = []
    try:
        def fake_payload(connection, subject_key, scope=None, limit=5):
            calls.append((subject_key, scope, limit))
            return payload

        da.dashboard_ticket_evidence_payload = fake_payload
        rows = da.report_ticket_evidence_rows(
            connection=object(),
            investigation_rows=[{"subject_key": subject}, {"subject_key": ""}, {}],
            scope="192.168.5.0/24",
            limit=3,
            evidence_limit=4,
        )
        check(len(rows) == 1, "ticket evidence collector row count changed")
        check(calls == [(subject, "192.168.5.0/24", 4)], "ticket evidence collector calls changed")
    finally:
        da.dashboard_ticket_evidence_payload = original

    lines: list[str] = []
    da.append_report_ticket_evidence_appendix(lines, [payload])
    rendered = "\n".join(lines)
    require(
        rendered,
        "## Ticket Evidence Appendix",
        "Ticket Evidence 1",
        stable_subject,
        "Workflow:",
        "Priority:",
        "Synthetic report reason.",
        "Synthetic report next action.",
        "Evidence Timeline Sample",
        "Current Risk Evidence",
        "Delta Events",
        "MAC-Port Behavior",
        "Ticket History",
        "Synthetic report timeline.",
        "Synthetic report port behavior.",
        "Synthetic report history.",
    )
    empty: list[str] = []
    da.append_report_ticket_evidence_appendix(empty, [])
    require("\n".join(empty), "No ticket evidence payloads were available")


def validate_trueaegis_correlations() -> None:
    summary = {
        "correlation_count": 2,
        "correlated_observation_count": 3,
        "asset_count": 1,
        "scan_count": 1,
        "status_counts": {"PROTECTED": 1, "SMB_EXPOSED": 1},
    }
    rows = [
        {
            "asset_key": "asset-linux",
            "host": "192.168.4.10",
            "service_protocol": "tcp",
            "port": 445,
            "finding_id": "SMB_EXPOSED",
            "validation_status": "PROTECTED",
            "validated": True,
            "safe": False,
            "confidence": "HIGH",
            "match_method": "host_port",
        }
    ]
    lines: list[str] = []
    da.append_report_trueaegis_validation_correlation_section(lines, summary, rows)
    rendered = "\n".join(lines)
    require(
        rendered,
        "## TrueAegis Validation Correlations",
        "do not alter DeltaAegis risk scoring",
        "PROTECTED",
        "SMB_EXPOSED",
        "tcp/445",
        "asset-linux",
    )
    empty: list[str] = []
    da.append_report_trueaegis_validation_correlation_section(
        empty,
        {"correlation_count": 0},
        [],
    )
    require("\n".join(empty), "No TrueAegis validation observations")


def main() -> int:
    print("DeltaAegis v0.44.1 Consolidated Report Contract Validator")
    print("=========================================================")
    validate_port_behavior()
    print("PASS: MAC-port behavior report contract")
    validate_investigation_center()
    print("PASS: Investigation Command Center report contract")
    validate_ticket_evidence()
    print("PASS: ticket evidence collection and appendix contract")
    validate_trueaegis_correlations()
    print("PASS: TrueAegis correlation report contract")
    print("PASS: consolidated current report contracts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
