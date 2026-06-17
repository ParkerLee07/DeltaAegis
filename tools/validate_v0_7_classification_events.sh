#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/DeltaAegis}" || {
  echo "[-] Could not enter DeltaAegis repo."
  exit 1
}

echo "[*] Running syntax check..."
python3 -m py_compile deltaaegis.py

echo "[*] Running live tests..."
pytest -q

echo "[*] Running classification event unit validation..."

python3 - <<'PY'
import json
import deltaaegis as da

def asset(
    key,
    ip,
    device_type,
    classification_type,
    confidence,
    decision,
    contradictions=None,
):
    contradictions = contradictions or []
    return da.AssetObservation(
        asset_key=key,
        identity_class="GLOBAL_MAC",
        identity_confidence="HIGH",
        identity_source="DISCOVERY_XML",
        ip_address=ip,
        mac_address=key.removeprefix("mac:"),
        vendor=None,
        hostname=None,
        device_type=device_type,
        severity="LOW",
        score=0,
        services=[],
        findings=[],
        device_type_confidence=confidence,
        classification_type=classification_type,
        classification_primary_type=classification_type,
        classification_confidence=confidence,
        classification_confidence_label="high" if confidence >= 70 else "medium" if confidence >= 40 else "weak" if confidence > 0 else "none",
        classification_decision=decision,
        classification_method="weighted_evidence",
        classification_json=json.dumps({
            "type": classification_type,
            "confidence": confidence,
            "decision": decision,
            "contradictions": contradictions,
        }, sort_keys=True),
        classification_evidence_json=json.dumps([
            {
                "candidate": classification_type,
                "source": "test",
                "value": "synthetic",
                "points": confidence,
                "reason": "synthetic validation evidence",
            }
        ], sort_keys=True),
        classification_contradictions_json=json.dumps(contradictions, sort_keys=True),
        classification_candidates_json="[]",
    )

previous = {
    "mac:aa:bb:cc:dd:ee:01": asset("mac:aa:bb:cc:dd:ee:01", "192.0.2.10", "Web Server", "Web Server", 40, "classified"),
    "mac:aa:bb:cc:dd:ee:02": asset("mac:aa:bb:cc:dd:ee:02", "192.0.2.20", "Web Server", "Web Server", 45, "classified"),
    "mac:aa:bb:cc:dd:ee:03": asset("mac:aa:bb:cc:dd:ee:03", "192.0.2.30", "Web Server", "Web Server", 40, "classified"),
    "mac:aa:bb:cc:dd:ee:04": asset("mac:aa:bb:cc:dd:ee:04", "192.0.2.40", "Network Printer", "Network Printer", 80, "classified"),
}

current = {
    # Type changed.
    "mac:aa:bb:cc:dd:ee:01": asset("mac:aa:bb:cc:dd:ee:01", "192.0.2.10", "IP Camera / NVR", "IP Camera / NVR", 80, "classified"),

    # Confidence changed significantly.
    "mac:aa:bb:cc:dd:ee:02": asset("mac:aa:bb:cc:dd:ee:02", "192.0.2.20", "Web Server", "Web Server", 75, "classified"),

    # Became weak/possible.
    "mac:aa:bb:cc:dd:ee:03": asset("mac:aa:bb:cc:dd:ee:03", "192.0.2.30", "Unknown", "Web Server", 20, "possible"),

    # Contradiction appeared.
    "mac:aa:bb:cc:dd:ee:04": asset(
        "mac:aa:bb:cc:dd:ee:04",
        "192.0.2.40",
        "Network Printer",
        "Network Printer",
        80,
        "classified",
        contradictions=[
            {
                "id": "printer+rdp",
                "reason": "Printer-like services detected, but RDP is also open.",
            }
        ],
    ),
}

events = da.classification_delta_events(previous, current)
event_types = {item["event_type"] for item in events}

required = {
    "DEVICE_CLASSIFICATION_CHANGED",
    "DEVICE_CLASSIFICATION_CONFIDENCE_CHANGED",
    "DEVICE_CLASSIFICATION_WEAK",
    "DEVICE_CLASSIFICATION_CONTRADICTION",
}

missing = required - event_types

if missing:
    print("[-] Missing expected event types:")
    for item in sorted(missing):
        print(f"    {item}")
    print()
    print("Observed:")
    for item in events:
        print(item)
    raise SystemExit(1)

print("[+] PASS: classification_delta_events() generated expected event types.")
print()
for item in events:
    print(f"{item['severity']:<6} {item['event_type']:<42} {item['subject_key']}  {item['summary']}")
PY

echo
echo "[+] PASS: DeltaAegis v0.7 classification event validation succeeded."
