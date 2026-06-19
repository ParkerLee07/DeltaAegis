#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="${REPO_DIR:-$HOME/DeltaAegis}"
cd "$REPO_DIR" || {
  echo "[-] Could not enter DeltaAegis repo: $REPO_DIR"
  exit 1
}

echo "[*] Validating DeltaAegis v0.10 NetSniper v1.6 risk policy..."

python3 -m py_compile deltaaegis.py

grep -q 'ao.classification_siem_action' deltaaegis.py
grep -q 'siem_action == "display_only"' deltaaegis.py
grep -q 'siem_action == "review_queue"' deltaaegis.py
grep -q 'siem_action == "contradiction_review"' deltaaegis.py

python3 - <<'PY'
import deltaaegis as da


def base_context(**overrides):
    context = {
        "classification_type": "Database Server",
        "classification_primary_type": "Database Server",
        "device_type": "Database Server",
        "classification_confidence": 80,
        "device_type_confidence": 80,
        "classification_decision": "classified",
        "classification_confidence_band": "confirmed",
        "classification_calibrated_decision": "classified",
        "classification_siem_action": "alert_eligible",
        "classification_validation_state": "confirmed",
        "classification_contradiction_count": 0,
        "classification_contradictions_json": "[]",
        "services": [
            {
                "protocol": "tcp",
                "port": 5432,
                "state": "open",
                "service_name": "postgresql",
                "product": "PostgreSQL",
                "version": None,
            }
        ],
    }
    context.update(overrides)
    return context


display_only = da.risk_classification_context(
    base_context(
        classification_siem_action="display_only",
        classification_confidence_band="weak",
        classification_calibrated_decision="possible",
        classification_decision="possible",
        classification_confidence=20,
    )
)

review_queue = da.risk_classification_context(
    base_context(
        classification_siem_action="review_queue",
        classification_confidence_band="possible",
        classification_calibrated_decision="possible",
        classification_decision="possible",
        classification_confidence=45,
    )
)

alert_eligible = da.risk_classification_context(
    base_context(
        classification_siem_action="alert_eligible",
        classification_confidence_band="confirmed",
        classification_calibrated_decision="classified",
        classification_decision="classified",
        classification_confidence=85,
    )
)

contradiction = da.risk_classification_context(
    base_context(
        classification_siem_action="contradiction_review",
        classification_validation_state="conflicted",
        classification_contradiction_count=1,
        classification_contradictions_json='[{"reason":"synthetic conflict"}]',
    )
)

checks = [
    ("display_only points", display_only["classification_risk_points"], 0),
    ("review_queue points", review_queue["classification_risk_points"], 5),
    ("alert_eligible has role risk", alert_eligible["classification_risk_points"] > 0, True),
    ("contradiction_review risk", contradiction["classification_risk_points"] >= 20, True),
    ("siem_action retained", alert_eligible["classification_siem_action"], "alert_eligible"),
]

for label, actual, expected in checks:
    if actual != expected:
        raise SystemExit(
            f"{label} failed: actual={actual!r} expected={expected!r}"
        )

print("[+] PASS: v0.10 NetSniper v1.6 risk policy behaves as expected.")
PY

echo "[+] PASS: DeltaAegis v0.10 NetSniper v1.6 risk policy validation succeeded."
