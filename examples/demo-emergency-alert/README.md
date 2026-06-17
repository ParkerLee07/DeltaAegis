# DeltaAegis Demo Emergency Alert Bundle

This directory contains safe demonstration NetSniper-style telemetry for showing new users what an emergency investigation looks like in DeltaAegis.

The demo uses documentation-only IP space (`192.0.2.0/24`) and a locally administered demo MAC address. It does not describe a real network, real customer environment, real credential, or real host.

## What it demonstrates

The demo contains two finalized NetSniper-style bundles:

1. `20260617-000000-demo-baseline`
   - A normal baseline scan of a demo administrative appliance.
   - Expected services: SSH and HTTPS.

2. `20260617-000500-demo-emergency`
   - A follow-up scan of the same demo appliance.
   - Newly observed high-risk services include SMB, RDP, alternate HTTP, and administrative console ports.
   - NetSniper-style findings include emergency-labeled exposure findings.

DeltaAegis is delta-based, so the baseline bundle must be ingested before the emergency bundle to produce the alert workflow.

## View it on the dashboard

Run this helper from the root of the DeltaAegis repo:

    bash examples/demo-emergency-alert/run_demo_dashboard.sh

Then open:

    http://127.0.0.1:8090

The helper uses a temporary demo database at `/tmp/deltaaegis-demo-emergency.db`, so it does not modify your real DeltaAegis database.

## Manual demo commands

    python3 deltaaegis.py --db /tmp/deltaaegis-demo-emergency.db --runs-dir examples/demo-emergency-alert/runs --events /tmp/deltaaegis-demo-emergency-events.jsonl ingest
    python3 deltaaegis.py --db /tmp/deltaaegis-demo-emergency.db alerts --scope 192.0.2.0/24 --limit 20
    python3 deltaaegis.py --db /tmp/deltaaegis-demo-emergency.db events --scope 192.0.2.0/24 --limit 20
    python3 deltaaegis.py --db /tmp/deltaaegis-demo-emergency.db risk --scope 192.0.2.0/24 --details
    python3 deltaaegis.py --db /tmp/deltaaegis-demo-emergency.db report --scope 192.0.2.0/24 --output /tmp/deltaaegis-demo-emergency-report.md

## Safety

This is synthetic defensive telemetry for demonstrations, screenshots, training, and release validation. It should not be used as evidence of a real incident.
