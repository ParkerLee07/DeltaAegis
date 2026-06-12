#!/usr/bin/env bash
set -euo pipefail

BASE="${DELTA_AEGIS_BASE:-$HOME/DeltaAegis}"
mkdir -p "$BASE/data" "$BASE/events"
chmod +x "$BASE/deltaaegis.py"

echo "[+] DeltaAegis Phase 1 initialized at $BASE"
echo "[+] Run: python3 $BASE/deltaaegis.py ingest"
