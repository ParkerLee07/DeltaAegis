#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# ============================================================
# DeltaAegis Uninstaller
#
# Usage:
#   ./uninstall.sh
#   ./uninstall.sh --purge
# ============================================================

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DELTA_AEGIS_HOME="${DELTA_AEGIS_HOME:-${DELTA_AEGIS_BASE:-$SCRIPT_DIR}}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"

PURGE=0

for arg in "$@"; do
    case "$arg" in
        --purge)
            PURGE=1
            ;;
        -h|--help)
            echo "Usage: ./uninstall.sh [--purge]"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Usage: ./uninstall.sh [--purge]"
            exit 1
            ;;
    esac
done

echo "[+] Removing DeltaAegis launcher"

rm -f "$BIN_DIR/deltaaegis"

if [[ "$PURGE" -eq 1 ]]; then
    echo "[+] Removing DeltaAegis project directory: $DELTA_AEGIS_HOME"
    rm -rf "$DELTA_AEGIS_HOME"
else
    echo "[!] Runtime data and project files were not deleted."
    echo "    To remove everything, run:"
    echo "    ./uninstall.sh --purge"
fi

echo "[+] DeltaAegis uninstall complete"
