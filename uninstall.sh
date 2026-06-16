#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

DELTA_AEGIS_HOME="${DELTA_AEGIS_HOME:-$HOME/DeltaAegis}"
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
    echo "[!] Runtime data was not deleted."
    echo "    To remove everything, run:"
    echo "    ./uninstall.sh --purge"
fi

echo "[+] DeltaAegis uninstall complete"
