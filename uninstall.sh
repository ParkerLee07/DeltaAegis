#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# ============================================================
# DeltaAegis Uninstaller
#
# Default behavior:
#   - Removes the installed deltaaegis launcher from ~/.local/bin
#   - Keeps the project directory and runtime data
#
# Optional cleanup:
#   ./uninstall.sh --purge-runtime
#   ./uninstall.sh --purge-project --yes
#
# Environment overrides:
#   DELTA_AEGIS_BASE=/custom/path
#   BIN_DIR=/custom/bin
# ============================================================

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DELTA_AEGIS_HOME="${DELTA_AEGIS_HOME:-${DELTA_AEGIS_BASE:-$SCRIPT_DIR}}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"

PURGE_RUNTIME=0
PURGE_PROJECT=0
YES=0
DRY_RUN=0

usage() {
    cat <<'EOF'
Usage:
  ./uninstall.sh [options]

Options:
  --purge-runtime   Remove local runtime data directories: data, events, reports, backups.
  --purge-project   Remove the entire DeltaAegis project directory. Requires --yes.
  --yes             Confirm destructive project removal.
  --dry-run         Print what would be removed without deleting anything.
  -h, --help        Show this help message.

Environment:
  DELTA_AEGIS_BASE  DeltaAegis project directory. Defaults to this script directory.
  BIN_DIR           Directory containing the installed deltaaegis launcher. Defaults to ~/.local/bin.

Default installed database:
  data/deltaaegis.db
EOF
}

log() {
    printf '[+] %s\n' "$*"
}

warn() {
    printf '[!] %s\n' "$*" >&2
}

run_rm() {
    local target="$1"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '[dry-run] rm -rf %q\n' "$target"
        return 0
    fi

    rm -rf -- "$target"
}

for arg in "$@"; do
    case "$arg" in
        --purge-runtime)
            PURGE_RUNTIME=1
            ;;
        --purge-project)
            PURGE_PROJECT=1
            ;;
        --yes)
            YES=1
            ;;
        --dry-run)
            DRY_RUN=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            warn "Unknown option: $arg"
            usage
            exit 1
            ;;
    esac
done

if [[ "$PURGE_PROJECT" -eq 1 && "$YES" -ne 1 ]]; then
    warn "--purge-project is destructive and requires --yes."
    exit 1
fi

if [[ "$PURGE_PROJECT" -eq 1 && "$DELTA_AEGIS_HOME" == "/" ]]; then
    warn "Refusing to remove /"
    exit 1
fi

log "DeltaAegis home: $DELTA_AEGIS_HOME"
log "Launcher directory: $BIN_DIR"

LAUNCHER="$BIN_DIR/deltaaegis"

if [[ -e "$LAUNCHER" || -L "$LAUNCHER" ]]; then
    log "Removing DeltaAegis launcher: $LAUNCHER"
    run_rm "$LAUNCHER"
else
    warn "Launcher not found: $LAUNCHER"
fi

if [[ "$PURGE_RUNTIME" -eq 1 ]]; then
    log "Removing DeltaAegis runtime data directories"
    run_rm "$DELTA_AEGIS_HOME/data"
    run_rm "$DELTA_AEGIS_HOME/events"
    run_rm "$DELTA_AEGIS_HOME/reports"
    run_rm "$DELTA_AEGIS_HOME/backups"
else
    warn "Runtime data was kept."
    warn "Default database path remains: $DELTA_AEGIS_HOME/data/deltaaegis.db"
    warn "To remove runtime data, run: ./uninstall.sh --purge-runtime"
fi

if [[ "$PURGE_PROJECT" -eq 1 ]]; then
    log "Removing DeltaAegis project directory: $DELTA_AEGIS_HOME"
    run_rm "$DELTA_AEGIS_HOME"
else
    warn "Project files were kept."
    warn "To remove the entire project, run: ./uninstall.sh --purge-project --yes"
fi

log "DeltaAegis uninstall complete"
