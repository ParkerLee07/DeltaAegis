#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# DeltaAegis uninstaller
#
# Default behavior removes only managed launchers. Runtime evidence and the
# project remain in place unless an explicit purge mode is requested.

log() {
    printf '\n[+] %s\n' "$*"
}

warn() {
    printf '\n[!] %s\n' "$*" >&2
}

die() {
    printf '\n[ERROR] %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: ./uninstall.sh [OPTIONS]

Default:
  Remove the managed `deltaaegis` and `deltaaegis-troubleshooter` launchers.
  Preserve project files, runtime evidence, and data/deltaaegis.db.

Options:
  --dry-run         Preview actions without deleting anything.
  --purge-runtime   Remove runtime directories inside the project.
  --purge-project   Remove the entire DeltaAegis project directory.
  --yes             Required with --purge-project.
  -h, --help        Show this help.

Environment:
  DELTA_AEGIS_HOME  Project directory. Defaults to this script's directory.
  DELTA_AEGIS_BASE  Backward-compatible alias for DELTA_AEGIS_HOME.
  BIN_DIR           Launcher directory. Defaults to ~/.local/bin.
  DELTAAEGIS_DB_PATH
                    Optional database override. Default: data/deltaaegis.db.

Safety:
  - Processes associated with this DeltaAegis project or its configured
    NetSniper/TrueAegis roots block purges.
  - A database outside the project runtime directories is never deleted.
  - ~/DeltaAegis-local-archive is never deleted by this script.
EOF
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
DELTA_AEGIS_HOME="${DELTA_AEGIS_HOME:-${DELTA_AEGIS_BASE:-$SCRIPT_DIR}}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
DELTAAEGIS_NETSNIPER_ROOT="${DELTAAEGIS_NETSNIPER_ROOT:-$HOME/NetSniper}"
DELTAAEGIS_TRUEAEGIS_ROOT="${DELTAAEGIS_TRUEAEGIS_ROOT:-$HOME/TrueAegis}"

DB_OVERRIDE_PRESENT=0
if [[ ${DELTAAEGIS_DB_PATH+x} ]]; then
    DB_OVERRIDE_PRESENT=1
fi
DELTAAEGIS_DB_PATH="${DELTAAEGIS_DB_PATH:-data/deltaaegis.db}"

DRY_RUN=0
PURGE_RUNTIME=0
PURGE_PROJECT=0
CONFIRM=0

while (($#)); do
    case "$1" in
        --dry-run)
            DRY_RUN=1
            ;;
        --purge-runtime)
            PURGE_RUNTIME=1
            ;;
        --purge-project)
            PURGE_PROJECT=1
            ;;
        --yes)
            CONFIRM=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "Unknown option: $1"
            ;;
    esac
    shift
done

if [[ -d "$DELTA_AEGIS_HOME" ]]; then
    DELTA_AEGIS_HOME="$(cd -- "$DELTA_AEGIS_HOME" && pwd -P)"
else
    DELTA_AEGIS_HOME="$(python3 - "$DELTA_AEGIS_HOME" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).expanduser().resolve(strict=False))
PY
)"
fi

[[ -n "$DELTA_AEGIS_HOME" ]] || die "Project path is empty."
[[ "$DELTA_AEGIS_HOME" != "/" ]] || die "Refusing to operate on /."
[[ "$DELTA_AEGIS_HOME" != "$HOME" ]] || die "Refusing to operate on HOME."

if [[ "$PURGE_PROJECT" -eq 1 && "$CONFIRM" -ne 1 ]]; then
    die "--purge-project requires --yes."
fi

active_processes() {
    local pattern

    pattern="$(
        printf '%s' \
            "$(printf '%s' "$DELTA_AEGIS_HOME/deltaaegis.py" | sed 's/[][\\.^$*+?(){}|]/\\&/g')" \
            "|$(printf '%s' "$DELTAAEGIS_NETSNIPER_ROOT/" | sed 's/[][\\.^$*+?(){}|]/\\&/g')" \
            "|$(printf '%s' "$DELTAAEGIS_TRUEAEGIS_ROOT/" | sed 's/[][\\.^$*+?(){}|]/\\&/g')"
    )"

    pgrep -af -- "$pattern" 2>/dev/null || true
}

if [[ "$PURGE_RUNTIME" -eq 1 || "$PURGE_PROJECT" -eq 1 ]]; then
    processes="$(active_processes)"
    if [[ -n "$processes" ]]; then
        printf '%s\n' "$processes" >&2
        die "A related process is active; stop it cleanly before purging."
    fi
fi

resolve_database_path() {
    local value output_value

    if [[ "$DB_OVERRIDE_PRESENT" -eq 1 ]]; then
        value="$DELTAAEGIS_DB_PATH"
    elif [[ \
        -f "$DELTA_AEGIS_HOME/deltaaegis.py" \
        && "$DELTA_AEGIS_HOME" == "$HOME/DeltaAegis" \
    ]]; then
        output_value="$(
            python3 \
                "$DELTA_AEGIS_HOME/deltaaegis.py" \
                paths \
                2>/dev/null \
            | awk -F': ' '/^Database: / {print $2; exit}'
        )"
        value="${output_value:-data/deltaaegis.db}"
    else
        value="data/deltaaegis.db"
    fi

    case "$value" in
        /*)
            printf '%s\n' "$value"
            ;;
        *)
            printf '%s\n' "$DELTA_AEGIS_HOME/$value"
            ;;
    esac
}

ACTIVE_DB="$(resolve_database_path)"
LOCAL_ARCHIVE="$HOME/DeltaAegis-local-archive"

runtime_paths=(
    "$DELTA_AEGIS_HOME/data"
    "$DELTA_AEGIS_HOME/events"
    "$DELTA_AEGIS_HOME/backups"
    "$DELTA_AEGIS_HOME/reports"
    "$DELTA_AEGIS_HOME/scan-logs"
    "$DELTA_AEGIS_HOME/trueaegis-logs"
    "$DELTA_AEGIS_HOME/restore-rehearsals"
)

managed_launcher_for_project() {
    local path="$1"

    [[ -f "$path" ]] || return 1

    if grep -Fq '# Managed by DeltaAegis install.sh' "$path" \
        && grep -Fq "$DELTA_AEGIS_HOME" "$path"; then
        return 0
    fi

    grep -Fq 'deltaaegis.py' "$path" \
        && grep -Fq "$DELTA_AEGIS_HOME" "$path"
}

remove_launcher() {
    local path="$1"

    [[ -e "$path" ]] || return 0

    if ! managed_launcher_for_project "$path"; then
        warn "Preserving unmanaged launcher: $path"
        return 0
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf 'Would remove launcher: %s\n' "$path"
    else
        rm -f -- "$path"
        printf 'Removed launcher: %s\n' "$path"
    fi
}

path_is_within_runtime() {
    local candidate="$1"
    local runtime

    for runtime in "${runtime_paths[@]}"; do
        case "$candidate" in
            "$runtime"|"$runtime"/*)
                return 0
                ;;
        esac
    done

    return 1
}

log "DeltaAegis uninstall plan"
printf 'Project:          %s\n' "$DELTA_AEGIS_HOME"
printf 'Active database:  %s\n' "$ACTIVE_DB"
printf 'Local archive:    %s (always preserved)\n' "$LOCAL_ARCHIVE"

remove_launcher "$BIN_DIR/deltaaegis"
remove_launcher "$BIN_DIR/deltaaegis-troubleshooter"

if [[ "$PURGE_RUNTIME" -eq 1 && "$PURGE_PROJECT" -eq 0 ]]; then
    log "Purging project runtime directories"

    if [[ -e "$ACTIVE_DB" ]] && ! path_is_within_runtime "$ACTIVE_DB"; then
        warn "Preserving database outside project runtime roots: $ACTIVE_DB"
    fi

    for path in "${runtime_paths[@]}"; do
        case "$path" in
            "$LOCAL_ARCHIVE"|"$LOCAL_ARCHIVE"/*)
                die "Internal safety error: archive path selected for deletion."
                ;;
        esac

        if [[ "$DRY_RUN" -eq 1 ]]; then
            printf 'Would remove runtime path: %s\n' "$path"
        else
            rm -rf -- "$path"
            printf 'Removed runtime path: %s\n' "$path"
        fi
    done
fi

if [[ "$PURGE_PROJECT" -eq 1 ]]; then
    case "$LOCAL_ARCHIVE" in
        "$DELTA_AEGIS_HOME"|"$DELTA_AEGIS_HOME"/*)
            die "Local archive is inside the project; move it before purging."
            ;;
    esac

    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf 'Would remove project: %s\n' "$DELTA_AEGIS_HOME"
    else
        rm -rf -- "$DELTA_AEGIS_HOME"
        printf 'Removed project: %s\n' "$DELTA_AEGIS_HOME"
    fi
elif [[ "$PURGE_RUNTIME" -eq 0 ]]; then
    warn "Project files and runtime data were preserved."
    warn "Default database path remains: $DELTA_AEGIS_HOME/data/deltaaegis.db"
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
    log "DRY RUN complete; no files were deleted."
else
    log "DeltaAegis uninstall complete."
fi
