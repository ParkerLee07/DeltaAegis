#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# DeltaAegis installer
#
# Creates local runtime directories and managed user launchers without
# installing system packages or overwriting the active database.
#
# Usage:
#   ./install.sh
#   ./install.sh --dry-run
#   ./install.sh --skip-health-check
#   ./install.sh --force-launcher
#
# Optional environment variables:
#   DELTA_AEGIS_BASE=/custom/DeltaAegis
#   BIN_DIR=/custom/bin
#   DELTAAEGIS_DB_PATH=/custom/database.db
#   DELTAAEGIS_NETSNIPER_ROOT=/custom/NetSniper
#   DELTAAEGIS_TRUEAEGIS_ROOT=/custom/TrueAegis
#   DELTAAEGIS_ADMIN_USERNAME=first.admin
#   DELTAAEGIS_ADMIN_PASSWORD=use-a-strong-secret
#   DELTAAEGIS_ADMIN_DISPLAY_NAME="First Admin"

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
Usage: ./install.sh [OPTIONS]

Options:
  --dry-run            Show planned actions without modifying files.
  --skip-health-check  Skip the post-install DeltaAegis health check.
  --force-launcher     Replace a conflicting unmanaged launcher.
  -h, --help           Show this help.

Environment:
  DELTA_AEGIS_BASE     Project directory. Defaults to this script's directory.
  BIN_DIR              Launcher directory. Defaults to ~/.local/bin.
  DELTAAEGIS_DB_PATH   Database path. Defaults to data/deltaaegis.db.
  DELTAAEGIS_NETSNIPER_ROOT
                       NetSniper root. Defaults to ~/NetSniper.
  DELTAAEGIS_TRUEAEGIS_ROOT
                       TrueAegis root. Defaults to ~/TrueAegis.
  DELTAAEGIS_ADMIN_USERNAME
  DELTAAEGIS_ADMIN_PASSWORD
  DELTAAEGIS_ADMIN_DISPLAY_NAME
                       Optional first-admin bootstrap values. Without these,
                       an interactive install prompts; a headless install
                       leaves first-admin creation to the dashboard /setup page.

Installed launchers:
  deltaaegis
  deltaaegis-troubleshooter

The installer never deletes or replaces an existing database.
EOF
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
BASE="${DELTA_AEGIS_BASE:-$SCRIPT_DIR}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"

# Compatibility contract retained for existing validators and launchers.
DELTAAEGIS_DB_PATH="${DELTAAEGIS_DB_PATH:-data/deltaaegis.db}"
DELTAAEGIS_NETSNIPER_ROOT="${DELTAAEGIS_NETSNIPER_ROOT:-$HOME/NetSniper}"
DELTAAEGIS_TRUEAEGIS_ROOT="${DELTAAEGIS_TRUEAEGIS_ROOT:-$HOME/TrueAegis}"

DRY_RUN=0
SKIP_HEALTH_CHECK=0
FORCE_LAUNCHER=0

while (($#)); do
    case "$1" in
        --dry-run)
            DRY_RUN=1
            ;;
        --skip-health-check)
            SKIP_HEALTH_CHECK=1
            ;;
        --force-launcher)
            FORCE_LAUNCHER=1
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

BASE="$(cd -- "$BASE" 2>/dev/null && pwd -P)" \
    || die "Project directory does not exist: $BASE"

required_files=(
    "deltaaegis.py"
    "deltaaegis_core/__init__.py"
    "deltaaegis_core/auth.py"
    "deltaaegis_core/config.py"
    "deltaaegis_core/db.py"
    "deltaaegis_core/ingest.py"
    "deltaaegis_core/jobs.py"
    "deltaaegis_core/reports.py"
    "deltaaegis_core/sites.py"
    "deltaaegis_core/web.py"
    "uninstall.sh"
    "tools/bootstrap_first_admin.py"
    "tools/reset_dashboard_admin.py"
    "tools/deltaaegis_troubleshooter.py"
)

for relative in "${required_files[@]}"; do
    [[ -f "$BASE/$relative" ]] \
        || die "Required project file is missing: $BASE/$relative"
done

command -v python3 >/dev/null 2>&1 \
    || die "python3 is required."
command -v bash >/dev/null 2>&1 \
    || die "bash is required."

case "$DELTAAEGIS_DB_PATH" in
    /*)
        RESOLVED_DB_PATH="$DELTAAEGIS_DB_PATH"
        ;;
    *)
        RESOLVED_DB_PATH="$BASE/$DELTAAEGIS_DB_PATH"
        ;;
esac

runtime_directories=(
    "$BASE/data"
    "$BASE/data/backups"
    "$BASE/events"
    "$BASE/events/backups"
    "$BASE/backups"
    "$BASE/reports"
    "$BASE/scan-logs"
    "$BASE/trueaegis-logs"
)

managed_launcher() {
    local path="$1"

    [[ -f "$path" ]] || return 1

    if grep -Fq '# Managed by DeltaAegis install.sh' "$path"; then
        return 0
    fi

    grep -Fq 'deltaaegis.py' "$path" \
        && grep -Fq "$BASE" "$path"
}

check_launcher_target() {
    local path="$1"

    [[ -e "$path" ]] || return 0

    if managed_launcher "$path"; then
        return 0
    fi

    [[ "$FORCE_LAUNCHER" -eq 1 ]] \
        || die "Refusing to replace unmanaged launcher: $path (use --force-launcher)"
}

write_deltaaegis_launcher() {
    local target="$1"
    local temporary="${target}.tmp.$$"

    {
        printf '%s\n' '#!/usr/bin/env bash'
        printf '%s\n' 'set -Eeuo pipefail'
        printf '%s\n' '# Managed by DeltaAegis install.sh'
        printf 'DELTA_AEGIS_HOME=%q\n' "$BASE"
        cat <<'EOF'
DELTAAEGIS_DB_PATH="${DELTAAEGIS_DB_PATH:-data/deltaaegis.db}"
DELTAAEGIS_NETSNIPER_ROOT="${DELTAAEGIS_NETSNIPER_ROOT:-$HOME/NetSniper}"
DELTAAEGIS_TRUEAEGIS_ROOT="${DELTAAEGIS_TRUEAEGIS_ROOT:-$HOME/TrueAegis}"

case "$DELTAAEGIS_DB_PATH" in
    /*)
        DB_PATH="$DELTAAEGIS_DB_PATH"
        ;;
    *)
        DB_PATH="$DELTA_AEGIS_HOME/$DELTAAEGIS_DB_PATH"
        ;;
esac

export DELTAAEGIS_NETSNIPER_ROOT
export DELTAAEGIS_TRUEAEGIS_ROOT

exec python3 \
    "$DELTA_AEGIS_HOME/deltaaegis.py" \
    --db "$DB_PATH" \
    "$@"
EOF
    } > "$temporary"

    chmod 0755 "$temporary"
    mv -f -- "$temporary" "$target"
}

write_troubleshooter_launcher() {
    local target="$1"
    local temporary="${target}.tmp.$$"

    {
        printf '%s\n' '#!/usr/bin/env bash'
        printf '%s\n' 'set -Eeuo pipefail'
        printf '%s\n' '# Managed by DeltaAegis install.sh'
        printf 'DELTA_AEGIS_HOME=%q\n' "$BASE"
        cat <<'EOF'
exec python3 \
    "$DELTA_AEGIS_HOME/tools/deltaaegis_troubleshooter.py" \
    --repo "$DELTA_AEGIS_HOME" \
    "$@"
EOF
    } > "$temporary"

    chmod 0755 "$temporary"
    mv -f -- "$temporary" "$target"
}

log "DeltaAegis installation plan"
printf 'Project:       %s\n' "$BASE"
printf 'Launcher dir:  %s\n' "$BIN_DIR"
printf 'Database:      %s\n' "$RESOLVED_DB_PATH"
printf 'NetSniper:     %s\n' "$DELTAAEGIS_NETSNIPER_ROOT"
printf 'TrueAegis:     %s\n' "$DELTAAEGIS_TRUEAEGIS_ROOT"

if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '\nRuntime directories:\n'
    printf '  %s\n' "${runtime_directories[@]}"
    printf '\nLaunchers:\n'
    printf '  %s\n' \
        "$BIN_DIR/deltaaegis" \
        "$BIN_DIR/deltaaegis-troubleshooter"
    printf '\nFirst-admin behavior:\n'
    printf '  credential environment -> non-interactive bootstrap\n'
    printf '  interactive terminal    -> bootstrap prompt when needed\n'
    printf '  headless/no credentials -> dashboard /setup workflow\n'
    printf '\n[+] DRY RUN: no files were changed.\n'
    exit 0
fi

check_launcher_target "$BIN_DIR/deltaaegis"
check_launcher_target "$BIN_DIR/deltaaegis-troubleshooter"

log "Creating local runtime directories"
mkdir -p -- "${runtime_directories[@]}" "$BIN_DIR"
mkdir -p -- "$(dirname "$RESOLVED_DB_PATH")"

chmod 0755 \
    "$BASE/deltaaegis.py" \
    "$BASE/install.sh" \
    "$BASE/uninstall.sh" \
    "$BASE/tools/bootstrap_first_admin.py" \
    "$BASE/tools/reset_dashboard_admin.py" \
    "$BASE/tools/deltaaegis_troubleshooter.py"

log "Installing managed user launchers"
write_deltaaegis_launcher "$BIN_DIR/deltaaegis"
write_troubleshooter_launcher "$BIN_DIR/deltaaegis-troubleshooter"

# DeltaAegis first-admin bootstrap
#
# The helper is idempotent: when an account already exists, it does not create
# another first admin. Fresh headless installs without credentials remain
# eligible for the browser-based /setup workflow.
if [[ -n "${DELTAAEGIS_ADMIN_USERNAME:-}" \
    || -n "${DELTAAEGIS_ADMIN_PASSWORD:-}" \
    || -n "${DELTAAEGIS_ADMIN_DISPLAY_NAME:-}" ]]
then
    log "Applying non-interactive first-admin bootstrap"
    PYTHONPATH="$BASE" python3 \
        "$BASE/tools/bootstrap_first_admin.py" \
        --db "$RESOLVED_DB_PATH" \
        --non-interactive
elif [[ -t 0 ]]; then
    log "Checking interactive first-admin bootstrap"
    PYTHONPATH="$BASE" python3 \
        "$BASE/tools/bootstrap_first_admin.py" \
        --db "$RESOLVED_DB_PATH"
else
    warn "No TTY or first-admin credentials were provided."
    warn "Create the first ADMIN later from the dashboard /setup page."
fi

log "Running non-mutating syntax and bundle checks"
PYTHONDONTWRITEBYTECODE=1 python3 - "$BASE" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
for relative in (
    "deltaaegis.py",
    "deltaaegis_core/__init__.py",
    "deltaaegis_core/auth.py",
    "deltaaegis_core/config.py",
    "deltaaegis_core/db.py",
    "deltaaegis_core/ingest.py",
    "deltaaegis_core/jobs.py",
    "deltaaegis_core/reports.py",
    "deltaaegis_core/sites.py",
    "deltaaegis_core/web.py",
    "tools/bootstrap_first_admin.py",
    "tools/reset_dashboard_admin.py",
    "tools/deltaaegis_troubleshooter.py",
):
    path = root / relative
    compile(path.read_text(encoding="utf-8"), str(path), "exec")
PY

bash -n "$BASE/install.sh"
bash -n "$BASE/uninstall.sh"

python3 \
    "$BASE/tools/deltaaegis_troubleshooter.py" \
    --self-check \
    --json \
    >/dev/null

if command -v node >/dev/null 2>&1; then
    log "Node.js detected: $(node --version)"
else
    warn "Node.js is not installed; JavaScript-focused diagnostics may be unavailable."
fi

if [[ "$SKIP_HEALTH_CHECK" -eq 0 ]]; then
    if [[ -f "$RESOLVED_DB_PATH" && "$BASE" == "$HOME/DeltaAegis" ]]; then
        log "Running the DeltaAegis quick health check"
        python3 \
            "$BASE/tools/deltaaegis_troubleshooter.py" \
            --repo "$BASE" \
            --quick-check
    elif [[ ! -f "$RESOLVED_DB_PATH" ]]; then
        warn "Fresh install: no database exists yet at $RESOLVED_DB_PATH"
        warn "The first dashboard start can initialize the database and first-admin workflow."
    else
        warn "Skipping automatic health check for a custom project/database path."
    fi
fi

log "DeltaAegis installation complete"
printf 'CLI:             %s\n' "$BIN_DIR/deltaaegis"
printf 'Troubleshooter:  %s\n' "$BIN_DIR/deltaaegis-troubleshooter"
printf 'Database:        %s\n' "$RESOLVED_DB_PATH"
printf '\nNext commands:\n'
printf '  deltaaegis paths\n'
printf '  deltaaegis dashboard\n'
printf '  deltaaegis-troubleshooter --quick-check\n'

case ":$PATH:" in
    *":$BIN_DIR:"*)
        ;;
    *)
        warn "$BIN_DIR is not currently in PATH."
        ;;
esac
