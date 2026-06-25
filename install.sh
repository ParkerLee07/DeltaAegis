#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# ============================================================
# DeltaAegis Installer
#
# Usage:
#   git clone https://github.com/ParkerLee07/DeltaAegis.git
#   cd DeltaAegis
#   chmod +x install.sh
#   ./install.sh
#
# Optional environment variables:
#   DELTA_AEGIS_BASE=/custom/path
#   BIN_DIR=/custom/bin
# ============================================================

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

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BASE="${DELTA_AEGIS_BASE:-$SCRIPT_DIR}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"

[[ -f "$BASE/deltaaegis.py" ]] || die "Could not find deltaaegis.py in $BASE"

command -v python3 >/dev/null 2>&1 || die "python3 is required."

log "Initializing DeltaAegis at $BASE"

mkdir -p \
    "$BASE/data" \
    "$BASE/events" \
    "$BASE/backups" \
    "$BASE/reports" \
    "$BIN_DIR"

chmod +x "$BASE/deltaaegis.py"

log "Installing deltaaegis launcher"

cat > "$BIN_DIR/deltaaegis" <<LAUNCHER
#!/usr/bin/env bash
exec python3 "$BASE/deltaaegis.py" "\$@"
LAUNCHER

chmod +x "$BIN_DIR/deltaaegis"

case ":$PATH:" in
    *":$BIN_DIR:"*)
        ;;
    *)
        warn "$BIN_DIR is not currently in your PATH."
        echo "Add this to your shell config if needed:"
        echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
        ;;
esac

log "DeltaAegis installation complete"

cat <<EOF2

Installed at:
  $BASE

Launcher:
  $BIN_DIR/deltaaegis

Try:
  deltaaegis
  deltaaegis summary
  deltaaegis paths
  deltaaegis report --limit 25

Runtime data:
  $BASE/data
  $BASE/events
  $BASE/backups
  $BASE/reports

EOF2

# DeltaAegis first-admin bootstrap
#
# Fresh installs need a local dashboard account. The installer prompts for the
# first ADMIN account only when the database has no existing dashboard users.
# Non-interactive installs may set:
#   DELTAAEGIS_DB_PATH
#   DELTAAEGIS_ADMIN_USERNAME
#   DELTAAEGIS_ADMIN_PASSWORD
#   DELTAAEGIS_ADMIN_DISPLAY_NAME
#
# Do not ship a hardcoded public default password.
DELTAAEGIS_DB_PATH="${DELTAAEGIS_DB_PATH:-data/deltaaegis.db}"
mkdir -p "$(dirname "$DELTAAEGIS_DB_PATH")"

if [ -f "tools/bootstrap_first_admin.py" ]; then
  if [ -n "${DELTAAEGIS_ADMIN_USERNAME:-}" ] || [ -n "${DELTAAEGIS_ADMIN_PASSWORD:-}" ]; then
    PYTHONPATH="$PWD" python3 tools/bootstrap_first_admin.py \
      --db "$DELTAAEGIS_DB_PATH" \
      --non-interactive
  elif [ -t 0 ]; then
    PYTHONPATH="$PWD" python3 tools/bootstrap_first_admin.py \
      --db "$DELTAAEGIS_DB_PATH"
  else
    echo "[INFO] No TTY available for dashboard admin setup."
    echo "[INFO] Create the first admin later at /setup, or rerun with DELTAAEGIS_ADMIN_USERNAME and DELTAAEGIS_ADMIN_PASSWORD."
  fi
fi
