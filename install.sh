#!/usr/bin/env bash
set -euo pipefail

PREFIX=/usr/local
SYSTEMD_DIR=/etc/systemd/system
CONFIG_DIR=/etc/rog-syncobra
DRY_RUN=0

print_usage() {
    cat <<'USAGE'
Usage: ./install.sh [options]

Install rog-syncobra scripts and supporting files.

Options:
  --prefix DIR         Installation prefix for executables (default: /usr/local)
  --systemd-dir DIR    Directory for systemd units (default: /etc/systemd/system)
  --config-dir DIR     Directory for rog-syncobra configuration files (default: /etc/rog-syncobra)
  --dry-run            Show the actions without making any changes
  -h, --help           Show this help message and exit
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)
            [[ $# -ge 2 ]] || { echo "Missing argument for --prefix" >&2; exit 1; }
            PREFIX=$2
            shift 2
            ;;
        --systemd-dir)
            [[ $# -ge 2 ]] || { echo "Missing argument for --systemd-dir" >&2; exit 1; }
            SYSTEMD_DIR=$2
            shift 2
            ;;
        --config-dir)
            [[ $# -ge 2 ]] || { echo "Missing argument for --config-dir" >&2; exit 1; }
            CONFIG_DIR=$2
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            print_usage >&2
            exit 1
            ;;
    esac
done

if [[ $(id -u) -ne 0 ]]; then
    echo "This installer must be run as root." >&2
    exit 1
fi

BIN_DIR="$PREFIX/bin"
SHARE_DIR="$PREFIX/share/rog-syncobra"

install_file() {
    local mode=$1
    local src=$2
    local dest=$3
    if [[ $DRY_RUN -eq 1 ]]; then
        printf '[dry-run] install -Dm%s %s %s\n' "$mode" "$src" "$dest"
        return 0
    fi
    install -Dm"$mode" "$src" "$dest"
}

create_config_example() {
    local dest="$1"
    if [[ $DRY_RUN -eq 1 ]]; then
        printf '[dry-run] create %s\n' "$dest"
        return 0
    fi
    install -d "$(dirname "$dest")"
    cat >"$dest" <<'CFG'
# Example configuration for rog-syncobra systemd instances
# Copy this file to /etc/rog-syncobra/<name>.conf and adjust the paths
# before enabling rog-syncobra@<name>.service.

# Directory to watch for new media files
INPUTDIR=/srv/media/incoming

# Destination directory for sorted files
DESTDIR=/srv/media/library

# Optional feature toggles understood by rog-syncobra.py.
#
# Each option is controlled by its own environment variable instead of a
# combined EXTRA_ARGS string. Set the value to 1 to enable, 0 to disable
# (where a "no" form exists), or provide the desired value directly. Common
# examples include:
#
# VERBOSE=1                 # chattier logging output
# DRY_RUN=1                 # simulate actions without touching files
# DEBUG=1                   # detailed exiftool logging
# DDWOMETADATA=1            # raw-content dedupe between source and destination
# DELDUPI=0                 # skip metadata dedupe on the source tree
# DEDUPSOURCEANDDEST=1      # compare metadata with the destination before moving
# DEDUP_DESTINATION_FINAL=1 # run metadata dedupe after processing completes
# YEAR_MONTH_SORT=1         # keep YYYY/MM layout (enabled by default)
# CHECK_YEAR_MOUNT=1        # verify the destination year folder is a mount point
# CHECK_YEAR_MONTH=1        # alias of CHECK_YEAR_MOUNT for convenience
# WHATSAPP=1                # enable WhatsApp-specific handling
# GRACE=600                 # wait (seconds) after changes before processing
# ARCHIVE_DIR=/srv/media/archive
# ARCHIVE_YEARS=3
# SKIP_MARKER=              # disable skip markers entirely
#
# Multiple toggles may be combined by adding one assignment per line. For
# example:
#
# VERBOSE=1
# DRY_RUN=1
# CHECK_YEAR_MONTH=1
# GRACE=600
#
# Legacy deployments that still rely on EXTRA_ARGS="..." continue to work, but
# the dedicated variables above are easier to read and audit.
CFG
}

SCRIPT_FILES=(
    "rog-syncobra.py"
    "photoprism-watcher.py"
    "xxrdfind.py"
)
MODULE_FILES=(
    "photoprism_api.py"
)

for script in "${SCRIPT_FILES[@]}"; do
    install_file 755 "$script" "$BIN_DIR/$script"
    if [[ $DRY_RUN -eq 1 ]]; then
        echo "[dry-run] Would install $script -> $BIN_DIR/$script"
    else
        echo "Installed $script -> $BIN_DIR/$script"
    fi
done

for module in "${MODULE_FILES[@]}"; do
    install_file 644 "$module" "$BIN_DIR/$module"
    if [[ $DRY_RUN -eq 1 ]]; then
        echo "[dry-run] Would install $module -> $BIN_DIR/$module"
    else
        echo "Installed $module -> $BIN_DIR/$module"
    fi
done

install_file 644 "rog-syncobra@.service" "$SYSTEMD_DIR/rog-syncobra@.service"
if [[ $DRY_RUN -eq 1 ]]; then
    echo "[dry-run] Would install systemd unit -> $SYSTEMD_DIR/rog-syncobra@.service"
else
    echo "Installed systemd unit -> $SYSTEMD_DIR/rog-syncobra@.service"
fi

install_file 644 "photoprism-watcher@.service" "$SYSTEMD_DIR/photoprism-watcher@.service"
if [[ $DRY_RUN -eq 1 ]]; then
    echo "[dry-run] Would install PhotoPrism watcher unit -> $SYSTEMD_DIR/photoprism-watcher@.service"
else
    echo "Installed PhotoPrism watcher unit -> $SYSTEMD_DIR/photoprism-watcher@.service"
fi

install_file 644 "README.md" "$SHARE_DIR/README.md"
if [[ $DRY_RUN -eq 1 ]]; then
    echo "[dry-run] Would install documentation -> $SHARE_DIR/README.md"
else
    echo "Installed documentation -> $SHARE_DIR/README.md"
fi

create_config_example "$CONFIG_DIR/rog-syncobra.conf.example"
if [[ $DRY_RUN -eq 1 ]]; then
    echo "[dry-run] Would create configuration example -> $CONFIG_DIR/rog-syncobra.conf.example"
else
    echo "Configuration example -> $CONFIG_DIR/rog-syncobra.conf.example"
fi

install_file 644 "photoprism-watcher.conf.example" "$CONFIG_DIR/photoprism-watcher.conf.example"
if [[ $DRY_RUN -eq 1 ]]; then
    echo "[dry-run] Would install watcher configuration example -> $CONFIG_DIR/photoprism-watcher.conf.example"
else
    echo "Watcher configuration example -> $CONFIG_DIR/photoprism-watcher.conf.example"
fi

echo
if [[ $DRY_RUN -eq 1 ]]; then
    echo "Dry-run complete. No changes were made."
else
    systemctl daemon-reload
    cat <<EOM
Installation complete.
Next steps:
  1. Run 'systemctl daemon-reload'.
  2. Copy $CONFIG_DIR/rog-syncobra.conf.example to $CONFIG_DIR/<name>.conf and adjust paths.
  3. Enable the service with 'systemctl enable --now rog-syncobra@<name>.service'.
EOM
fi
