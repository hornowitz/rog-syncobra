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

# Additional arguments passed to rog-syncobra.py (optional).
#
# Separate options with spaces just like you would on the command line.
# Boolean flags enable features when present (equivalent to verbose=1,
# dedup=1 style switches). Common examples include:
#   --verbose                     # chattier logging
#   --dry-run                     # simulate actions only
#   --debug                       # detailed exiftool output
#   --deldupi                     # metadata dedupe on source
#   --ddwometadata                # raw-content dedupe on source/destination
#   --dedupsourceanddest          # compare metadata against destination
#   --dedup-destination-final     # run metadata dedupe after moving files
#   --year-month-sort             # ensure Year/Month layout (default)
#   --check-year-mount            # verify destination mount point
#   --whatsapp                    # enable WhatsApp-specific handling
#   --archive-dir /srv/media/archive
#   --archive-years 3
#   --skip-marker .rog-syncobraignore
#   --exiftool-workers 4
#   --grace 600                   # delay (seconds) before processing events
#   --photoprism-index-command "photoprism index -f -c {path_q}"
#   --photoprism-api-base-url https://photos.example.com
#   --photoprism-api-username admin
#   --photoprism-api-password supersecret
#   --photoprism-api-rescan
#   --photoprism-api-cleanup
#   --photoprism-api-strip-prefix /mnt/photos
#   --photoprism-api-call /index
#
# Combine whichever options you need, for example:
# EXTRA_ARGS="--verbose --dedupsourceanddest --dedup-destination-final"
# EXTRA_ARGS="--dry-run --debug --exiftool-workers 8 --grace 900"
# EXTRA_ARGS="--photoprism-api-base-url https://photos.example.com --photoprism-api-username admin --photoprism-api-password supersecret --photoprism-api-rescan --photoprism-api-strip-prefix /mnt/photos"
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
    cat <<EOM
Installation complete.
Next steps:
  1. Run 'systemctl daemon-reload'.
  2. Copy $CONFIG_DIR/rog-syncobra.conf.example to $CONFIG_DIR/<name>.conf and adjust paths.
  3. Enable the service with 'systemctl enable --now rog-syncobra@<name>.service'.
EOM
fi
