#!/usr/bin/env bash
set -euo pipefail

PREFIX=/usr/local
SYSTEMD_DIR=/etc/systemd/system
CONFIG_DIR=/etc/rog-syncobra
DRY_RUN=0

print_usage() {
    cat <<'USAGE'
Usage: ./uninstall.sh [options]

Remove rog-syncobra scripts and supporting files.

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
    echo "This uninstaller must be run as root." >&2
    exit 1
fi

BIN_DIR="$PREFIX/bin"
SHARE_DIR="$PREFIX/share/rog-syncobra"

remove_path() {
    local path=$1
    local description=$2
    if [[ $DRY_RUN -eq 1 ]]; then
        printf '[dry-run] rm -f %s (%s)\n' "$path" "$description"
        return 0
    fi
    if [[ -e $path ]]; then
        rm -f "$path"
        echo "Removed $description -> $path"
    else
        echo "Skipping missing $description -> $path"
    fi
}

prune_dir_if_empty() {
    local path=$1
    if [[ -z $path || $path == / ]]; then
        return 0
    fi
    if [[ $DRY_RUN -eq 1 ]]; then
        printf '[dry-run] rmdir %s (if empty)\n' "$path"
        return 0
    fi
    if [[ -d $path ]]; then
        rmdir --ignore-fail-on-non-empty "$path" 2>/dev/null || true
    fi
}

SCRIPT_FILES=(
    "rog-syncobra.py"
    "photoprism-watcher.py"
    "xxrdfind.py"
    "photoprism_api.py"
)

for script in "${SCRIPT_FILES[@]}"; do
    remove_path "$BIN_DIR/$script" "binary"
done

remove_path "$SYSTEMD_DIR/rog-syncobra@.service" "systemd unit"
remove_path "$SYSTEMD_DIR/photoprism-watcher@.service" "systemd unit"

remove_path "$SHARE_DIR/README.md" "documentation"
remove_path "$CONFIG_DIR/rog-syncobra.conf.example" "config example"
remove_path "$CONFIG_DIR/photoprism-watcher.conf.example" "config example"

prune_dir_if_empty "$SHARE_DIR"
prune_dir_if_empty "$CONFIG_DIR"

if [[ $DRY_RUN -eq 1 ]]; then
    echo "Dry-run complete. No files were removed."
else
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl daemon-reload; then
            echo "systemd daemon reloaded."
        else
            echo "Warning: systemctl daemon-reload failed" >&2
        fi
    else
        echo "systemctl not found; skipping daemon reload."
    fi
    echo "Uninstallation complete."
fi
