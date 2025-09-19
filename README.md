# rog-syncobra
Python script that utilizes exiftool and other utilities to sort and move
pictures to a desired destination.

## Requirements

The script relies on a few external programs:

- `libimage-exiftool-perl` (provides `exiftool`)
- `xxhash` (provides `xxhsum`)
- `inotify-tools` (required only for `--watch` mode)
- standard Unix tools such as `sort`, `du` and `df`

For metadata or raw-data deduplication an internal script `xxrdfind.py`
(xxhash64 with BLAKE2b confirmation) is included, removing the need for the
external `rdfind` utility. Using its `--strip-metadata` option allows
deduplication based solely on media content.

To automatically install missing packages run:

```bash
./rog-syncobra.py --install-deps
```

## Options

- `-r, --recursive` – recurse into subdirectories
- `-d, --ddwometadata` – raw dedupe by XXH64 between source and destination
- `-D, --deldupi` – force metadata dedupe on source (runs before `--ddwometadata`; now
  enabled by default)
- `-X, --dedupsourceanddest` – force metadata dedupe on source and compare against the
  destination before moving files (now the default when a destination is provided)
- `-y, --year-month-sort` – sort into `Year/Month` directories (default on)
- `-Y, --check-year-mount` – verify that the current year's folder under the
  destination exists and is a mountpoint
- `-m, --move2targetdir DIR` – destination directory for processed files
- `-w, --whatsapp` – enable WhatsApp media handling
- `-n, --dry-run` – show actions without executing them
- `--debug` – verbose exiftool output
- `--exiftool-workers N` – run exiftool with up to `N` parallel workers (default: auto)
- `-W, --watch` – watch mode; monitor for `CLOSE_WRITE` events
- `-I, --inputdir DIR` – directory to watch/process (default: current directory)
- `-g, --grace SECONDS` – seconds to wait after `close_write` (default: 300)
- `--archive-dir DIR` – directory to archive old files to
- `--archive-years YEARS` – move directories older than this many years (default: 2)
- `--skip-marker NAME` – skip directories that contain `NAME` (default: `.rog-syncobraignore`; set to an empty string to disable)
- `-F, --dedup-destination-final` – run metadata dedupe on the destination after the
  pipeline finishes moving files
- `--install-deps` – install required system packages and exit
- `--photoprism-index-command CMD` – run `CMD` via `/bin/sh -c` after changes are
  made so Photoprism can index new or removed files; failed runs are retried on the
  next invocation. The placeholders `{path}`, `{relative}`, and `{dest}` expand to
  the absolute directory path, the path relative to the destination root, and the
  destination root respectively. Appending `_q` (for example `{path_q}`) inserts a
  shell-quoted version suitable for commands such as `kubectl exec`.

### Photoprism index examples

Trigger Photoprism directly for each affected directory:

```bash
./rog-syncobra.py --photoprism-index-command "photoprism index -f -c {path_q}"
```

Run indexing inside a Kubernetes-managed Photoprism instance:

```bash
./rog-syncobra.py --photoprism-index-command \
  "kubectl exec --stdin --tty -n photoprism pod/photoprism-0 -- photoprism index -f -c {path_q}"
```

## Systemd service
An example systemd **template** unit is provided in `rog-syncobra@.service`. It
reads instance-specific settings from `/etc/rog-syncobra/<instance>.conf`,
allowing multiple configurations to run simultaneously.

To install a new instance:

```bash
sudo cp rog-syncobra@.service /etc/systemd/system/
sudo mkdir -p /etc/rog-syncobra

sudo tee /etc/rog-syncobra/example.conf <<'EOF'
INPUTDIR=/path/to/watch
DESTDIR=/path/to/destination
# Additional rog-syncobra.py options (space-separated)
EXTRA_ARGS=""
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now rog-syncobra@example.service
```

Create additional `*.conf` files under `/etc/rog-syncobra/` and start them with
`systemctl enable --now rog-syncobra@<name>.service` to run multiple instances.

## Logging

When running under systemd the service logs to the system journal and can be
viewed with `journalctl -u rog-syncobra@<instance>.service`.  Additionally, a
rotating log file is written to `/var/log/rog-syncobra/rog-syncobra.log`.
