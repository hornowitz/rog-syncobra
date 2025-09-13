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
(based on xxhash64) is included, removing the need for the external
`rdfind` utility.  Using its `--strip-metadata` option allows deduplication
based solely on media content.

To automatically install missing packages run:

```bash
./rog-syncobra.py --install-deps
```

## Options

- `-r, --recursive` – recurse into subdirectories
- `-d, --ddwometadata` – raw dedupe by XXH64 between source and destination
- `-D, --deldupi` – metadata dedupe by bundled xxhash scanner on source
- `-X, --deldupidest` – metadata dedupe by bundled xxhash scanner on destination
- `-y, --year-month-sort` – sort into `Year/Month` directories (default on)
- `-Y, --check-year-mount` – verify that the current year's folder under the
  destination exists and is a mountpoint
- `-m, --move2targetdir DIR` – destination directory for processed files
- `-w, --whatsapp` – enable WhatsApp media handling
- `-n, --dry-run` – show actions without executing them
- `--debug` – verbose exiftool output
- `-W, --watch` – watch mode; monitor for `CLOSE_WRITE` events
- `-I, --inputdir DIR` – directory to watch/process (default: current directory)
- `-g, --grace SECONDS` – seconds to wait after `close_write` (default: 300)
- `--archive-dir DIR` – directory to archive old files to
- `--archive-years YEARS` – move directories older than this many years (default: 2)
- `--install-deps` – install required system packages and exit

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
