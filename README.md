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
- `--photoprism-api-base-url URL`, `--photoprism-api-username USER`,
  `--photoprism-api-password PASS` – trigger indexing through the Photoprism REST
  API instead of executing a local command. Optional flags `--photoprism-api-rescan`
  and `--photoprism-api-cleanup` request a full rescan or cleanup cycle,
  respectively. Use `--photoprism-api-insecure` to skip TLS verification when
  working with self-signed certificates. Use `--photoprism-api-strip-prefix`
  one or more times to remove prefixes (for example host mount points) from
  paths before they are submitted to the API. Use `--photoprism-api-call [PATH]`
  to trigger the API manually (defaulting to `/`) and exit without performing
  any file processing.

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

Use the REST API instead of a shell command:

```bash
./rog-syncobra.py \
  --photoprism-api-base-url https://photos.example.com \
  --photoprism-api-username admin \
  --photoprism-api-password supersecret
```

### Photoprism REST watcher

For setups where Photoprism should be reindexed whenever new files appear, a
dedicated helper script `photoprism-watcher.py` is provided. It watches one or
more directories and triggers the REST API once changes have settled for a
configurable grace period:

```bash
./photoprism-watcher.py \
  --watch /path/to/library/originals \
  --library-root /path/to/library \
  --photoprism-api-base-url https://photos.example.com \
  --photoprism-api-username admin \
  --photoprism-api-password supersecret
```

Additional flags mirror the Photoprism options available in `rog-syncobra.py`:

- `--initial-index` runs an indexing pass for all watched directories before
  entering watch mode.
- `--grace SECONDS` waits for a quiet period before invoking the API (default:
  300 seconds).
- `--photoprism-api-strip-prefix PREFIX` removes mount-point prefixes from
  paths submitted to the API (may be supplied multiple times).

The watcher writes detailed logs to `/var/log/rog-syncobra/photoprism-watcher.log`.

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
