# rog-syncobra
Python script that utilizes exiftool and other utilities to sort and move
pictures to a desired destination.

## Requirements

The script relies on a few external programs:

- `libimage-exiftool-perl` (provides `exiftool`)
- `xxhash` (provides `xxhsum`)
- `watchdog` Python package (install via `pip install watchdog` or the `python3-watchdog`
  package; required only for `--watch` mode)
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
- `-d, --raw-dedupe` – raw dedupe by XXH64 between source and destination (legacy
  alias: `--ddwometadata`)
- `-D, --metadata-dedupe-source` – force metadata dedupe on source (runs before
  `--raw-dedupe`; legacy alias: `--deldupi`; enabled by default)
- `-X, --metadata-dedupe-source-dest` – force metadata dedupe on source and compare
  against the destination before moving files (legacy alias: `--dedupsourceanddest`;
  now the default when a destination is provided)
- `-y, --year-month-sort` – sort into `Year/Month` directories (default on)
- `-Y, --check-year-mount` – verify that the current year's folder under the
  destination exists and is a mountpoint
- `-m, --move2targetdir DIR` – destination directory for processed files
- `-w, --whatsapp` – enable WhatsApp media handling
- `-n, --dry-run` – show actions without executing them
- `-v, --verbose` – enable verbose logging output
- `--debug` – verbose exiftool output
- `-W, --watch` – watch mode; monitor for `CLOSE_WRITE` events
- `-I, --inputdir DIR` – directory to watch/process (default: current directory)
- `-g, --grace SECONDS` – seconds to wait after `close_write` (default: 300)
- `--min-age-days DAYS` – only process media at least `DAYS` old (default: disabled)
- `--archive-dir DIR` – directory to archive old files to
- `--archive-years YEARS` – move directories older than this many years (default: 2)
- `--skip-marker NAME` – skip directories that contain `NAME` (default: `.rog-syncobraignore`; set to an empty string to disable)
- `-F, --metadata-dedupe-destination-final` – run metadata dedupe on the destination
  after the pipeline finishes moving files (legacy alias: `--dedup-destination-final`)
- `--install-deps` – install required system packages and exit

### Photoprism REST watcher

For setups where Photoprism should be reindexed whenever new files appear, a
dedicated helper script `photoprism-watcher.py` is provided. rog-syncobra
itself no longer triggers PhotoPrism; use the watcher to keep your library in
sync. It watches one or more directories and triggers the REST API once changes
have settled for a configurable grace period:

```bash
./photoprism-watcher.py \
  --watch /path/to/library/originals \
  --library-root /path/to/library \
  --photoprism-api-base-url https://photos.example.com \
  --photoprism-api-username admin \
  --photoprism-api-password supersecret
```

Additional flags control how the watcher talks to PhotoPrism:

- `--initial-index` runs an indexing pass for all watched directories before
  entering watch mode.
- `--grace SECONDS` waits for a quiet period before invoking the API (default:
  300 seconds).
- `--photoprism-api-strip-prefix PREFIX` removes mount-point prefixes from
  paths submitted to the API (may be supplied multiple times).
- Supply watch directories as `PATH=PREFIX` to override the path that is
  submitted to Photoprism. Only the final directory component from `PATH` is
  appended to `PREFIX`, allowing setups such as
  `--watch /library/aktuell/2025/09=aktuell/2025`.

The watcher writes detailed logs to `/var/log/rog-syncobra/photoprism-watcher.log`.

When installed through `install.sh` a systemd template unit
`photoprism-watcher@.service` is also available. Copy
`/etc/rog-syncobra/photoprism-watcher.conf.example` to
`/etc/rog-syncobra/photoprism-watcher-<name>.conf`, adjust it to your
environment, and enable the watcher with:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now photoprism-watcher@<name>.service
```

## Installation

The repository ships with an `install.sh` helper that copies the Python
scripts, documentation, and systemd unit into their default locations. Run it as
root (or through `sudo`) from the repository root:

```bash
sudo ./install.sh
```

By default the installer places executables under `/usr/local/bin`, the
`rog-syncobra@.service` template under `/etc/systemd/system/`, and a
configuration example at `/etc/rog-syncobra/rog-syncobra.conf.example`. Use the
`--prefix`, `--systemd-dir`, and `--config-dir` options to override these
defaults. Supply `--dry-run` to review the actions without changing the system.

## Systemd service
An example systemd **template** unit is provided in `rog-syncobra@.service`. It
reads instance-specific settings from `/etc/rog-syncobra/<instance>.conf`,
allowing multiple configurations to run simultaneously. After running the
installer, copy the example configuration and adjust it for your environment:

```bash
sudo cp /etc/rog-syncobra/rog-syncobra.conf.example /etc/rog-syncobra/example.conf
sudoedit /etc/rog-syncobra/example.conf
sudo systemctl daemon-reload
sudo systemctl enable --now rog-syncobra@example.service
```

Create additional `*.conf` files under `/etc/rog-syncobra/` and start them with
`systemctl enable --now rog-syncobra@<name>.service` to run multiple instances.

Each configuration file may enable features by setting dedicated environment
variables instead of assembling a single `EXTRA_ARGS` string. Use `1`, `true`,
`yes`, or `on` to enable a toggle; `0`, `false`, `no`, or `off` disable options
that provide a "no" variant such as `METADATA_DEDUPE_SOURCE=0` (legacy
deployments may still use `DELDUPI=0`). Assign literal values to parameters
such as `GRACE` or `ARCHIVE_DIR`. For example:

```bash
VERBOSE=1
DRY_RUN=1
CHECK_YEAR_MONTH=1
GRACE=600
ARCHIVE_DIR=/srv/archive
MIN_AGE_DAYS=30
METADATA_DEDUPE_SOURCE=0
```

This configuration runs rog-syncobra with `--verbose --dry-run
--check-year-mount --grace 600 --min-age-days 30 --archive-dir /srv/archive --no-metadata-dedupe-source`. Leave
variables unset to keep their defaults. Setting `SKIP_MARKER=` (an empty value)
disables skip markers entirely. Legacy deployments using
`EXTRA_ARGS="..."` continue to work, but the per-variable approach is easier to
audit at a glance.

Assign `INPUTDIR=/path/to/incoming` in each configuration to process a single
tree, or set `INPUTDIRS=/path/one:/path/two` to monitor multiple roots. The
systemd unit expands `INPUTDIRS` into repeated `--inputdir` arguments so watch
mode reacts to changes in every listed directory.

## Logging

When running under systemd the services log to the system journal and can be
viewed with `journalctl -u <service>@<instance>.service`. Each instance also
writes to its own log file under `/var/log/rog-syncobra/`. rog-syncobra
instances use `rog-syncobra-<instance>.log` by default, while PhotoPrism watcher
instances write to `photoprism-watcher-<instance>.log`. Override the paths with
the `ROG_SYNCOBRA_LOGFILE` or `PHOTOPRISM_WATCHER_LOGFILE` environment
variables in the corresponding configuration files when a custom location is
desired.
