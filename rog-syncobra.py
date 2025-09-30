#!/usr/bin/env python3
import os
import sys
import shutil
import subprocess
import logging
import argparse
import shlex
import time
import threading
import queue
import importlib.util
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, Sequence, Tuple, Union

import xxrdfind

try:  # pragma: no cover - optional dependency import
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:  # pragma: no cover - handled at runtime
    FileSystemEventHandler = None  # type: ignore[assignment]
    Observer = None  # type: ignore[assignment]

HEIC_EXTS = {'.heic', '.heif'}
SCREENSHOT_EXTS = {'.png', '.jpg', '.jpeg', '.heic', '.heif', '.webp'}
WHATSAPP_IMAGE_EXTS = {'.jpg', '.jpeg'}
WHATSAPP_VIDEO_EXTS = {'.mp4', '.mov', '.3gp'}
ANDROID_VIDEO_EXTS = {'.mp4', '.mov', '.mts', '.mpg', '.vob', '.3gp', '.avi'}
DCIM_EXTS = {
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp',
    '.heic', '.heif', '.tif', '.tiff', '.dng', '.nef', '.arw', '.orf', '.raf',
    '.rw2', '.srw', '.cr2', '.cr3', '.pef', '.raw',
    '.mp4', '.mov', '.m4v', '.mts', '.m2ts', '.mpg', '.mpeg', '.vob', '.3gp',
    '.avi', '.mkv', '.wmv', '.hevc', '.webm',
}
MEDIA_SCAN_EXTS = (
    HEIC_EXTS
    | SCREENSHOT_EXTS
    | WHATSAPP_IMAGE_EXTS
    | WHATSAPP_VIDEO_EXTS
    | ANDROID_VIDEO_EXTS
    | DCIM_EXTS
)


def _expand_path(path: str) -> str:
    """Return a normalized absolute path with user expansion."""

    return os.path.abspath(os.path.expanduser(path))


def normalize_extensions(exts):
    if not exts:
        return set()
    normalized = set()
    for ext in exts:
        if not ext:
            continue
        ext = ext.lower()
        if not ext.startswith('.'):
            ext = f'.{ext}'
        normalized.add(ext)
    return normalized


def describe_extensions(exts):
    if not exts:
        return ''
    return ", ".join(sorted(e.lstrip('.').upper() for e in exts))


def build_exiftool_extension_filters(exts: Sequence[str]) -> list[str]:
    """Return a list of ``-ext`` arguments for exiftool.

    The stay-open interface expects each argument on its own line, so this
    helper keeps the construction of extension filters in one place and
    guarantees deterministic ordering.  Exiftool wants raw extensions without
    a leading dot; we normalise incoming values and convert them to upper case
    to keep the generated commands easy to read in logs.
    """

    filters: list[str] = []
    for ext in sorted(normalize_extensions(exts)):
        filters.extend(['-ext', ext.lstrip('.').upper()])
    return filters


def scan_media_extensions(root, recursive=False, extensions=None, skip_paths=None):
    targets = normalize_extensions(extensions)
    found = set()
    stack = [root]
    while stack:
        current = stack.pop()
        current_abs = _expand_path(current)
        if skip_paths and any(
            current_abs == skip or current_abs.startswith(f"{skip}{os.sep}")
            for skip in skip_paths
        ):
            continue
        try:
            with os.scandir(current) as iterator:
                for entry in iterator:
                    try:
                        if entry.is_file():
                            _, ext = os.path.splitext(entry.name)
                            if not ext:
                                continue
                            ext = ext.lower()
                            if targets and ext not in targets:
                                continue
                            found.add(ext)
                        elif recursive and entry.is_dir(follow_symlinks=False):
                            entry_abs = _expand_path(entry.path)
                            if skip_paths and any(
                                entry_abs == skip or entry_abs.startswith(f"{skip}{os.sep}")
                                for skip in skip_paths
                            ):
                                continue
                            stack.append(entry.path)
                    except FileNotFoundError:
                        continue
        except PermissionError as exc:
            logger.debug(f"Permission denied while scanning {current}: {exc}")
        except FileNotFoundError:
            logger.debug(f"Path disappeared while scanning: {current}")
    return found


def has_matching_media(found_exts, candidates):
    if not candidates:
        return bool(found_exts)
    normalized = normalize_extensions(candidates)
    return bool(found_exts & normalized)

# ────────────────────────────────────────────────────────────────────────────────
# Configuration
DEFAULT_LOGFILE = '/var/log/rog-syncobra/rog-syncobra.log'

def _resolve_logfile() -> Optional[str]:
    raw = os.environ.get('ROG_SYNCOBRA_LOGFILE')
    if raw is None:
        return DEFAULT_LOGFILE
    candidate = raw.strip()
    if not candidate:
        return None
    return _expand_path(candidate)


LOGFILE = _resolve_logfile()
#────────────────────────────────────────────────────────────────────────────────

# ─── Logging setup ─────────────────────────────────────────────────────────────
logdir = os.path.dirname(LOGFILE) if LOGFILE else None
if logdir:
    try:
        os.makedirs(logdir, exist_ok=True)
    except Exception as e:
        print(f"ERROR: could not create log dir {logdir}: {e}", file=sys.stderr)

logger = logging.getLogger('rog-syncobra')
logger.setLevel(logging.INFO)

fmt = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')

LOG_HANDLERS: list[logging.Handler] = []

sh = logging.StreamHandler(sys.stdout)
sh.setLevel(logging.INFO)
sh.setFormatter(fmt)
logger.addHandler(sh)
LOG_HANDLERS.append(sh)

if LOGFILE:
    try:
        fh = logging.FileHandler(LOGFILE)
        fh.setLevel(logging.INFO)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
        LOG_HANDLERS.append(fh)
    except Exception as e:
        logger.error(f"Could not open log file {LOGFILE}: {e}")

try:
    from systemd.journal import JournalHandler
    jh = JournalHandler()
    jh.setLevel(logging.INFO)
    jh.setFormatter(fmt)
    logger.addHandler(jh)
    LOG_HANDLERS.append(jh)
except Exception:
    pass
# ────────────────────────────────────────────────────────────────────────────────


XXRDFIND_CONFIG: dict[str, Optional[int]] = {
    'threads': None,
    'scan_threads': None,
}


def configure_xxrdfind(threads: Optional[int] = None, scan_threads: Optional[int] = None) -> None:
    """Configure xxrdfind execution defaults for serialized execution."""

    if threads not in (None, 1):
        logger.warning(
            "Ignoring xxrdfind thread override (%s); running sequentially with a single worker",
            threads,
        )
    if scan_threads not in (None, 1):
        logger.warning(
            "Ignoring xxrdfind scan thread override (%s); running sequentially with a single worker",
            scan_threads,
        )

    XXRDFIND_CONFIG['threads'] = 1
    XXRDFIND_CONFIG['scan_threads'] = 1

    logger.debug("xxrdfind configured for serialized execution (threads=1, scan_threads=1)")


@dataclass
class OperationTracker:
    deleted: list[Path] = field(default_factory=list)
    moved: list[Tuple[Path, Path]] = field(default_factory=list)

    def reset(self) -> None:
        self.deleted.clear()
        self.moved.clear()

    def record_deleted(self, paths: Sequence[Union[Path, str]]) -> None:
        for path in paths:
            if path is None:
                continue
            self.deleted.append(Path(path))

    def record_moved(self, src: Union[Path, str], dest: Union[Path, str]) -> None:
        self.moved.append((Path(src), Path(dest)))

    def log_summary(self) -> None:
        if self.deleted:
            logger.info(
                "Deleted files (%d): %s",
                len(self.deleted),
                ", ".join(str(p) for p in self.deleted),
            )
        else:
            logger.info("Deleted files: none")

        if self.moved:
            logger.info(
                "Moved files (%d): %s",
                len(self.moved),
                ", ".join(f"{src} → {dest}" for src, dest in self.moved),
            )
        else:
            logger.info("Moved files: none")


_operation_tracker = OperationTracker()


def get_operation_tracker() -> OperationTracker:
    return _operation_tracker

def check_program(name):
    if not shutil.which(name):
        logger.error(f"Required program '{name}' not found in PATH.")
        sys.exit(1)


def install_requirements():
    """Install missing external program dependencies using apt."""
    packages = {
        'exiftool': 'libimage-exiftool-perl',
        'xxhsum': 'xxhash',
    }
    missing = [pkg for prog, pkg in packages.items() if not shutil.which(prog)]
    python_packages = {
        'watchdog': 'python3-watchdog',
    }
    for module, package in python_packages.items():
        if importlib.util.find_spec(module) is None:
            missing.append(package)
    if not missing:
        logger.info("All required programs already installed")
        return
    logger.info("Installing missing packages: %s" % ", ".join(missing))
    try:
        subprocess.run(['sudo', 'apt-get', 'update'], check=True)
        subprocess.run(['sudo', 'apt-get', 'install', '-y', *missing], check=True)
    except Exception as e:
        logger.error(f"Failed to install dependencies: {e}")
        sys.exit(1)

def set_logging_verbosity(enable_debug: bool) -> None:
    level = logging.DEBUG if enable_debug else logging.INFO
    logger.setLevel(level)
    for handler in LOG_HANDLERS:
        handler.setLevel(level)

    # Mirror the verbosity settings onto the xxrdfind logger so that
    # dedupe operations provide matching detail when verbose/debug is enabled.
    xx_logger = logging.getLogger('xxrdfind')
    xx_logger.setLevel(level)
    xx_logger.propagate = False
    for handler in LOG_HANDLERS:
        if handler not in xx_logger.handlers:
            xx_logger.addHandler(handler)


TRUE_VALUES = {'1', 'true', 'yes', 'on'}
FALSE_VALUES = {'0', 'false', 'no', 'off'}

ENV_BOOL_FLAGS: dict[str, str] = {
    'VERBOSE': '--verbose',
    'DEBUG': '--debug',
    'DRY_RUN': '--dry-run',
    'WATCH': '--watch',
    'RECURSIVE': '--recursive',
    'WHATSAPP': '--whatsapp',
    'DDWOMETADATA': '--raw-dedupe',
    'RAW_DEDUPE': '--raw-dedupe',
    'YEAR_MONTH_SORT': '--year-month-sort',
    'CHECK_YEAR_MOUNT': '--check-year-mount',
    'CHECK_YEAR_MONTH': '--check-year-mount',
    'DEDUP_DESTINATION_FINAL': '--metadata-dedupe-destination-final',
    'METADATA_DEDUPE_DESTINATION_FINAL': '--metadata-dedupe-destination-final',
}

ENV_TOGGLE_FLAGS: dict[str, tuple[str, str]] = {
    'DELDUPI': (
        '--metadata-dedupe-source',
        '--no-metadata-dedupe-source',
    ),
    'METADATA_DEDUPE_SOURCE': (
        '--metadata-dedupe-source',
        '--no-metadata-dedupe-source',
    ),
    'DEDUPSOURCEANDDEST': (
        '--metadata-dedupe-source-dest',
        '--no-metadata-dedupe-source-dest',
    ),
    'METADATA_DEDUPE_SOURCE_DEST': (
        '--metadata-dedupe-source-dest',
        '--no-metadata-dedupe-source-dest',
    ),
}

ENV_VALUE_FLAGS: dict[str, dict[str, Union[str, bool]]] = {
    'GRACE': {'flag': '--grace'},
    'ARCHIVE_DIR': {'flag': '--archive-dir'},
    'ARCHIVE_YEARS': {'flag': '--archive-years'},
    'SKIP_MARKER': {'flag': '--skip-marker', 'allow_empty': True},
    'MIN_AGE_DAYS': {'flag': '--min-age-days'},
    'XXRDFIND_THREADS': {'flag': '--xxrdfind-threads'},
    'XXRDFIND_SCAN_THREADS': {'flag': '--xxrdfind-scan-threads'},
}


def _parse_env_bool(value: str) -> Union[bool, None]:
    stripped = value.strip()
    hash_index = stripped.find('#')
    if hash_index != -1:
        stripped = stripped[:hash_index].rstrip()
    if stripped == '':
        return None
    lowered = stripped.lower()
    if lowered in TRUE_VALUES:
        return True
    if lowered in FALSE_VALUES:
        return False
    return None


def _collect_cli_args_from_env(environ: Optional[dict[str, str]] = None) -> list[str]:
    env = os.environ if environ is None else environ
    cli_args: list[str] = []

    for var, flag in ENV_BOOL_FLAGS.items():
        raw = env.get(var)
        if raw is None:
            continue
        result = _parse_env_bool(raw)
        if result is None:
            logger.warning(
                "Ignoring %s=%s (expected one of %s or %s)",
                var,
                raw,
                '/'.join(sorted(TRUE_VALUES)),
                '/'.join(sorted(FALSE_VALUES)),
            )
            continue
        if result:
            cli_args.append(flag)

    for var, (enable_flag, disable_flag) in ENV_TOGGLE_FLAGS.items():
        raw = env.get(var)
        if raw is None:
            continue
        result = _parse_env_bool(raw)
        if result is None:
            logger.warning(
                "Ignoring %s=%s (expected one of %s or %s)",
                var,
                raw,
                '/'.join(sorted(TRUE_VALUES)),
                '/'.join(sorted(FALSE_VALUES)),
            )
            continue
        cli_args.append(enable_flag if result else disable_flag)

    for var, spec in ENV_VALUE_FLAGS.items():
        if var not in env:
            continue
        raw_value = env[var]
        value = raw_value.strip()
        if value == '' and not spec.get('allow_empty', False):
            continue
        cli_args.extend([spec['flag'], value])

    extra = env.get('EXTRA_ARGS')
    if extra:
        try:
            cli_args.extend(shlex.split(extra))
        except ValueError as exc:
            logger.warning("Could not parse EXTRA_ARGS (%s): %s", extra, exc)

    return cli_args


def _inject_env_cli_args() -> None:
    env_args = _collect_cli_args_from_env()
    if not env_args:
        return
    sys.argv = [sys.argv[0], *env_args, *sys.argv[1:]]


def parse_args():
    p = argparse.ArgumentParser(description="rog-syncobra: sort & dedupe media")
    p.add_argument('-r','--recursive', action='store_true', help="Recurse subdirectories")
    p.add_argument('-d','--raw-dedupe','--ddwometadata', dest='raw_dedupe', action='store_true',
                   help="Raw dedupe by data (XXH64) between source & dest")
    p.add_argument('-D','--metadata-dedupe-source','--deldupi', dest='metadata_dedupe_source', action='store_true', default=True,
                   help="Force metadata dedupe on source (use --no-metadata-dedupe-source to skip)")
    p.add_argument('--no-metadata-dedupe-source','--no-deldupi', dest='metadata_dedupe_source', action='store_false',
                   help="Skip metadata dedupe on source before processing")
    p.add_argument('-X','--metadata-dedupe-source-dest','--dedupsourceanddest', dest='metadata_dedupe_source_dest', action='store_true', default=None,
                   help="Force metadata dedupe between source and destination pre-move (auto unless disabled)")
    p.add_argument('--no-metadata-dedupe-source-dest','--no-dedupsourceanddest', dest='metadata_dedupe_source_dest', action='store_false',
                   help="Skip metadata dedupe between source and destination before processing")
    p.add_argument('-y','--year-month-sort', action='store_true',
                   help="Sort into Year/Month dirs (default on)")
    p.add_argument('-Y','--check-year-mount', action='store_true',
                   help="Verify current year dir under destination is a mountpoint")
    p.add_argument('--xxrdfind-threads', type=int, default=None,
                   help="Override worker threads for xxrdfind (default: auto)")
    p.add_argument('--xxrdfind-scan-threads', type=int, default=None,
                   help="Override directory scan threads for xxrdfind (default: auto)")
    p.add_argument('-m','--move2targetdir', metavar='DIR', default='',
                   help="Destination directory for processed files")
    p.add_argument('-w','--whatsapp', action='store_true',
                   help="Enable WhatsApp media handling")
    p.add_argument('-n','--dry-run', action='store_true',
                   help="Show actions without executing")
    p.add_argument('--debug', action='store_true',
                   help="Verbose exiftool (-v); default is quiet (-q)")
    p.add_argument('-v','--verbose', action='store_true',
                   help="Enable verbose logging output")
    p.add_argument('-W','--watch', action='store_true',
                   help="Watch mode: monitor for CLOSE_WRITE events")
    p.add_argument('-I','--inputdir', dest='inputdirs', action='append',
                   help="Directory to watch/process (can be provided multiple times; default cwd)")
    p.add_argument('-g','--grace', type=int, default=300,
                   help="Seconds to wait after close_write (default 300)")
    p.add_argument('--min-age-days', type=int, default=0,
                   help="Minimum age in days before media is processed (0 disables)")
    p.add_argument('--archive-dir', default='',
                   help="Directory to archive old files to (e.g. /rogaliki/obrazy/0archiv)")
    p.add_argument('--archive-years', type=int, default=2,
                   help="Move directories older than this many years (default 2)")
    p.add_argument('--skip-marker', default='.rog-syncobraignore',
                   help="Filename that marks directories to skip (set to '' to disable)")
    p.add_argument('-F','--metadata-dedupe-destination-final','--dedup-destination-final', dest='metadata_dedupe_destination_final', action='store_true',
                   help="Run metadata dedupe on destination after processing completes")
    p.add_argument('--install-deps', action='store_true',
                   help="Install required system packages and exit")

    # Use parse_known_args so we can gracefully ignore stray '-' arguments.
    # A single dash can sneak in via misconfigured systemd unit files or
    # shell wrappers and would normally cause argparse to abort.  We strip
    # such dashes from the list of unknown arguments and only raise an error
    # if anything else remains.
    args, extra = p.parse_known_args()
    extra = [e for e in extra if e != '-']
    if extra:
        p.error(f"unrecognized arguments: {' '.join(extra)}")
    if not args.inputdirs:
        args.inputdirs = [os.getcwd()]
    if args.min_age_days < 0:
        p.error("--min-age-days must be zero or greater")

    return args

def safe_run(cmd, dry_run=False):
    logger.info(" ".join(cmd))
    if dry_run:
        return
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        logger.warning(f"Command failed ({e.returncode}), continuing...")

def check_disk_space(src, dest, dry_run=False):
    if isinstance(src, (str, bytes, os.PathLike)):
        sources = [src]
    elif isinstance(src, Sequence):
        sources = list(src)
    else:
        sources = [src]

    if not sources:
        return

    wd_abs = os.path.realpath(dest or sources[0])
    src_abs_paths = [os.path.realpath(path) for path in sources]

    if all(src_abs == wd_abs for src_abs in src_abs_paths):
        logger.info("Source and destination identical; skipping disk space check")
        return

    total_required = 0
    for src_abs in src_abs_paths:
        logger.info(f"Checking disk space under {src_abs}")
        if wd_abs.startswith(src_abs):
            excl = f"--exclude={wd_abs}/*"
            du_cmd = ['du', '--bytes', excl, '-c', src_abs]
        else:
            du_cmd = ['du', '--bytes', '-c', src_abs]
        try:
            out = subprocess.check_output(du_cmd, stderr=subprocess.STDOUT).decode()
        except subprocess.CalledProcessError as exc:
            output = exc.output.decode(errors='ignore') if isinstance(exc.output, bytes) else str(exc.output)
            logger.warning(
                "Could not determine disk usage for %s (exit %s): %s",
                src_abs,
                exc.returncode,
                output.strip(),
            )
            continue

        try:
            required = int(
                [line for line in out.splitlines() if line.endswith('total')][0].split()[0]
            )
        except (IndexError, ValueError) as exc:
            logger.warning(
                "Unexpected output from du while scanning %s: %s",
                src_abs,
                exc,
            )
            continue
        total_required += required

    if not total_required:
        return

    usage_path = wd_abs
    while not os.path.exists(usage_path):
        parent = os.path.dirname(usage_path)
        if parent == usage_path:
            break
        usage_path = parent
    stat = shutil.disk_usage(usage_path)
    avail = stat.free
    logger.info(
        f"Required: {total_required} B ({total_required/1024/1024:.2f} MB), "
        f"Available: {avail} B ({avail/1024/1024:.2f} MB)"
    )
    if not dry_run and avail < total_required:
        logger.error("Not enough space, aborting")
        sys.exit(1)

def check_year_mount(dest):
    """Ensure the destination's current year directory exists and is mounted."""
    year_dir = os.path.join(_expand_path(dest), datetime.now().strftime('%Y'))
    if not os.path.isdir(year_dir):
        logger.error(f"Year directory {year_dir} does not exist")
        sys.exit(1)
    if not os.path.ismount(year_dir):
        logger.error(f"Year directory {year_dir} is not a mountpoint")
        sys.exit(1)
    logger.info(f"Verified mountpoint for {year_dir}")

def xxrdfind_dedupe(paths, dry_run=False, strip_metadata=False, delete_within=None):
    path_strings = [str(p) for p in paths]
    details = []
    mode = strip_metadata
    if isinstance(mode, str) and mode == 'both':
        details.append('metadata+raw')
    elif mode:
        details.append('strip_metadata')
    delete_within_strings = [str(root) for root in delete_within] if delete_within else []
    threads = XXRDFIND_CONFIG.get('threads')
    scan_workers = XXRDFIND_CONFIG.get('scan_threads')
    if threads is not None:
        details.append(f"threads={threads}")
    if scan_workers is not None:
        details.append(f"scan_threads={scan_workers}")
    if delete_within_strings:
        details.append(f"delete_within={', '.join(delete_within_strings)}")
    detail_str = f" ({'; '.join(details)})" if details else ''
    logger.info("xxrdfind dedupe: %s%s", " ".join(path_strings), detail_str)
    if dry_run:
        logger.info("Dry run: skipping xxrdfind execution")
        return xxrdfind.DuplicateSummary()

    delete_roots = [Path(root) for root in delete_within_strings] if delete_within_strings else None
    summary = xxrdfind.find_duplicates(
        [Path(p) for p in path_strings],
        delete=True,
        dry_run=dry_run,
        threads=threads,
        show_progress=False,
        strip_metadata=strip_metadata,
        delete_roots=delete_roots,
        scan_workers=scan_workers,
    )
    tracker = get_operation_tracker()
    tracker.record_deleted(summary.deleted)
    return summary


def metadata_dedupe(path, dry_run=False):
    prefix = "[DRY] " if dry_run else ""
    logger.info(f"{prefix}Metadata dedupe via xxrdfind: {path}")
    xxrdfind_dedupe([path], dry_run=dry_run, strip_metadata=False)


def metadata_dedupe_source_against_dest(src, dest, dry_run=False):
    src_abs = _expand_path(src)
    dest_abs = _expand_path(dest)
    prefix = "[DRY] " if dry_run else ""
    message = (
        f"{prefix}Metadata dedupe via xxrdfind between destination ({dest_abs}) "
        f"and source ({src_abs}); deleting duplicates from source"
    )
    logger.info(message)
    xxrdfind_dedupe(
        [dest_abs, src_abs],
        dry_run=dry_run,
        strip_metadata=False,
        delete_within=[src_abs],
    )


def raw_dedupe(src, dest, dry_run=False, *_, **__):
    paths = []
    dest_abs = _expand_path(dest) if dest else None
    src_abs = _expand_path(src)
    if dest_abs and dest_abs != src_abs:
        paths.append(dest_abs)
    paths.append(src_abs)
    prefix = "[DRY] " if dry_run else ""
    logger.info(
        f"{prefix}Raw dedupe via xxrdfind (including metadata pass): {' '.join(paths)}"
    )
    xxrdfind_dedupe(paths, dry_run=dry_run, strip_metadata='both')

def exif_sort(src, dest, args):
    cwd = os.getcwd()
    src_abs = _expand_path(src)
    os.chdir(src_abs)
    exiftool_flags = ['-q']
    if args.debug:
        # Keep exiftool quiet so the stay-open protocol remains predictable while
        # still surfacing progress information when debugging.
        exiftool_flags.append('-progress')

    def _exiftool_cmd(*parts: str) -> list[str]:
        return ['exiftool', *exiftool_flags, *parts]
    ym = '%Y/%m' if args.year_month_sort else '.'
    skip_marker = args.skip_marker
    skip_rel = set()
    skip_abs = set()
    min_age_days = int(getattr(args, 'min_age_days', 0) or 0)
    if min_age_days < 0:
        min_age_days = 0
    cutoff_epoch = None
    age_filter_args: Optional[list[str]] = None
    if min_age_days:
        cutoff_epoch = int(time.time() - (min_age_days * 86400))
        if cutoff_epoch < 0:
            cutoff_epoch = 0
        age_filter_args = ['-if', f'$FileModifyDate# <= {cutoff_epoch}']
        logger.info(
            "Requiring minimum file age of %d day(s) before processing", min_age_days
        )

    def mark_skip(rel_path):
        if rel_path in skip_rel:
            return
        skip_rel.add(rel_path)
        abs_path = _expand_path(os.path.join(src_abs, rel_path))
        skip_abs.add(abs_path)
        if skip_marker:
            logger.info(
                "Skip marker %s present in %s; skipping directory",
                skip_marker,
                abs_path,
            )

    if skip_marker:
        if os.path.exists(skip_marker):
            mark_skip('.')

    if args.recursive:
        targets = ['.']
        seen = {'.'}
        for walk_root, dirs, _ in os.walk('.', topdown=True):
            if skip_marker and walk_root in skip_rel:
                dirs[:] = []
                continue
            if skip_marker:
                marker_here = os.path.join(walk_root, skip_marker)
                if os.path.exists(marker_here):
                    mark_skip(walk_root or '.')
                    dirs[:] = []
                    continue
            dirs.sort()
            pruned = []
            for name in dirs:
                rel = os.path.join(walk_root, name)
                if skip_marker:
                    marker_path = os.path.join(rel, skip_marker)
                    if os.path.exists(marker_path):
                        mark_skip(rel)
                        continue
                if rel in seen:
                    continue
                targets.append(rel)
                seen.add(rel)
                pruned.append(name)
            dirs[:] = pruned
    else:
        targets = ['.']

    if skip_rel:
        targets = [t for t in targets if t not in skip_rel]

    present_exts = scan_media_extensions(
        src_abs, args.recursive, MEDIA_SCAN_EXTS, skip_paths=skip_abs
    )
    if logger.isEnabledFor(logging.DEBUG):
        detected = describe_extensions(present_exts) or 'none'
        logger.debug(f"Detected media extensions: {detected}")

    heic_present = has_matching_media(present_exts, HEIC_EXTS)
    screenshot_present = has_matching_media(present_exts, SCREENSHOT_EXTS)
    whatsapp_image_present = has_matching_media(present_exts, WHATSAPP_IMAGE_EXTS)
    whatsapp_video_present = has_matching_media(present_exts, WHATSAPP_VIDEO_EXTS)
    android_video_present = has_matching_media(present_exts, ANDROID_VIDEO_EXTS)
    dcim_present = has_matching_media(present_exts, DCIM_EXTS)

    should_run = any(
        (
            heic_present,
            screenshot_present,
            android_video_present,
            dcim_present,
            args.whatsapp and (whatsapp_image_present or whatsapp_video_present),
        )
    )

    if not should_run:
        if present_exts:
            logger.info(
                "Skipping exiftool processing in %s (no matching HEIC/screenshot/DCIM media)",
                src_abs,
            )
        else:
            logger.info(
                "Skipping exiftool processing in %s (no media files detected)", src_abs
            )
        os.chdir(cwd)
        return False

    if age_filter_args and cutoff_epoch is not None:

        youngest_mtime: Optional[float] = None

        def _has_eligible_media() -> bool:
            nonlocal youngest_mtime
            stack = [os.path.join(src_abs, target) for target in targets]
            seen_dirs = set()
            while stack:
                current = stack.pop()
                if current in seen_dirs:
                    continue
                seen_dirs.add(current)
                try:
                    with os.scandir(current) as iterator:
                        for entry in iterator:
                            try:
                                if entry.is_file(follow_symlinks=False):
                                    _, ext = os.path.splitext(entry.name)
                                    if not ext:
                                        continue
                                    if ext.lower() not in MEDIA_SCAN_EXTS:
                                        continue
                                    try:
                                        mtime = entry.stat(follow_symlinks=False).st_mtime
                                    except FileNotFoundError:
                                        continue
                                    if youngest_mtime is None or mtime > youngest_mtime:
                                        youngest_mtime = mtime
                                    if mtime <= cutoff_epoch:
                                        return True
                                elif args.recursive and entry.is_dir(follow_symlinks=False):
                                    entry_abs = _expand_path(entry.path)
                                    if skip_abs and any(
                                        entry_abs == skip or entry_abs.startswith(f"{skip}{os.sep}")
                                        for skip in skip_abs
                                    ):
                                        continue
                                    stack.append(entry.path)
                            except FileNotFoundError:
                                continue
                except FileNotFoundError:
                    continue
            return False

        if not _has_eligible_media():
            if youngest_mtime is not None:
                cutoff_dt = datetime.fromtimestamp(cutoff_epoch)
                newest_dt = datetime.fromtimestamp(youngest_mtime)
                logger.info(
                    "Newest media under %s is %s (cutoff %s); min-age filter active",
                    src_abs,
                    newest_dt.strftime("%Y-%m-%d %H:%M:%S"),
                    cutoff_dt.strftime("%Y-%m-%d %H:%M:%S"),
                )
            logger.info(
                "Skipping exiftool processing in %s (no media at least %d day(s) old)",
                src_abs,
                min_age_days,
            )
            os.chdir(cwd)
            return False

    jobs: list[tuple[list[str], Optional[list[str]], Optional[str]]] = []

    def queue(cmd, extra_targets=None, message=None):
        job_cmd = list(cmd)
        if age_filter_args and age_filter_args[1] not in job_cmd:
            insert_at = 2 if len(job_cmd) >= 2 and job_cmd[0] == 'exiftool' else len(job_cmd)
            job_cmd[insert_at:insert_at] = age_filter_args
        job_targets = list(extra_targets) if extra_targets is not None else None
        logger.debug(
            "Queued exiftool job: cmd=%s extra_targets=%s message=%s",
            " ".join(job_cmd),
            job_targets,
            message,
        )
        jobs.append((job_cmd, job_targets, message))

    class _StayOpenUnavailable(RuntimeError):
        """Raised when the stay_open ready marker is not supported."""

    def _run_exiftool_oneshot(commands, worker_targets):
        logger.debug("Running exiftool in one-shot mode for %d job(s)", len(commands))
        ran_any_job = False
        for cmd, extra, message in commands:
            current_targets = extra if extra is not None else worker_targets
            if not current_targets:
                logger.debug("Skipping exiftool job (no targets): cmd=%s", " ".join(cmd))
                continue
            if message:
                logger.info(message)
            full_cmd = [*cmd, *current_targets]
            logger.info("Exiftool (compat): %s", " ".join(full_cmd))
            proc = subprocess.Popen(
                full_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            assert proc.stdout is not None
            for raw_line in iter(proc.stdout.readline, ''):
                line = raw_line.strip()
                if not line:
                    continue
                lower = line.lower()
                if lower.startswith('error'):
                    logger.error("Exiftool: %s", line)
                elif 'warning' in lower:
                    logger.warning("Exiftool: %s", line)
                else:
                    logger.info("Exiftool: %s", line)
            code = proc.wait()
            if code != 0:
                raise RuntimeError(
                    f"exiftool exited with {code} while running: {' '.join(full_cmd)}"
                )
            ran_any_job = True
        if ran_any_job:
            logger.info("Exiftool processing finished")

    def run_exiftool_stay_open(worker_targets):
        if not worker_targets:
            logger.debug("Exiftool stay-open session received no targets; skipping")
            return

        def _consume_output_until_ready(proc, ready_marker):
            logger.debug(
                "Waiting for exiftool ready marker '%s'", ready_marker
            )
            while True:
                line = proc.stdout.readline()
                if not line:
                    raise RuntimeError('exiftool terminated unexpectedly')
                stripped = line.strip()
                lower = stripped.lower()
                if 'option -echo3' in lower:
                    raise _StayOpenUnavailable(stripped)
                if stripped == ready_marker:
                    logger.debug("Received ready marker '%s'", ready_marker)
                    break
                if lower.startswith('error'):
                    logger.error("Exiftool: %s", stripped)
                elif 'warning' in lower:
                    logger.warning("Exiftool: %s", stripped)
                elif stripped:
                    logger.info("Exiftool: %s", stripped)

        logger.info(
            "Starting exiftool processing for %d target(s)",
            len(worker_targets),
        )
        logger.debug("Launching stay-open exiftool session")
        proc = subprocess.Popen(
            ['exiftool', '-stay_open', 'True', '-@', '-'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert proc.stdin and proc.stdout
        ready_marker = "{ready}"

        def _shutdown_process():
            try:
                if proc.stdin:
                    proc.stdin.write("-stay_open\nFalse\n")
                    proc.stdin.flush()
            except Exception:
                pass
            finally:
                try:
                    proc.communicate(timeout=5)
                except Exception:
                    proc.kill()
                    proc.communicate()

        ran_any_job = False
        try:
            logger.debug("Sending initial ready probe to exiftool")
            proc.stdin.write(f"-echo3\n{ready_marker}\n-execute\n")
            proc.stdin.flush()
            _consume_output_until_ready(proc, ready_marker)

            for cmd, extra, message in jobs:
                current_targets = extra if extra is not None else worker_targets
                if not current_targets:
                    logger.debug(
                        "Skipping exiftool job (no targets): cmd=%s",
                        " ".join(cmd),
                    )
                    continue
                if message:
                    logger.info(message)
                full_cmd = [*cmd, *current_targets]
                logger.info("Exiftool: %s", " ".join(full_cmd))
                payload = "\n".join(full_cmd[1:])
                logger.debug(
                    "Sending payload to exiftool: %s",
                    payload.replace("\n", " | "),
                )
                proc.stdin.write(
                    f"{payload}\n-echo3\n{ready_marker}\n-execute\n"
                )
                proc.stdin.flush()
                _consume_output_until_ready(proc, ready_marker)
                ran_any_job = True
        except _StayOpenUnavailable as exc:
            logger.warning(
                "Exiftool does not support -echo3 (%s); falling back to one-shot mode",
                exc,
            )
            if proc.poll() is None:
                proc.kill()
            proc.communicate()
            _run_exiftool_oneshot(jobs, worker_targets)
            return
        finally:
            if proc.poll() is None:
                _shutdown_process()

        if ran_any_job:
            logger.info("Exiftool processing finished")

    heic_desc = describe_extensions(HEIC_EXTS)
    if heic_present:
        cmd = _exiftool_cmd(
            '-FileName<${CreateDate}_$SubSecTimeOriginal ${model;}%-c.%e',
            '-d', f"{dest}/{ym}/%Y-%m-%d %H-%M-%S",
            '-ext', 'HEIC'
        )
        queue(cmd, message="HEIC processing")
    else:
        logger.info("Skipping HEIC processing (no %s media detected)", heic_desc or 'HEIC')

    screenshot_desc = describe_extensions(SCREENSHOT_EXTS)
    if screenshot_present:
        base_if = (
            r"$filename=~/screenshot/i or "
            r"$UserComment=~/screenshot/i"
        )
        first_tagging = True
        for src_tag, dst_tag in (("FileModifyDate","DateTimeOriginal"),
                                 ("DateCreated",   "DateCreated")):
            cmd = _exiftool_cmd(
                '-if', base_if,
                '-if', 'not defined $Keywords or $Keywords!~/Screenshot/i',
                '-Keywords+=Screenshot',
                f"-alldates<{src_tag}", f"-FileModifyDate<{dst_tag}",
                '-overwrite_original_in_place','-P','-fast2'
            )
            queue(cmd, message="Screenshots tagging" if first_tagging else None)
            first_tagging = False

        cmd = _exiftool_cmd(
            '-if', '$Keywords=~/screenshot/i',
            '-Filename<${CreateDate} ${Keywords}%-c.%e',
            '-d', "%Y-%m-%d %H-%M-%S"
        )
        queue(cmd, message="Screenshots rename & move")
        cmd = _exiftool_cmd(
            '-if', '$Keywords=~/screenshot/i',
            '-Directory<$CreateDate/Screenshots',
            '-d', f"{dest}/{ym}", '-Filename=%f%-c.%e'
        )
        queue(cmd)
    else:
        logger.info("Skipping screenshot flow (no %s media detected)", screenshot_desc)

    if args.whatsapp:
        whatsapp_desc = describe_extensions(WHATSAPP_IMAGE_EXTS | WHATSAPP_VIDEO_EXTS)
        if not (whatsapp_image_present or whatsapp_video_present):
            logger.info(
                "Skipping WhatsApp processing (no %s media detected)", whatsapp_desc
            )
        else:
            logger.debug("Scheduling WhatsApp processing jobs")
            whatsapp_logged = False

            def stage_message():
                nonlocal whatsapp_logged
                if whatsapp_logged:
                    return None
                whatsapp_logged = True
                return "WhatsApp processing"

            whatsapp_keywords_condition = '$Keywords=~/whatsapp/i'
            whatsapp_subject_condition = '$XMP:Subject=~/whatsapp/i'
            whatsapp_keys_keywords_condition = '$Keys:Keywords=~/whatsapp/i'

            blocks = [
                # WhatsApp Images (JPG)
                (
                    r"$filename=~/^IMG-\d{8}-WA\d{4}\.\w*/ or $jfifversion=~/1\.01/i and $EncodingProcess=~/progressive/i",
                    ['-ext', 'JPG'],
                    WHATSAPP_IMAGE_EXTS,
                    [
                        ('-Keywords+=WhatsApp', whatsapp_keywords_condition),
                        ('-XMP-dc:Subject+=WhatsApp', whatsapp_subject_condition),
                    ],
                ),
                # WhatsApp Videos (MP4 + MOV)
                (
                    r"$filename=~/^VID-\d{8}-WA\d{4}\.\w*/ or $jfifversion=~/1\.01/i and $EncodingProcess=~/progressive/i",
                    ['-ext', 'MP4', '-ext', 'MOV'],
                    WHATSAPP_VIDEO_EXTS,
                    [
                        ('-Keywords=WhatsApp', whatsapp_keywords_condition),
                        ('-Keys:Keywords=WhatsApp', whatsapp_keys_keywords_condition),
                        ('-XMP-dc:Subject=WhatsApp', whatsapp_subject_condition),
                    ],
                ),
                # WhatsApp Videos (3GP)
                (
                    r"$filename=~/^VID-\d{8}-WA\d{4}\.\w*/ or $jfifversion=~/1\.01/i and $EncodingProcess=~/progressive/i",
                    ['-ext', '3GP'],
                    {'.3gp'},
                    [
                        ('-Keywords=WhatsApp', whatsapp_keywords_condition),
                        ('-Keys:Keywords=WhatsApp', whatsapp_keys_keywords_condition),
                        ('-XMP-dc:Subject=WhatsApp', whatsapp_subject_condition),
                    ],
                ),

            ]
            for cond, exts, required, tag_updates in blocks:
                if required and not has_matching_media(present_exts, required):
                    logger.debug(
                        "Skipping WhatsApp rule %s (no %s media)",
                        cond,
                        describe_extensions(required),
                    )
                    continue
                base_cmd = _exiftool_cmd(
                    '-if', cond,
                    '-AllDates<FileModifyDate',
                    '-CreateDate<FileModifyDate',
                    '-ModifyDate<FileModifyDate',
                    '-DateTimeOriginal<FileModifyDate',
                    '-FileModifyDate<FileModifyDate',
                    '-overwrite_original_in_place','-P','-fast2', *exts
                )
                queue(base_cmd, message=stage_message())

                for tag_update, existing_condition in tag_updates:
                    cmd = _exiftool_cmd(
                        '-if', cond,
                        '-if', f'not ({existing_condition})',
                        tag_update,
                        '-overwrite_original_in_place','-P','-fast2', *exts
                    )
                    queue(cmd, message=stage_message())

            whatsapp_tag_condition = (
                '$Keywords=~/whatsapp/i or $XMP:Subject=~/whatsapp/i '
                'or $Keys:Keywords=~/whatsapp/i'
            )
            cmd = _exiftool_cmd(
                '-if', whatsapp_tag_condition,
                '-if','not defined $CreateDate',
                '-CreateDate<FileModifyDate',
                '-overwrite_original_in_place','-P','-fast2',
                '-ext+','JPG','-ext+','MP4','-ext+','3GP'
            )
            queue(cmd, message=stage_message())
            cmd = _exiftool_cmd(
                '-if', whatsapp_tag_condition,
                '-FileName<${FileModifyDate} WhatsApp%-c.%e',
                '-d', "%Y-%m-%d %H-%M-%S",
                '-ext+','MP4','-ext+','MOV','-ext+','3GP'
            )
            queue(cmd, message=stage_message())
            cmd = _exiftool_cmd(
                '-if', whatsapp_tag_condition,
                '-Directory<$FileModifyDate/WhatsApp',
                '-d', f"{dest}/{ym}", '-Filename=%f%-c.%e',
                '-ext+','MP4','-ext+','MOV','-ext+','3GP'
            )
            queue(cmd, message=stage_message())
            cmd = _exiftool_cmd(
                '-if', whatsapp_tag_condition,
                '-Directory<$FileModifyDate/WhatsApp',
                '-d', f"{dest}/{ym}", '-Filename=%f%-c.%e',
                '-ext+','JPG','-ext+','JPEG'
            )
            queue(cmd, message=stage_message())

    if dcim_present:
        dcim_ext_filters = build_exiftool_extension_filters(DCIM_EXTS - HEIC_EXTS)
        cmd = _exiftool_cmd(
            '-if', 'not defined $Keywords',
            '-if', 'not defined $Keys:Keywords',
            '-if', 'not defined $model',
            "-FileName<${FileModifyDate}%-c.%e",
            '-d', f"{dest}/{ym}/%Y-%m-%d %H-%M-%S",
            '-ext', 'mp4',
            '-ext', '3gp',
            '-ext', 'mov',
            '-ext', 'mts',
            '-ext', 'avi',
            '-ext', 'vob',
        )
        queue(cmd, message="Misc vid processing")
        dcim_common = _exiftool_cmd(
            '-if','not defined $Keywords',
            '-if','not defined $Keys:Keywords',
            '-d', f"{dest}/{ym}/%Y-%m-%d %H-%M-%S",
            *dcim_ext_filters,
            '-ee'
        )

        cmd = [
            *dcim_common,
            '-Filename<${ModifyDate}%-c.%e',
            '-Filename<${DateTimeOriginal}%-c.%e',
            '-Filename<${CreateDate}%-c.%e',
            '-Filename<${CreateDate} ${model}%-c.%e',
            '-Filename<${CreateDate}_$SubSecTimeOriginal ${model}%-c.%e',
        ]
        queue(cmd, message="DCIM processing")


        creation_date_condition = (
            'defined $CreationDate or defined $QuickTime:CreationDate '
            'or defined $QuickTime:CreateDate'
        )
        creation_date_tag = (
            '${CreationDate;QuickTime:CreationDate;QuickTime:CreateDate}'
        )
        creation_date_cmd = [
            *dcim_common,
            '-if', creation_date_condition,
            f'-Filename<{creation_date_tag} ${{model}}%-c.%e',
            f'-Filename<{creation_date_tag}_$SubSecTimeOriginal ${{model}}%-c.%e',

        ]
        queue(creation_date_cmd)
        cmd = _exiftool_cmd(
            '-if','not defined $Keywords and not defined $Keys:Keywords and not defined $model;',
            '-Directory<$FileModifyDate/diverses',
            '-d', f"{dest}/{ym}", '-Filename=%f%-c.%e'
        )
        queue(cmd)
    else:
        logger.info("Skipping DCIM & misc processing (no supported media detected)")

    result = False
    try:
        if args.dry_run:
            for cmd, extra_targets, message in jobs:
                target_list = extra_targets if extra_targets is not None else targets
                if not target_list:
                    continue
                if message:
                    logger.info("[DRY] %s", message)
                full_cmd = [*cmd, *target_list]
                logger.info("[DRY] " + " ".join(full_cmd))
            return False

        if not jobs:
            return False

        run_exiftool_stay_open(targets)
        result = True
    finally:
        os.chdir(cwd)

    return result

def archive_old(src, archive_dir, years, dry_run=False):
    """
    Move Year/Month subdirectories under `src` that are older than `years`
    into the matching structure under `archive_dir`, but only if there’s
    sufficient free space on the archive filesystem.
    """
    src_abs = _expand_path(src)
    arch_abs = _expand_path(archive_dir)

    # Only proceed if the archive mount is available
    if not os.path.ismount(arch_abs):
        logger.warning(f"Archive target {arch_abs} not mounted; skipping archive.")
        return

    logger.info(f"Archiving {years}-year-old dirs from {src_abs} → {arch_abs}")

    # Calculate cutoff
    now = datetime.now()
    cutoff_year  = now.year - years
    cutoff_month = now.month

    # Gather candidate folders to move
    to_move = []    # list of (src_path, dest_path)

    for year_entry in os.scandir(src_abs):
        if not year_entry.is_dir() or not year_entry.name.isdigit():
            continue
        y = int(year_entry.name)
        for month_entry in os.scandir(year_entry.path):
            if not month_entry.is_dir() or not month_entry.name.isdigit():
                continue
            m = int(month_entry.name)
            # check if this YYYY/MM is older than cutoff
            if (y < cutoff_year) or (y == cutoff_year and m < cutoff_month):
                src_path  = month_entry.path
                dest_path = os.path.join(arch_abs, year_entry.name, month_entry.name)
                to_move.append((src_path, dest_path))

    # Aggregate sizes of directories to move
    total_size = 0
    for src_path, _ in to_move:
        try:
            res = subprocess.run(
                ['du', '-sb', src_path],
                capture_output=True,
                text=True,
                check=True,
            )
            size = int(res.stdout.split()[0])
            total_size += size
        except Exception as e:
            logger.warning(f"Could not determine size of {src_path}: {e}")

    # Check archive free space
    stat = shutil.disk_usage(arch_abs)
    free_bytes = stat.free
    logger.info(
        f"Archive requires {total_size} B ({total_size/1024/1024:.2f} MB), "
        f"target has {free_bytes} B ({free_bytes/1024/1024:.2f} MB)"
    )
    if total_size > free_bytes:
        logger.error("Not enough space on archive destination; skipping archiving.")
        return

    # Perform the moves
    for src_path, dest_path in to_move:
        if dry_run:
            logger.info(f"[DRY] mv {src_path} → {dest_path}")
        else:
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            shutil.move(src_path, dest_path)
            tracker = get_operation_tracker()
            tracker.record_moved(Path(src_path), Path(dest_path))
            logger.info(f"Archived: {src_path} → {dest_path}")


def pipeline(args, src):
    src = os.path.expanduser(src)
    dest_root = args.move2targetdir or src
    dest = os.path.expanduser(dest_root).rstrip('/') or '/'
    src_abs = _expand_path(src)
    dest_abs = _expand_path(dest)
    dest_specified = bool(args.move2targetdir)
    dest_is_distinct = dest_specified and dest_abs != src_abs
    tracker = get_operation_tracker()
    tracker.reset()
    if args.check_year_mount and args.year_month_sort:
        check_year_mount(dest)
    check_disk_space(src, dest, args.dry_run)
    # Optionally dedupe the source first to ensure we work with a clean input set.
    if args.metadata_dedupe_source:
        metadata_dedupe(src, args.dry_run)

    # When a distinct destination is provided (or explicitly requested),
    # also dedupe source against destination by default unless disabled.
    dedupe_src_dest = args.metadata_dedupe_source_dest
    if dedupe_src_dest is None:
        dedupe_src_dest = dest_is_distinct
    if dedupe_src_dest and dest_abs != src_abs:
        metadata_dedupe_source_against_dest(src, dest, args.dry_run)
    if args.raw_dedupe:
        raw_dedupe(src, dest, args.dry_run)
    exif_changed = exif_sort(src, dest, args)
    if args.archive_dir:
        archive_old(dest if args.move2targetdir else src,
                    args.archive_dir,
                    args.archive_years,
                    args.dry_run)

    if args.metadata_dedupe_destination_final and dest_is_distinct:
        metadata_dedupe(dest, args.dry_run)

    tracker.log_summary()


def _run_pipelines(args, sources):
    if not sources:
        return
    if len(sources) > 1 and args.move2targetdir:
        dest_root = os.path.expanduser(args.move2targetdir).rstrip('/') or '/'
        check_disk_space(sources, dest_root, args.dry_run)
    logger.info(
        "Processing %d input director%s in strict sequence",
        len(sources),
        "y" if len(sources) == 1 else "ies",
    )
    for index, src in enumerate(sources, start=1):
        logger.debug("Running pipeline %d/%d for %s", index, len(sources), src)
        try:
            pipeline(args, src)
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.exception("Pipeline for %s failed: %s", src, exc)


class _WatchdogUnavailableError(RuntimeError):
    """Raised when watch mode dependencies are missing."""


def _require_watchdog() -> None:
    if Observer is None or FileSystemEventHandler is None:
        raise _WatchdogUnavailableError(
            "Watch mode requires the 'watchdog' Python package. "
            "Install it with 'pip install watchdog' or 'apt install python3-watchdog'."
        )


_WatchdogBase = FileSystemEventHandler or object


class _QueueingEventHandler(_WatchdogBase):
    """Collect file system events into a queue for later processing."""

    def __init__(self, event_queue: "queue.Queue[str]") -> None:
        super().__init__()
        self._queue = event_queue

    @staticmethod
    def _event_path(event) -> Optional[str]:
        if getattr(event, "is_directory", False):
            return None
        path = getattr(event, "dest_path", None) or getattr(event, "src_path", None)
        if not path:
            return None
        return _expand_path(path)

    def _enqueue(self, event) -> None:
        path = self._event_path(event)
        if path is None:
            return
        logger.debug("Watchdog queued event for %s", path)
        self._queue.put(path)

    def on_created(self, event) -> None:  # pragma: no cover - thin wrapper
        self._enqueue(event)

    def on_modified(self, event) -> None:  # pragma: no cover - thin wrapper
        self._enqueue(event)

    def on_moved(self, event) -> None:  # pragma: no cover - thin wrapper
        self._enqueue(event)


_WATCHDOG_REARM_DELAY = 1.0


class _WatchdogWatcher:
    """Manage a watchdog observer and expose events as a simple iterator."""

    def __init__(self, roots: Sequence[str]):
        _require_watchdog()
        normalized: list[str] = []
        seen = set()
        for raw in roots:
            path = _expand_path(raw)
            if path not in seen:
                normalized.append(path)
                seen.add(path)
        if not normalized:
            raise ValueError("At least one watch directory must be provided")
        self.roots = tuple(normalized)
        self._queue: "queue.Queue[str]" = queue.Queue()
        self._observer = Observer()
        self._handler = _QueueingEventHandler(self._queue)
        self._stop_requested = threading.Event()
        self._started = False

    def __enter__(self) -> "_WatchdogWatcher":
        for root in self.roots:
            logger.debug("Scheduling watchdog observer for %s", root)
            self._observer.schedule(self._handler, root, recursive=True)
        self._observer.start()
        self._started = True
        self._stop_requested.clear()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        self._stop_requested.set()
        if self._started:
            logger.debug("Stopping watchdog observer")
            self._observer.stop()
            try:
                self._observer.join(timeout=5)
            except RuntimeError:  # pragma: no cover - defensive
                pass
            self._started = False

    def __iter__(self):
        return self.iter_events()

    def iter_events(self):
        while not self._stop_requested.is_set():
            try:
                path = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            yield path


def _run_watch_mode(args, inputdirs: Sequence[str]) -> None:
    last_processed: dict[str, float] = {}
    rearm_delay = _WATCHDOG_REARM_DELAY

    try:
        with _WatchdogWatcher(inputdirs) as watcher:
            _run_pipelines(args, inputdirs)
            processed_time = time.monotonic()
            for root in inputdirs:
                last_processed[root] = processed_time

            for event_path in watcher:
                if not event_path:
                    logger.info("No path detected from watcher; re-arming")
                    continue

                matching = [
                    src
                    for src in inputdirs
                    if event_path == src or event_path.startswith(f"{src}{os.sep}")
                ]

                roots_to_check = list(matching) if matching else list(inputdirs)
                now = time.monotonic()
                ready = [
                    root
                    for root in roots_to_check
                    if now - last_processed.get(root, 0.0) >= rearm_delay
                ]

                if not ready:
                    logger.debug(
                        "Ignoring watchdog event for %s; matching roots recently processed",
                        event_path,
                    )
                    continue

                if matching:
                    joined_match = ", ".join(ready)
                    logger.info(
                        "Detected filesystem change under %s; sleeping %ds before processing",
                        joined_match,
                        args.grace,
                    )
                else:
                    logger.info(
                        "Detected change at %s outside configured roots; sleeping %ds before processing",
                        event_path,
                        args.grace,
                    )

                time.sleep(args.grace)
                _run_pipelines(args, ready)
                processed_time = time.monotonic()
                for root in ready:
                    last_processed[root] = processed_time
    except _WatchdogUnavailableError as exc:
        logger.error(str(exc))
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Watch mode interrupted by user")

def main():
    _inject_env_cli_args()
    args = parse_args()
    configure_xxrdfind(args.xxrdfind_threads, args.xxrdfind_scan_threads)
    set_logging_verbosity(args.debug or getattr(args, 'verbose', False))
    if args.install_deps:
        install_requirements()
        return
    for cmd in ('exiftool','xxhsum','sort','du','df'):
        check_program(cmd)
    inputdirs = [_expand_path(path) for path in args.inputdirs]

    if args.watch:
        joined = ", ".join(inputdirs)
        logger.info(f"Entering watch mode on {joined}")
        _run_watch_mode(args, inputdirs)
    else:
        _run_pipelines(args, inputdirs)

if __name__ == '__main__':
    main()
