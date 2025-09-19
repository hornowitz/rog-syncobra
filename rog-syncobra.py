#!/usr/bin/env python3
import os
import sys
import shutil
import subprocess
import logging
import argparse
import time
from datetime import datetime

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


def scan_media_extensions(root, recursive=False, extensions=None, skip_paths=None):
    targets = normalize_extensions(extensions)
    found = set()
    stack = [root]
    while stack:
        current = stack.pop()
        current_abs = os.path.abspath(current)
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
                            entry_abs = os.path.abspath(entry.path)
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
LOGFILE = '/var/log/rog-syncobra/rog-syncobra.log'
#────────────────────────────────────────────────────────────────────────────────

# ─── Logging setup ─────────────────────────────────────────────────────────────
logdir = os.path.dirname(LOGFILE)
try:
    os.makedirs(logdir, exist_ok=True)
except Exception as e:
    print(f"ERROR: could not create log dir {logdir}: {e}", file=sys.stderr)

logger = logging.getLogger('rog-syncobra')
logger.setLevel(logging.DEBUG)

fmt = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')

sh = logging.StreamHandler(sys.stdout)
sh.setLevel(logging.INFO)
sh.setFormatter(fmt)
logger.addHandler(sh)

try:
    fh = logging.FileHandler(LOGFILE)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)
except Exception as e:
    logger.error(f"Could not open log file {LOGFILE}: {e}")

try:
    from systemd.journal import JournalHandler
    jh = JournalHandler()
    jh.setLevel(logging.INFO)
    jh.setFormatter(fmt)
    logger.addHandler(jh)
except Exception:
    pass
# ────────────────────────────────────────────────────────────────────────────────

def check_program(name):
    if not shutil.which(name):
        logger.error(f"Required program '{name}' not found in PATH.")
        sys.exit(1)


def install_requirements():
    """Install missing external program dependencies using apt."""
    packages = {
        'exiftool': 'libimage-exiftool-perl',
        'xxhsum': 'xxhash',
        'inotifywait': 'inotify-tools',
    }
    missing = [pkg for prog, pkg in packages.items() if not shutil.which(prog)]
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

def parse_args():
    p = argparse.ArgumentParser(description="rog-syncobra: sort & dedupe media")
    p.add_argument('-r','--recursive', action='store_true', help="Recurse subdirectories")
    p.add_argument('-d','--ddwometadata', action='store_true',
                   help="Raw dedupe by data (XXH64) between source & dest")
    p.add_argument('-D','--deldupi', dest='deldupi', action='store_true', default=True,
                   help="Force metadata dedupe on source (use --no-deldupi to skip)")
    p.add_argument('--no-deldupi', dest='deldupi', action='store_false',
                   help="Skip metadata dedupe on source before processing")
    p.add_argument('-X','--dedupsourceanddest', dest='dedupsourceanddest', action='store_true', default=None,
                   help="Force metadata dedupe on source and destination pre-move (auto unless disabled)")
    p.add_argument('--no-dedupsourceanddest', dest='dedupsourceanddest', action='store_false',
                   help="Skip metadata dedupe between source and destination before processing")
    p.add_argument('-y','--year-month-sort', action='store_true',
                   help="Sort into Year/Month dirs (default on)")
    p.add_argument('-Y','--check-year-mount', action='store_true',
                   help="Verify current year dir under destination is a mountpoint")
    p.add_argument('-m','--move2targetdir', metavar='DIR', default='',
                   help="Destination directory for processed files")
    p.add_argument('-w','--whatsapp', action='store_true',
                   help="Enable WhatsApp media handling")
    p.add_argument('-n','--dry-run', action='store_true',
                   help="Show actions without executing")
    p.add_argument('--debug', action='store_true',
                   help="Verbose exiftool (-v); default is quiet (-q)")
    p.add_argument('-W','--watch', action='store_true',
                   help="Watch mode: monitor for CLOSE_WRITE events")
    p.add_argument('-I','--inputdir', default=os.getcwd(),
                   help="Directory to watch/process (default cwd)")
    p.add_argument('-g','--grace', type=int, default=300,
                   help="Seconds to wait after close_write (default 300)")
    p.add_argument('--archive-dir', default='',
                   help="Directory to archive old files to (e.g. /rogaliki/obrazy/0archiv)")
    p.add_argument('--archive-years', type=int, default=2,
                   help="Move directories older than this many years (default 2)")
    p.add_argument('--skip-marker', default='.rog-syncobraignore',
                   help="Filename that marks directories to skip (set to '' to disable)")
    p.add_argument('-F','--dedup-destination-final', action='store_true',
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
    src_abs = os.path.realpath(src)
    wd_abs  = os.path.realpath(dest or src)

    if src_abs == wd_abs:
        logger.info("Source and destination identical; skipping disk space check")
        return

    logger.info(f"Checking disk space under {src_abs}")
    if wd_abs.startswith(src_abs):
        excl = f"--exclude={wd_abs}/*"
        du_cmd = ['du','--bytes',excl,'-c',src_abs]
    else:
        du_cmd = ['du','--bytes','-c',src_abs]
    out = subprocess.check_output(du_cmd).decode()
    required = int([l for l in out.splitlines() if l.endswith('total')][0].split()[0])
    usage_path = wd_abs
    while not os.path.exists(usage_path):
        parent = os.path.dirname(usage_path)
        if parent == usage_path:
            break
        usage_path = parent
    stat = shutil.disk_usage(usage_path)
    avail = stat.free
    logger.info(f"Required: {required} B ({required/1024/1024:.2f} MB), "
                f"Available: {avail} B ({avail/1024/1024:.2f} MB)")
    if not dry_run and avail < required:
        logger.error("Not enough space, aborting")
        sys.exit(1)

def check_year_mount(dest):
    """Ensure the destination's current year directory exists and is mounted."""
    year_dir = os.path.join(os.path.abspath(dest), datetime.now().strftime('%Y'))
    if not os.path.isdir(year_dir):
        logger.error(f"Year directory {year_dir} does not exist")
        sys.exit(1)
    if not os.path.ismount(year_dir):
        logger.error(f"Year directory {year_dir} is not a mountpoint")
        sys.exit(1)
    logger.info(f"Verified mountpoint for {year_dir}")

def xxrdfind_dedupe(paths, dry_run=False, strip_metadata=False, delete_within=None):
    script = os.path.join(os.path.dirname(__file__), 'xxrdfind.py')
    cmd = [sys.executable, script, '--delete', *paths]
    if strip_metadata:
        cmd.append('--strip-metadata')
    if dry_run:
        cmd.append('--dry-run')
    if delete_within:
        for root in delete_within:
            cmd.extend(['--delete-within', root])
    logger.info(f"xxrdfind dedupe: {' '.join(cmd)}")
    if dry_run:
        logger.info("Dry run: skipping xxrdfind execution")
        return
    safe_run(cmd, False)


def metadata_dedupe(path, dry_run=False):
    prefix = "[DRY] " if dry_run else ""
    logger.info(f"{prefix}Metadata dedupe via xxrdfind: {path}")
    xxrdfind_dedupe([path], dry_run=dry_run, strip_metadata=False)


def metadata_dedupe_source_against_dest(src, dest, dry_run=False):
    src_abs = os.path.abspath(src)
    dest_abs = os.path.abspath(dest)
    prefix = "[DRY] " if dry_run else ""
    logger.info(
        f"{prefix}Metadata dedupe via xxrdfind between destination ({dest_abs}) and source ({src_abs}); deleting duplicates from source"
    )
    xxrdfind_dedupe(
        [dest_abs, src_abs],
        dry_run=dry_run,
        strip_metadata=False,
        delete_within=[src_abs],
    )


def raw_dedupe(src, dest, dry_run=False, *_, **__):
    paths = []
    dest_abs = os.path.abspath(dest) if dest else None
    src_abs = os.path.abspath(src)
    if dest_abs and dest_abs != src_abs:
        paths.append(dest_abs)
    paths.append(src_abs)
    prefix = "[DRY] " if dry_run else ""
    logger.info(f"{prefix}Raw dedupe via xxrdfind: {' '.join(paths)}")
    xxrdfind_dedupe(paths, dry_run=dry_run, strip_metadata=True)

def exif_sort(src, dest, args):
    cwd = os.getcwd()
    src_abs = os.path.abspath(src)
    os.chdir(src_abs)
    vflag = '-v' if args.debug else '-q'
    ym = '%Y/%m' if args.year_month_sort else '.'
    skip_marker = args.skip_marker
    skip_rel = set()
    skip_abs = set()

    def mark_skip(rel_path):
        if rel_path in skip_rel:
            return
        skip_rel.add(rel_path)
        abs_path = os.path.abspath(os.path.join(src_abs, rel_path))
        skip_abs.add(abs_path)

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
        return

    jobs = []

    def queue(cmd, extra_targets=None):
        jobs.append((list(cmd), list(extra_targets) if extra_targets is not None else None))

    def run_worker(worker_id, worker_targets):
        if not worker_targets:
            logger.debug(f"Worker {worker_id} received no targets; skipping")
            return
        logger.info(
            "Worker %s starting with %d target(s)",
            worker_id,
            len(worker_targets),
        )
        proc = subprocess.Popen(
            ['exiftool', '-stay_open', 'True', '-@', '-'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert proc.stdin and proc.stdout
        try:
            for cmd, extra in jobs:
                current_targets = extra if extra is not None else worker_targets
                if not current_targets:
                    continue
                full_cmd = [*cmd, *current_targets]
                logger.info("[worker %s] %s", worker_id, " ".join(full_cmd))
                proc.stdin.write("\n".join(full_cmd[1:]) + "\n-execute\n")
                proc.stdin.flush()

                while True:
                    line = proc.stdout.readline()
                    if not line:
                        raise RuntimeError('exiftool terminated unexpectedly')
                    line = line.strip()
                    if line == '{ready}':
                        break
                    if line.lower().startswith('error'):
                        logger.error("[worker %s] %s", worker_id, line)
                    elif 'warning' in line.lower():
                        logger.warning("[worker %s] %s", worker_id, line)
                    elif line:
                        logger.info("[worker %s] %s", worker_id, line)
        finally:
            proc.stdin.write("-stay_open\nFalse\n")
            proc.stdin.flush()
            proc.communicate()
            logger.info("Worker %s finished", worker_id)

    heic_desc = describe_extensions(HEIC_EXTS)
    if heic_present:
        logger.info("HEIC processing")
        cmd = [
            'exiftool', vflag,
            '-FileName<${CreateDate}_$SubSecTimeOriginal ${model;}%-c.%e',
            '-d', f"{dest}/{ym}/%Y-%m-%d %H-%M-%S",
            '-ext', 'HEIC'
        ]
        queue(cmd)
    else:
        logger.info("Skipping HEIC processing (no %s media detected)", heic_desc or 'HEIC')

    screenshot_desc = describe_extensions(SCREENSHOT_EXTS)
    if screenshot_present:
        logger.info("Screenshots tagging")
        base_if = (
            r"$filename=~/screenshot/i or "
            r"$UserComment=~/screenshot/i"
        )
        for src_tag, dst_tag in (("FileModifyDate","DateTimeOriginal"),
                                 ("DateCreated",   "DateCreated")):
            cmd = [
                'exiftool', vflag,
                '-if', base_if,
                '-if', 'not defined $Keywords or $Keywords!~/Screenshot/i',
                '-Keywords+=Screenshot',
                f"-alldates<{src_tag}", f"-FileModifyDate<{dst_tag}",
                '-overwrite_original_in_place','-P','-fast2'
            ]
            queue(cmd)

        logger.info("Screenshots rename & move")
        cmd = [
            'exiftool', vflag,
            '-if', '$Keywords=~/screenshot/i',
            '-Filename<${CreateDate} ${Keywords}%-c.%e',
            '-d', "%Y-%m-%d %H-%M-%S"
        ]
        queue(cmd)
        cmd = [
            'exiftool', vflag,
            '-if', '$Keywords=~/screenshot/i',
            '-Directory<$CreateDate/Screenshots',
            '-d', f"{dest}/{ym}", '-Filename=%f%-c.%e'
        ]
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
            logger.info("WhatsApp processing")
            blocks = [
                # WhatsApp Images (JPG)
                (
                    r"$filename=~/^IMG-\d{8}-WA\d{4}\.\w*/ or $jfifversion=~/1\.01/i and $EncodingProcess=~/progressive/i",
                    ['-ext', 'JPG'],
                    WHATSAPP_IMAGE_EXTS,
                ),
                # WhatsApp Videos (MP4 + MOV)
                (
                    r"$filename=~/^VID-\d{8}-WA\d{4}\.\w*/ or $jfifversion=~/1\.01/i and $EncodingProcess=~/progressive/i",
                    ['-ext', 'MP4', '-ext', 'MOV'],
                    WHATSAPP_VIDEO_EXTS,
                ),
                # WhatsApp Videos (3GP)
                (
                    r"$filename=~/^VID-\d{8}-WA\d{4}\.\w*/ or $jfifversion=~/1\.01/i and $EncodingProcess=~/progressive/i",
                    ['-ext', '3GP'],
                    {'.3gp'},
                ),

            ]
            for cond, exts, required in blocks:
                if required and not has_matching_media(present_exts, required):
                    logger.debug(
                        "Skipping WhatsApp rule %s (no %s media)",
                        cond,
                        describe_extensions(required),
                    )
                    continue
                cmd = [
                    'exiftool', vflag,
                    '-if', cond,
                    '-if', 'not defined $Keywords or $Keywords!~/WhatsApp/i',
                    '-Keywords+=WhatsApp',
                    '-alldates<20${filename}','-FileModifyDate<20${filename}',
                    '-overwrite_original_in_place','-P','-fast2', *exts
                ]
                queue(cmd)

            cmd = [
                'exiftool', vflag,
                '-if','$Keywords=~/whatsapp/i',
                '-if','not defined $CreateDate',
                '-CreateDate<FileModifyDate',
                '-overwrite_original_in_place','-P','-fast2',
                '-ext+','JPG','-ext+','MP4','-ext+','3GP'
            ]
            queue(cmd)
            cmd = [
                'exiftool', vflag,
                '-if','$Keywords=~/whatsapp/i',
                '-FileName<${CreateDate} ${Keywords}%-c.%e',
                '-d', "%Y-%m-%d %H-%M-%S",
                '-ext+','JPG','-ext+','MP4','-ext+','3GP'
            ]
            queue(cmd)
            cmd = [
                'exiftool', vflag,
                '-if','$Keywords=~/whatsapp/i',
                '-Directory<$CreateDate/WhatsApp',
                '-d', f"{dest}/{ym}", '-Filename=%f%-c.%e'
            ]
            queue(cmd)

    if dcim_present:
        logger.info("Misc vid processing")
        cmd = [
            'exiftool', vflag,
            '-if', 'not defined $Keywords',
            '-if', 'not defined $model',
            "-FileName<${FileModifyDate}%-c.%e",
            '-d', f"{dest}/{ym}/%Y-%m-%d %H-%M-%S",
            '-ext', 'mp4',
            '-ext', '3gp',
            '-ext', 'mov',
            '-ext', 'mts',
            '-ext', 'avi',
            '-ext', 'vob',
        ]
        queue(cmd)
        logger.info("DCIM processing")
        cmd = [
            'exiftool', vflag,
            '-if','not defined $Keywords',
            '-Filename<${ModifyDate}%-c.%e',
            '-Filename<${DateTimeOriginal}%-c.%e',
            '-Filename<${CreateDate}%-c.%e',
            '-Filename<${CreateDate} ${model}%-c.%e',
            '-Filename<${CreationDate} ${model}%-c.%e',
            '-Filename<${CreateDate}_$SubSecTimeOriginal ${model}%-c.%e',
            '-Filename<${CreationDate}_$SubSecTimeOriginal ${model}%-c.%e',
            '-d', f"{dest}/{ym}/%Y-%m-%d %H-%M-%S",
            '-ext+','mpg','-ext+','MTS','-ext+','VOB','-ext+','3GP','-ext+','AVI',
            '-ee'
        ]
        queue(cmd)
        cmd = [
            'exiftool', vflag,
            '-if','not defined $Keywords and not defined $model;',
            '-Directory<$FileModifyDate/diverses',
            '-d', f"{dest}/{ym}", '-Filename=%f%-c.%e'
        ]
        queue(cmd)
    else:
        logger.info("Skipping DCIM & misc processing (no supported media detected)")

    try:
        if args.dry_run:
            for cmd, extra_targets in jobs:
                target_list = extra_targets if extra_targets is not None else targets
                if not target_list:
                    continue
                full_cmd = [*cmd, *target_list]
                logger.info("[DRY] " + " ".join(full_cmd))
            return

        if not jobs:
            return

        run_worker(1, targets)
    finally:
        os.chdir(cwd)

def archive_old(src, archive_dir, years, dry_run=False):
    """
    Move Year/Month subdirectories under `src` that are older than `years`
    into the matching structure under `archive_dir`, but only if there’s
    sufficient free space on the archive filesystem.
    """
    src_abs  = os.path.abspath(src)
    arch_abs = os.path.abspath(archive_dir)

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
            logger.info(f"Archived: {src_path} → {dest_path}")


def pipeline(args):
    src = args.inputdir
    dest = (args.move2targetdir or src).rstrip('/')
    src_abs = os.path.abspath(src)
    dest_abs = os.path.abspath(dest)
    dest_specified = bool(args.move2targetdir)
    dest_is_distinct = dest_specified and dest_abs != src_abs
    if args.check_year_mount and args.year_month_sort:
        check_year_mount(dest)
    check_disk_space(src, dest, args.dry_run)
    # Optionally dedupe the source first to ensure we work with a clean input set.
    if args.deldupi:
        metadata_dedupe(src, args.dry_run)

    # When a distinct destination is provided (or explicitly requested),
    # also dedupe source against destination by default unless disabled.
    dedupe_src_dest = args.dedupsourceanddest
    if dedupe_src_dest is None:
        dedupe_src_dest = dest_is_distinct
    if dedupe_src_dest and dest_abs != src_abs:
        metadata_dedupe_source_against_dest(src, dest, args.dry_run)
    if args.ddwometadata:
        raw_dedupe(src, dest, args.dry_run)
    exif_sort(src, dest, args)
    if args.archive_dir:
        archive_old(dest if args.move2targetdir else src,
                    args.archive_dir,
                    args.archive_years,
                    args.dry_run)

    if args.dedup_destination_final and dest_is_distinct:
        metadata_dedupe(dest, args.dry_run)

def main():
    args = parse_args()
    if args.install_deps:
        install_requirements()
        return
    for cmd in ('exiftool','xxhsum','sort','du','df'):
        check_program(cmd)
    if args.watch:
        check_program('inotifywait')
        pipeline(args)
        logger.info(f"Entering watch mode on {args.inputdir}")
        while True:
            subprocess.run(['inotifywait','-e','close_write','-r', args.inputdir])
            logger.info(f"Sleeping {args.grace}s before processing")
            time.sleep(args.grace)
            pipeline(args)
    else:
        pipeline(args)

if __name__ == '__main__':
    main()
