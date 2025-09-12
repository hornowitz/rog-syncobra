#!/usr/bin/env python3
import os
import sys
import shutil
import subprocess
import tempfile
import shlex
import logging
import argparse
import time
import json
from datetime import datetime

# ────────────────────────────────────────────────────────────────────────────────
# Configuration
LOGFILE = '/var/log/rog-syncobra/rog-syncobra.log'
CACHE_FILE = '.raw_dedupe_cache.json'
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
        'rdfind': 'rdfind',
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
    p.add_argument('-D','--deldupi', action='store_true',
                   help="Metadata dedupe by rdfind on source")
    p.add_argument('-X','--deldupidest', action='store_true',
                   help="Metadata dedupe by rdfind on destination")
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

def metadata_dedupe(path, dry_run=False):
    cmd = ['rdfind','-deleteduplicates','true', path]
    logger.info(f"Metadata dedupe: {' '.join(cmd)}")
    safe_run(cmd, dry_run)

def load_cache(root):
    """Load dedupe cache from ROOT directory."""
    path = os.path.join(root, CACHE_FILE)
    try:
        with open(path, 'r') as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}

def save_cache(root, cache):
    """Write dedupe cache back to ROOT directory."""
    path = os.path.join(root, CACHE_FILE)
    try:
        pruned = {p: meta for p, meta in cache.items() if os.path.exists(p)}
        with open(path, 'w') as f:
            json.dump(pruned, f)
    except Exception as e:
        logger.warning(f"Failed to write cache {path}: {e}")

def raw_dedupe(src, dest, dry_run=False, recursive=False):
    src_abs  = os.path.abspath(src)
    dest_abs = os.path.abspath(dest) if dest else src_abs
    logger.info(f"Raw dedupe: {src_abs} ↔ {dest_abs}")

    src_cache = load_cache(src_abs)
    dest_cache = src_cache if dest_abs == src_abs else load_cache(dest_abs)

    if dest and dest_abs != src_abs:
        doppelt = os.path.join(dest_abs, 'doppelt')
    else:
        doppelt = os.path.join(src_abs,  'doppelt')
    os.makedirs(doppelt, exist_ok=True)

    MEDIA_EXTS = {'.jpg','.jpeg','.png','.heic',
                  '.mp4','.mov','.3gp','.mts','.vob','.avi','.mpg'}

    tmp_src  = tempfile.NamedTemporaryFile('w+', delete=False)
    tmp_dest = tempfile.NamedTemporaryFile('w+', delete=False)
    sorted_src = sorted_dest = None

    try:
        # hash source
        for root, dirs, files in os.walk(src_abs):
            if not recursive: dirs.clear()
            for fn in files:
                if os.path.splitext(fn)[1].lower() not in MEDIA_EXTS:
                    continue
                p = os.path.join(root, fn)
                st = os.stat(p)
                meta = src_cache.get(p)
                if meta and meta.get('mtime') == st.st_mtime and meta.get('size') == st.st_size:
                    h = meta.get('hash')
                else:
                    cmd = f"exiftool -all= -o - {shlex.quote(p)} 2>/dev/null | xxhsum -H64"
                    try:
                        out = subprocess.check_output(cmd, shell=True)
                        h = out.decode().split()[0]
                    except subprocess.CalledProcessError:
                        continue
                    src_cache[p] = {'mtime': st.st_mtime, 'size': st.st_size, 'hash': h}
                tmp_src.write(f"{h}\t{p}\n")

        # hash dest
        for root, dirs, files in os.walk(dest_abs):
            if not recursive: dirs.clear()
            for fn in files:
                if os.path.splitext(fn)[1].lower() not in MEDIA_EXTS:
                    continue
                p = os.path.join(root, fn)
                st = os.stat(p)
                meta = dest_cache.get(p)
                if meta and meta.get('mtime') == st.st_mtime and meta.get('size') == st.st_size:
                    h = meta.get('hash')
                else:
                    cmd = f"exiftool -all= -o - {shlex.quote(p)} 2>/dev/null | xxhsum -H64"
                    try:
                        out = subprocess.check_output(cmd, shell=True)
                        h = out.decode().split()[0]
                    except subprocess.CalledProcessError:
                        continue
                    dest_cache[p] = {'mtime': st.st_mtime, 'size': st.st_size, 'hash': h}
                tmp_dest.write(f"{h}\t{p}\n")

        tmp_src.flush(); tmp_dest.flush()
        tmp_src.close(); tmp_dest.close()

        # sort on disk
        sorted_src  = tmp_src.name  + '.s'
        sorted_dest = tmp_dest.name + '.s'
        subprocess.run(['sort','-k1,1', tmp_src.name, '-o', sorted_src],  check=True)
        subprocess.run(['sort','-k1,1', tmp_dest.name,'-o',  sorted_dest], check=True)

        # merge‐join and move
        freed = 0
        with open(sorted_src) as fsrc, open(sorted_dest) as fdst:
            ls = fsrc.readline()
            ld = fdst.readline()
            while ls and ld:
                h_src, p_src = ls.rstrip().split('\t',1)
                h_dst, _     = ld.rstrip().split('\t',1)
                if h_src < h_dst:
                    ls = fsrc.readline()
                elif h_src > h_dst:
                    ld = fdst.readline()
                else:
                    while ls and ls.startswith(h_src):
                        _, p = ls.rstrip().split('\t',1)
                        target = os.path.join(doppelt, os.path.basename(p))
                        if dry_run:
                            logger.info(f"[DRY] mv {p} → {target}")
                        else:
                            size = os.path.getsize(p)
                            freed += size
                            shutil.move(p, target)
                            logger.info(f"Moved duplicate: {p}")
                        ls = fsrc.readline()
                    while ld and ld.startswith(h_dst):
                        ld = fdst.readline()
        logger.info(f"{freed} bytes freed")

    finally:
        save_cache(src_abs, src_cache)
        if dest_cache is not src_cache:
            save_cache(dest_abs, dest_cache)
        for fh in (tmp_src, tmp_dest):
            try:
                fh.close()
            except Exception:
                pass
        for fn in (tmp_src.name, tmp_dest.name, sorted_src, sorted_dest):
            if fn and os.path.exists(fn):
                os.unlink(fn)

def exif_sort(src, dest, args):
    cwd = os.getcwd()
    os.chdir(src)
    vflag = '-v' if args.debug else '-q'
    recur = ['-r'] if args.recursive else []
    ym = '%Y/%m' if args.year_month_sort else '.'

    def run(cmd):
        safe_run(cmd, args.dry_run)

    # 1) HEIC
    logger.info("HEIC processing")
    cmd = [
        'exiftool', vflag, *recur,
        '-FileName<${CreateDate}_$SubSecTimeOriginal ${model;}%-c.%e',
        '-d', f"{dest}/{ym}/%Y-%m-%d %H-%M-%S",
        '-ext', 'HEIC', '.'
    ]
    run(cmd)

    # 2) Screenshots tagging & date-fix
    logger.info("Screenshots tagging")
    base_if = (
        r"$filename=~/screenshot/i or "
        r"$ProfileCopyright=~/google inc\. 2016/i and "
        r"$jfifversion=~/1\.01/i or "
        r"$UserComment=~/screenshot/i"
    )
    for src_tag, dst_tag in (("FileModifyDate","DateTimeOriginal"),
                             ("DateCreated",   "DateCreated")):
        cmd = [
            'exiftool', vflag, *recur,
            '-if', base_if,
            '-if', 'not defined $Keywords or $Keywords!~/Screenshot/i',
            '-Keywords+=Screenshot',
            f"-alldates<{src_tag}", f"-FileModifyDate<{dst_tag}",
            '-overwrite_original_in_place','-P','-fast2','.'
        ]
        run(cmd)

    # 3) Rename & move screenshots
    logger.info("Screenshots rename & move")
    cmd = [
        'exiftool', vflag, *recur,
        '-if', '$Keywords=~/screenshot/i',
        '-Filename<${CreateDate} ${Keywords}%-c.%e',
        '-d', "%Y-%m-%d %H-%M-%S", '.'
    ]
    run(cmd)
    cmd = [
        'exiftool', vflag, *recur,
        '-if', '$Keywords=~/screenshot/i',
        '-Directory<$CreateDate/Screenshots',
        '-d', f"{dest}/{ym}", '-Filename=%f%-c.%e', '.'
    ]
    run(cmd)

    # 4) WhatsApp
    if args.whatsapp:
        logger.info("WhatsApp processing")
        blocks = [
            (r"$filename=~/^IMG-.../ and ...", ['-ext','JPG']),
            (r"$jfifversion=~/1\.01/i and ...", ['-ext','JPG']),
            (r"$filename=~/^VID-.../", ['-ext','MP4','-ext','MOV']),
            (r"$filename=~/^VID-.../", ['-ext','3GP']),
        ]
        for cond, exts in blocks:
            cmd = [
                'exiftool', vflag, *recur,
                '-if', cond,
                '-if', 'not defined $Keywords or $Keywords!~/WhatsApp/i',
                '-Keywords+=WhatsApp',
                '-alldates<20${filename}','-FileModifyDate<20${filename}',
                '-overwrite_original_in_place','-P','-fast2', *exts, '.'
            ]
            run(cmd)
        # rename & move WhatsApp
        cmd = [
            'exiftool', vflag, *recur,
            '-if','$Keywords=~/whatsapp/i',
            '-FileName<${CreateDate} ${Keywords}%-c.%e',
            '-d', "%Y-%m-%d %H-%M-%S",
            '-ext+','JPG','-ext+','MP4','-ext+','3GP','.'
        ]
        run(cmd)
        cmd = [
            'exiftool', vflag, *recur,
            '-if','$Keywords=~/whatsapp/i',
            '-Directory<$CreateDate/WhatsApp',
            '-d', f"{dest}/{ym}", '-Filename=%f%-c.%e'
        ]
        run(cmd)

    # 5) AndroidModel-specific timestamp fixes
    logger.info("AndroidModel A059P timestamp fix")
    cmd = [
        'exiftool', vflag, *recur,
        '-if', "$AndroidModel eq 'A059P'",
        '-alldates<FileModifyDate',
        '-overwrite_original_in_place','-P','-fast2',
        '-ext+','MP4','-ext+','MOV','-ext+','MTS','-ext+','MPG',
        '-ext+','VOB','-ext+','3GP','-ext+','AVI','.'
    ]
    run(cmd)

    # 6) Main DCIM & misc
    logger.info("DCIM & misc processing")
    cmd = [
        'exiftool', vflag, *recur,
        '-if','not defined $Keywords',
        '-Filename<${ModifyDate}%-c.%e',
        '-Filename<${DateTimeOriginal}%-c.%e',
        '-Filename<${CreateDate}%-c.%e',
        '-Filename<${CreateDate} ${model;}%-c.%e',
        '-Filename<${CreationDate} ${model;}%-c.%e',
        '-Filename<${CreateDate}_$SubSecTimeOriginal ${model;}%-c.%e',
        '-Filename<${CreationDate}_$SubSecTimeOriginal ${model;}%-c.%e',
        '-d', f"{dest}/{ym}/%Y-%m-%d %H-%M-%S",
        '-ext+','MPG','-ext+','MTS','-ext+','VOB','-ext+','3GP','-ext+','AVI',
        '-ee','.'
    ]
    run(cmd)
    cmd = [
        'exiftool', vflag, *recur,
        '-if','not defined $Keywords and not defined $model;',
        '-Directory<$FileModifyDate/diverses',
        '-d', f"{dest}/{ym}", '-Filename=%f%-c.%e','.']
    run(cmd)

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

    # Gather all candidate folders and accumulate their total size
    to_move = []    # list of (src_path, dest_path)
    total_size = 0

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
                # sum sizes of all files in this folder
                for root, _, files in os.walk(src_path):
                    for fn in files:
                        fp = os.path.join(root, fn)
                        try:
                            total_size += os.path.getsize(fp)
                        except OSError:
                            pass
                to_move.append((src_path, dest_path))

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
    if args.check_year_mount and args.year_month_sort:
        check_year_mount(dest)
    check_disk_space(src, dest, args.dry_run)
    if args.deldupidest:
        metadata_dedupe(dest, args.dry_run)
    if args.deldupi:
        metadata_dedupe(src, args.dry_run)
    if args.ddwometadata:
        raw_dedupe(src, dest, args.dry_run, args.recursive)
    exif_sort(src, dest, args)
    if args.archive_dir:
        archive_old(dest if args.move2targetdir else src,
                    args.archive_dir,
                    args.archive_years,
                    args.dry_run)

def main():
    args = parse_args()
    if args.install_deps:
        install_requirements()
        return
    for cmd in ('exiftool','xxhsum','rdfind','sort','du','df'):
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
