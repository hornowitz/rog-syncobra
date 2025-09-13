#!/usr/bin/env python3
"""
xxrdfind.py - xxhash64-based duplicate finder with logging, dry-run, 
multithreading and progress display. Designed as a lightweight replacement for
rdfind for use within rog-syncobra.

Usage:
    ./xxrdfind.py [options] DIR [DIR ...]

Options:
    --delete        Remove duplicate files, keeping first instance.
    --dry-run       Show actions without deleting files.
    --threads N     Number of hashing worker threads (default: CPU count).
    --log-level L   Logging level (DEBUG, INFO, WARNING; default INFO).
    --no-progress   Disable progress bar.
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import os
import subprocess
import xxhash
from tqdm import tqdm

CHUNK_SIZE = 1 << 20  # 1 MB

logger = logging.getLogger("xxrdfind")


def file_hash(path: Path, strip_metadata: bool = False) -> tuple[Path, str | None]:
    h = xxhash.xxh64()
    try:
        if strip_metadata:
            cmd = ['exiftool', '-all=', '-o', '-', str(path)]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            assert proc.stdout is not None
            with proc.stdout as f:
                for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
                    h.update(chunk)
            if proc.wait() != 0:
                raise RuntimeError('exiftool failed')
        else:
            with path.open('rb') as f:
                for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
                    h.update(chunk)
        return path, h.hexdigest()
    except Exception as e:
        logger.warning("Hash failed for %s: %s", path, e)
        return path, None


def iter_files(paths):
    for p in paths:
        if p.is_file():
            yield p
        elif p.is_dir():
            for sub in p.rglob('*'):
                if sub.is_file():
                    yield sub


def find_duplicates(paths, delete=False, dry_run=False, threads=None, show_progress=True, strip_metadata=False):
    size_map = defaultdict(list)
    all_files = list(iter_files(paths))
    for f in all_files:
        try:
            size_map[f.stat().st_size].append(f)
        except OSError as e:
            logger.warning("Skipping %s: %s", f, e)

    candidates = [group for group in size_map.values() if len(group) > 1]
    files_to_hash = [f for group in candidates for f in group]

    hash_map = defaultdict(list)
    if threads is None or threads < 1:
        threads = os.cpu_count() or 1

    progress = tqdm(total=len(files_to_hash), unit="file", disable=not show_progress)
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for path, digest in ex.map(lambda p: file_hash(p, strip_metadata), files_to_hash):
            if digest:
                hash_map[digest].append(path)
            progress.update(1)
    progress.close()

    dup_groups = [group for group in hash_map.values() if len(group) > 1]
    for group in dup_groups:
        group_sorted = sorted(group)
        logger.info("Duplicates: %s", ", ".join(str(p) for p in group_sorted))
        if delete:
            for f in group_sorted[1:]:
                if dry_run:
                    logger.info("Would delete %s", f)
                else:
                    try:
                        f.unlink()
                        logger.info("Deleted %s", f)
                    except OSError as e:
                        logger.error("Failed to delete %s: %s", f, e)


def main():
    p = argparse.ArgumentParser(description="xxhash64 duplicate finder")
    p.add_argument('paths', nargs='+', type=Path, help="Directories/files to scan")
    p.add_argument('--delete', action='store_true', help="Delete duplicates")
    p.add_argument('--dry-run', action='store_true', help="Dry run")
    p.add_argument('--threads', type=int, default=0, help="Worker threads")
    p.add_argument('--log-level', default='INFO', help="Logging level")
    p.add_argument('--no-progress', action='store_true', help="Disable progress bar")
    p.add_argument('--strip-metadata', action='store_true',
                   help="Hash file content with metadata removed")
    args = p.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO),
                        format='%(levelname)s: %(message)s')

    find_duplicates(args.paths, delete=args.delete, dry_run=args.dry_run,
                    threads=args.threads, show_progress=not args.no_progress,
                    strip_metadata=args.strip_metadata)


if __name__ == '__main__':
    main()
