#!/usr/bin/env python3
"""
xxrdfind.py - xxhash64-based duplicate finder with persistent hashing cache,
logging, dry-run, multithreading and progress display. Designed as a
lightweight replacement for rdfind for use within rog-syncobra.

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
import json
import xxhash
from tqdm import tqdm

CHUNK_SIZE = 1 << 20  # 1 MB

logger = logging.getLogger("xxrdfind")


def _cache_file(root: Path, strip_metadata: bool) -> Path:
    suffix = '_stripped' if strip_metadata else ''
    return root / f'.xxrdfind_cache{suffix}.json'


def load_cache(root: Path, strip_metadata: bool) -> dict:
    path = _cache_file(root, strip_metadata)
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception as e:
            logger.warning("Failed to load cache %s: %s", path, e)
    return {}


def save_cache(root: Path, cache: dict, strip_metadata: bool) -> None:
    path = _cache_file(root, strip_metadata)
    try:
        path.write_text(json.dumps(cache))
    except Exception as e:
        logger.warning("Failed to save cache %s: %s", path, e)


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
            yield p, p.parent
        elif p.is_dir():
            for sub in p.rglob('*'):
                if sub.is_file():
                    yield sub, p


def find_duplicates(paths, delete=False, dry_run=False, threads=None, show_progress=True, strip_metadata=False):
    all_files = list(iter_files(paths))
    cache_map: dict[Path, dict] = {}
    for f, root in all_files:
        if root not in cache_map:
            cache_map[root] = load_cache(root, strip_metadata)

    hash_map: defaultdict[str, list[Path]] = defaultdict(list)
    if threads is None or threads < 1:
        threads = os.cpu_count() or 1

    def hash_with_cache(item: tuple[Path, Path]) -> tuple[Path, str | None]:
        path, root = item
        try:
            stat = path.stat()
        except OSError as e:
            logger.warning("Skipping %s: %s", path, e)
            return path, None
        rel = str(path.relative_to(root))
        digest: str | None = None
        cache = cache_map.get(root, {})
        entry = cache.get(rel)
        if entry and entry.get('size') == stat.st_size and entry.get('mtime') == stat.st_mtime:
            digest = entry.get('hash')
        if not digest:
            _, digest = file_hash(path, strip_metadata)
            if digest:
                cache_map.setdefault(root, {})[rel] = {
                    'size': stat.st_size,
                    'mtime': stat.st_mtime,
                    'hash': digest,
                }
        return path, digest

    progress = tqdm(total=len(all_files), unit="file", disable=not show_progress)
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for path, digest in ex.map(hash_with_cache, all_files):
            if digest:
                hash_map[digest].append(path)
            progress.update(1)
    progress.close()

    for root, cache in cache_map.items():
        save_cache(root, cache, strip_metadata)

    for digest, group in hash_map.items():
        if len(group) < 2:
            continue
        group_sorted = sorted(group)
        logger.info("Duplicates: %s", ", ".join(str(p) for p in group_sorted))
        if delete:
            for f in group_sorted[1:]:
                if dry_run:
                    logger.info("Would delete %s", f)
                else:
                    current_digest = file_hash(f, strip_metadata)[1]
                    if current_digest == digest:
                        try:
                            f.unlink()
                            logger.info("Deleted %s", f)
                        except OSError as e:
                            logger.error("Failed to delete %s: %s", f, e)
                    else:
                        logger.warning("Skipped deletion for %s: file changed since hashing", f)


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
