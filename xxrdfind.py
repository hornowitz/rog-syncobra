#!/usr/bin/env python3
"""
xxrdfind.py - xxhash64-based duplicate finder with persistent hashing cache,
logging, dry-run, multithreading and progress display. Designed as a
lightweight replacement for rdfind for use within rog-syncobra.

Usage:
    ./xxrdfind.py [options] DIR [DIR ...]

Options:
    -d, --delete          Remove duplicate files, keeping first instance.
    -n, --dry-run         Show actions without deleting files.
    -t, --threads N       Number of hashing worker threads (default: CPU count).
    -l, --log-level L     Logging level (DEBUG, INFO, WARNING; default INFO).
    -p, --no-progress     Disable progress bar.
    -s, --strip-metadata  Hash file content with metadata removed.
    -r, --recursive       Recurse into subdirectories (use --no-recursive to disable).
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
import hashlib
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


def file_hash(path: Path, strip_metadata: bool = False, algorithm: str = 'xxh64') -> tuple[Path, str | None]:
    if algorithm == 'xxh64':
        h = xxhash.xxh64()
    elif algorithm == 'blake2b':
        h = hashlib.blake2b(digest_size=32)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
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


def iter_files(paths, recursive: bool = True):
    for p in paths:
        if p.is_file():
            yield p, p.parent
        elif p.is_dir():
            iterator = p.rglob('*') if recursive else p.iterdir()
            for sub in iterator:
                if sub.is_file():
                    yield sub, p


def find_duplicates(paths, delete=False, dry_run=False, threads=None, show_progress=True,
                    strip_metadata=False, recursive: bool = True):
    all_files = list(iter_files(paths, recursive))
    cache_map: dict[Path, dict] = {}
    root_map: dict[Path, Path] = {}
    for f, root in all_files:
        root_map[f] = root
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
            digest = entry.get('xxh64') or entry.get('hash')
        if not digest:
            _, digest = file_hash(path, strip_metadata, 'xxh64')
            if digest:
                cache_map.setdefault(root, {})[rel] = {
                    'size': stat.st_size,
                    'mtime': stat.st_mtime,
                    'xxh64': digest,
                    **({'blake2b': entry['blake2b']} if entry and 'blake2b' in entry else {}),
                }
        else:
            if entry and 'xxh64' not in entry:
                entry['xxh64'] = digest
        return path, digest

    progress = tqdm(total=len(all_files), unit="file", disable=not show_progress)
    try:
        with ThreadPoolExecutor(max_workers=threads) as ex:
            it = ex.map(hash_with_cache, all_files)
            try:
                for path, digest in it:
                    if digest:
                        hash_map[digest].append(path)
                    progress.update(1)
            except KeyboardInterrupt:
                logger.warning("Interrupted during hashing; processing partial results")
                ex.shutdown(cancel_futures=True)
    finally:
        progress.close()

    try:
        for digest, group in hash_map.items():
            if len(group) < 2:
                continue
            strong_map: defaultdict[str, list[Path]] = defaultdict(list)
            for f in group:
                root = root_map[f]
                try:
                    stat = f.stat()
                except OSError as e:
                    logger.warning("Skipping %s: %s", f, e)
                    continue
                rel = str(f.relative_to(root))
                cache = cache_map.get(root, {})
                entry = cache.get(rel)
                strong_digest: str | None = None
                if entry and entry.get('size') == stat.st_size and entry.get('mtime') == stat.st_mtime:
                    strong_digest = entry.get('blake2b')
                if not strong_digest:
                    _, strong_digest = file_hash(f, strip_metadata, 'blake2b')
                    if strong_digest:
                        cache.setdefault(rel, {
                            'size': stat.st_size,
                            'mtime': stat.st_mtime,
                            'xxh64': entry.get('xxh64') or entry.get('hash') if entry else None,
                        })['blake2b'] = strong_digest
                if strong_digest:
                    strong_map[strong_digest].append(f)
            for strong_digest, files in strong_map.items():
                if len(files) < 2:
                    continue
                group_sorted = sorted(files)
                logger.info("Duplicates: %s", ", ".join(str(p) for p in group_sorted))
                if delete:
                    for f in group_sorted[1:]:
                        if dry_run:
                            logger.info("Would delete %s", f)
                        else:
                            current_digest = file_hash(f, strip_metadata, 'blake2b')[1]
                            if current_digest == strong_digest:
                                try:
                                    f.unlink()
                                    logger.info("Deleted %s", f)
                                except OSError as e:
                                    logger.error("Failed to delete %s: %s", f, e)
                            else:
                                logger.warning("Skipped deletion for %s: file changed since hashing", f)
    except KeyboardInterrupt:
        logger.warning("Interrupted during duplicate verification; saving cache")
    finally:
        for root, cache in cache_map.items():
            save_cache(root, cache, strip_metadata)


def main():
    p = argparse.ArgumentParser(description="xxhash64 duplicate finder")
    p.add_argument('paths', nargs='+', type=Path, help="Directories/files to scan")
    p.add_argument('-d', '--delete', action='store_true', help="Delete duplicates")
    p.add_argument('-n', '--dry-run', action='store_true', help="Dry run")
    p.add_argument('-t', '--threads', type=int, default=0, help="Worker threads")
    p.add_argument('-l', '--log-level', default='INFO', help="Logging level")
    p.add_argument('-p', '--no-progress', action='store_true', help="Disable progress bar")
    p.add_argument('-s', '--strip-metadata', action='store_true',
                   help="Hash file content with metadata removed")
    p.add_argument('-r', '--recursive', action=argparse.BooleanOptionalAction, default=True,
                   help="Recurse into subdirectories (use --no-recursive to disable)")
    args = p.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO),
                        format='%(levelname)s: %(message)s')

    try:
        find_duplicates(args.paths, delete=args.delete, dry_run=args.dry_run,
                        threads=args.threads, show_progress=not args.no_progress,
                        strip_metadata=args.strip_metadata, recursive=args.recursive)
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")


if __name__ == '__main__':
    main()
