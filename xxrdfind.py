#!/usr/bin/env python3
"""
xxrdfind.py - xxhash64-based duplicate finder with optional persistent hashing
cache, logging, dry-run, multithreading and progress display. Designed as a
lightweight replacement for rdfind for use within rog-syncobra.

Usage:
    ./xxrdfind.py [options] DIR [DIR ...]

Options:
    -d, --delete             Remove duplicate files, keeping first instance (default: keep files).
    -n, --dry-run            Show actions without deleting files (default: false).
    -t, --threads N          Number of hashing worker threads (default: CPU count).
    -l, --log-level L        Logging level (DEBUG, INFO, WARNING; default INFO).
    -p, --no-progress        Disable progress bar (default: show progress).
    -s, --strip-metadata     Hash file content with metadata removed (default: include metadata).
    -r, --recursive          Recurse into subdirectories (default: enabled; use --no-recursive to disable).
    -c, --cache              Use persistent hash cache (default: enabled; use --no-cache to disable).
        --delete-within DIR  Restrict deletions to files under DIR (may be provided multiple times).
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import os
import subprocess
import json
import hashlib
import xxhash
from tqdm import tqdm

CHUNK_SIZE = 1 << 20  # 1 MB

UNSUPPORTED_EXIFTOOL_VIDEO_EXTENSIONS = {
    ".mkv",
    ".avi",
    ".wmv",
    ".mts",
    ".m2ts",
    ".vob",
}

logger = logging.getLogger("xxrdfind")


@dataclass
class DuplicateSummary:
    deleted: list[Path] = field(default_factory=list)
    would_delete: list[Path] = field(default_factory=list)


def _format_paths(paths: list[Path]) -> str:
    return ", ".join(str(p) for p in paths)


def _cache_file(root: Path, strip_metadata: bool) -> Path:
    suffix = '_stripped' if strip_metadata else ''
    return root / f'.xxrdfind_cache{suffix}.json'


def load_cache(root: Path, strip_metadata: bool) -> dict:
    path = _cache_file(root, strip_metadata)
    if path.exists():
        try:
            data = json.loads(path.read_text())
            logger.debug("Loaded cache %s (%d entries)", path, len(data))
            return data
        except Exception as e:
            logger.warning("Failed to load cache %s: %s", path, e)
    else:
        logger.debug("No cache file %s", path)
    return {}


def save_cache(root: Path, cache: dict, strip_metadata: bool) -> None:
    path = _cache_file(root, strip_metadata)
    try:
        path.write_text(json.dumps(cache))
        logger.debug("Saved cache %s (%d entries)", path, len(cache))
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
            suffix = path.suffix.lower()
            if suffix in UNSUPPORTED_EXIFTOOL_VIDEO_EXTENSIONS:
                logger.info("skipping raw dedupe for %s", path)
                return path, None
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
        digest = h.hexdigest()
        logger.debug("Hashed %s with %s -> %s", path, algorithm, digest)
        return path, digest
    except Exception as e:
        logger.warning("Hash failed for %s: %s", path, e)
        return path, None


def iter_files(paths, recursive: bool = True):
    for p in paths:
        logger.debug("Scanning %s", p)
        if p.is_file():
            logger.debug("Found file %s", p)
            yield p, p.parent
        elif p.is_dir():
            iterator = p.rglob('*') if recursive else p.iterdir()
            for sub in iterator:
                if sub.is_file():
                    logger.debug("Found file %s", sub)
                    yield sub, p


def find_duplicates(paths, delete=False, dry_run=False, threads=None, show_progress=True,
                    strip_metadata=False, recursive: bool = True, use_cache: bool = True,
                    delete_roots: list[Path] | None = None,
                    summary: DuplicateSummary | None = None) -> DuplicateSummary:
    summary = summary or DuplicateSummary()
    raw_files = list(iter_files(paths, recursive))
    logger.debug("Found %d files to process", len(raw_files))
    cache_map: dict[Path, dict] = {}
    root_map: dict[Path, Path] = {}
    all_files: list[tuple[Path, Path]] = []
    cache_root_cache: dict[Path, Path] = {}

    delete_roots_resolved: set[Path] | None
    if delete_roots:
        delete_roots_resolved = {p.resolve() for p in delete_roots}
    else:
        delete_roots_resolved = None

    def is_within(path: Path, root: Path) -> bool:
        try:
            path.resolve().relative_to(root)
            return True
        except ValueError:
            return False

    def cache_root_for(path: Path, base: Path) -> Path:
        dir_path = path.parent
        if dir_path in cache_root_cache:
            return cache_root_cache[dir_path]
        current = dir_path
        while True:
            if _cache_file(current, strip_metadata).exists():
                cache_root_cache[dir_path] = current
                return current
            if current == base:
                cache_root_cache[dir_path] = base
                return base
            current = current.parent

    seen_paths: set[Path] = set()

    for f, root in raw_files:
        resolved = f.resolve()
        if resolved in seen_paths:
            logger.debug("Skipping already queued path %s", f)
            continue
        seen_paths.add(resolved)
        root_cache = cache_root_for(f, root) if use_cache else root
        root_map[f] = root_cache
        if use_cache and root_cache not in cache_map:
            cache_map[root_cache] = load_cache(root_cache, strip_metadata)
        all_files.append((f, root_cache))

    hash_map: defaultdict[str, list[Path]] = defaultdict(list)
    if threads is None or threads < 1:
        threads = os.cpu_count() or 1
    logger.debug("Using %d worker threads", threads)

    def hash_with_cache(item: tuple[Path, Path]) -> tuple[Path, str | None]:
        path, root = item
        try:
            stat = path.stat()
        except OSError as e:
            logger.warning("Skipping %s: %s", path, e)
            return path, None
        rel = str(path.relative_to(root))
        digest: str | None = None
        entry = None
        if use_cache:
            cache = cache_map.get(root, {})
            entry = cache.get(rel)
            if entry and entry.get('size') == stat.st_size and entry.get('mtime') == stat.st_mtime:
                digest = entry.get('xxh64') or entry.get('hash')
                if digest:
                    logger.debug("Cache hit for %s", path)
        if not digest:
            logger.debug("Hashing %s", path)
            _, digest = file_hash(path, strip_metadata, 'xxh64')
            if digest and use_cache:
                cache_map.setdefault(root, {})[rel] = {
                    'size': stat.st_size,
                    'mtime': stat.st_mtime,
                    'xxh64': digest,
                    **({'blake2b': entry['blake2b']} if entry and 'blake2b' in entry else {}),
                }
        elif use_cache and entry and 'xxh64' not in entry:
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
                cache = cache_map.get(root, {}) if use_cache else {}
                entry = cache.get(rel) if use_cache else None
                strong_digest: str | None = None
                if use_cache and entry and entry.get('size') == stat.st_size and entry.get('mtime') == stat.st_mtime:
                    strong_digest = entry.get('blake2b')
                if not strong_digest:
                    _, strong_digest = file_hash(f, strip_metadata, 'blake2b')
                    if strong_digest and use_cache:
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
                    if delete_roots_resolved is None:
                        candidates = group_sorted[1:]
                    else:
                        delete_candidates = []
                        keepers = []
                        for candidate in group_sorted:
                            if any(is_within(candidate, root) for root in delete_roots_resolved):
                                delete_candidates.append(candidate)
                            else:
                                keepers.append(candidate)
                        if not keepers and delete_candidates:
                            delete_candidates = delete_candidates[1:]
                        candidates = delete_candidates
                    for f in candidates:
                        if dry_run:
                            logger.info("Would delete %s", f)
                            summary.would_delete.append(f)
                        else:
                            current_digest = file_hash(f, strip_metadata, 'blake2b')[1]
                            if current_digest == strong_digest:
                                try:
                                    f.unlink()
                                    logger.info("Deleted %s", f)
                                    summary.deleted.append(f)
                                except FileNotFoundError:
                                    logger.warning("Skipped deletion for %s: file missing", f)
                                except OSError as e:
                                    logger.error("Failed to delete %s: %s", f, e)
                            else:
                                logger.warning("Skipped deletion for %s: file changed since hashing", f)
    except KeyboardInterrupt:
        logger.warning("Interrupted during duplicate verification; saving cache")
    finally:
        if use_cache:
            for root, cache in cache_map.items():
                save_cache(root, cache, strip_metadata)

    return summary


def main():
    p = argparse.ArgumentParser(
        description="xxhash64 duplicate finder",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument('paths', nargs='+', type=Path, help="Directories/files to scan")
    p.add_argument('-d', '--delete', action='store_true', help="Delete duplicates")
    p.add_argument('-n', '--dry-run', action='store_true', help="Dry run")
    p.add_argument('-t', '--threads', type=int, default=os.cpu_count() or 1,
                   help="Worker threads")
    p.add_argument('-l', '--log-level', default='INFO', help="Logging level")
    p.add_argument('-p', '--no-progress', action='store_true', help="Disable progress bar")
    p.add_argument('-s', '--strip-metadata', action='store_true',
                   help="Hash file content with metadata removed")
    p.add_argument('-c', '--cache', action=argparse.BooleanOptionalAction, default=True,
                   help="Use persistent hash cache (use --no-cache to disable)")
    p.add_argument('-r', '--recursive', action=argparse.BooleanOptionalAction, default=True,
                   help="Recurse into subdirectories (use --no-recursive to disable)")
    p.add_argument('--delete-within', action='append', default=None,
                   help="Restrict deletions to files under the specified directory")
    args = p.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO),
                        format='%(levelname)s: %(message)s')

    summary: DuplicateSummary | None = None
    try:
        summary = find_duplicates(
            args.paths,
            delete=args.delete,
            dry_run=args.dry_run,
            threads=args.threads,
            show_progress=not args.no_progress,
            strip_metadata=args.strip_metadata,
            recursive=args.recursive,
            use_cache=args.cache,
            delete_roots=[Path(p) for p in args.delete_within] if args.delete_within else None,
        )
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
    if summary is not None:
        if summary.deleted:
            logger.info("Deleted files (%d): %s", len(summary.deleted), _format_paths(summary.deleted))
        else:
            logger.info("Deleted files: none")
        if summary.would_delete:
            logger.info(
                "Files that would be deleted in dry-run (%d): %s",
                len(summary.would_delete),
                _format_paths(summary.would_delete),
            )
        elif args.dry_run:
            logger.info("Files that would be deleted in dry-run: none")


if __name__ == '__main__':
    main()
