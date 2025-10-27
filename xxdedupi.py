#!/usr/bin/env python3
"""
xxdedupi.py - xxhash64-based duplicate finder with optional persistent hashing
cache, logging, dry-run, multithreading and progress display. Designed as a
lightweight replacement for rdfind for use within rog-syncobra.

Usage:
    ./xxdedupi.py [options] DIR [DIR ...]

Options:
    -d, --delete             Remove duplicate files, keeping first instance (default: keep files).
    -n, --dry-run            Show actions without deleting files (default: false).
    -t, --threads N          Number of hashing worker threads (default: CPU count).
        --scan-threads N     Number of directory scanning threads (default: CPU count).
    -l, --log-level L        Logging level (DEBUG, INFO, WARNING; default INFO).
    -p, --no-progress        Disable progress bar (default: show progress).
    -s, --strip-metadata     Hash file content with metadata removed (default: include metadata).
    -r, --recursive          Recurse into subdirectories (default: enabled; use --no-recursive to disable).
    -c, --cache              Use persistent hash cache (default: enabled; use --no-cache to disable).
        --remove-cache       Delete existing cache files before processing.
        --delete-within DIR  Restrict deletions to files under DIR (may be provided multiple times).
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
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

MEDIA_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".bmp",
    ".webp",
    ".heic",
    ".heif",
    ".tif",
    ".tiff",
    ".dng",
    ".nef",
    ".arw",
    ".orf",
    ".raf",
    ".rw2",
    ".srw",
    ".cr2",
    ".cr3",
    ".pef",
    ".raw",
    ".mp4",
    ".mov",
    ".m4v",
    ".mts",
    ".m2ts",
    ".mpg",
    ".mpeg",
    ".vob",
    ".3gp",
    ".avi",
    ".mkv",
    ".wmv",
    ".hevc",
    ".webm",
}

logger = logging.getLogger("xxdedupi")

CACHE_SUFFIXES = ('', '_stripped')


def cache_files_for_root(root: Path) -> list[Path]:
    """Return all cache file paths that xxdedupi may create under *root*."""

    return [root / f'.xxdedupi_cache{suffix}.json' for suffix in CACHE_SUFFIXES]


@dataclass
class DuplicateSummary:
    deleted: list[Path] = field(default_factory=list)
    would_delete: list[Path] = field(default_factory=list)


def _format_paths(paths: list[Path]) -> str:
    return ", ".join(str(p) for p in paths)


def _cache_file(root: Path, strip_metadata: bool) -> Path:
    suffix = '_stripped' if strip_metadata else ''
    return root / f'.xxdedupi_cache{suffix}.json'


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


def remove_cache(root: Path) -> None:
    for cache_path in cache_files_for_root(root):
        try:
            cache_path.unlink()
            logger.info("Removed cache %s", cache_path)
        except FileNotFoundError:
            continue
        except OSError as e:
            logger.warning("Failed to remove cache %s: %s", cache_path, e)


def file_hash(
    path: Path,
    strip_metadata: bool = False,
    algorithm: str = 'xxh64',
) -> tuple[Path, str | None, str | None]:
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
                return path, None, 'unsupported_exiftool_extension'
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
        return path, digest, None
    except Exception as e:
        logger.warning("Hash failed for %s: %s", path, e)
        return path, None, str(e)


def _scan_directory(path: Path, recursive: bool) -> tuple[list[Path], list[Path]]:
    files: list[Path] = []
    subdirs: list[Path] = []
    try:
        with os.scandir(path) as it:
            for entry in it:
                try:
                    entry_path = Path(entry.path)
                    if entry.is_file(follow_symlinks=False):
                        files.append(entry_path)
                    elif recursive and entry.is_dir(follow_symlinks=False):
                        subdirs.append(entry_path)
                except OSError as e:
                    logger.warning("Error accessing %s: %s", entry.path, e)
    except OSError as e:
        logger.warning("Failed to scan directory %s: %s", path, e)
    return files, subdirs


def iter_files(paths, recursive: bool = True, scan_workers: int | None = None):
    for p in paths:
        logger.debug("Scanning %s", p)
        if p.is_file():
            logger.debug("Found file %s", p)
            yield p, p.parent
        elif p.is_dir():
            if not recursive:
                try:
                    with os.scandir(p) as it:
                        for entry in it:
                            try:
                                if entry.is_file(follow_symlinks=False):
                                    file_path = Path(entry.path)
                                    logger.debug("Found file %s", file_path)
                                    yield file_path, p
                            except OSError as e:
                                logger.warning("Error accessing %s: %s", entry.path, e)
                except OSError as e:
                    logger.warning("Failed to scan directory %s: %s", p, e)
                continue

            workers = (
                scan_workers
                if (scan_workers is not None and scan_workers > 0)
                else (os.cpu_count() or 1)
            )
            with ThreadPoolExecutor(max_workers=workers) as executor:
                in_progress: dict[Future[tuple[list[Path], list[Path]]], Path] = {}
                seen_dirs: set[Path] = set()

                def submit_dir(dir_path: Path):
                    try:
                        resolved = dir_path.resolve()
                    except OSError as e:
                        logger.warning("Failed to resolve %s: %s", dir_path, e)
                        return
                    if resolved in seen_dirs:
                        return
                    seen_dirs.add(resolved)
                    future = executor.submit(_scan_directory, resolved, recursive)
                    in_progress[future] = resolved

                submit_dir(p)
                while in_progress:
                    for future in as_completed(list(in_progress.keys())):
                        dir_path = in_progress.pop(future)
                        try:
                            files, subdirs = future.result()
                        except Exception as e:  # pragma: no cover - unexpected
                            logger.warning("Directory scan failed for %s: %s", dir_path, e)
                            files, subdirs = [], []
                        for file_path in files:
                            logger.debug("Found file %s", file_path)
                            yield file_path, dir_path
                        for subdir in subdirs:
                            submit_dir(subdir)


def find_duplicates(paths, delete=False, dry_run=False, threads=None, show_progress=True,
                    strip_metadata: bool | str = False, recursive: bool = True, use_cache: bool = True,
                    delete_roots: list[Path] | None = None,
                    scan_workers: int | None = None,
                    summary: DuplicateSummary | None = None,
                    remove_cache_files: bool = False) -> DuplicateSummary:
    summary = summary or DuplicateSummary()
    raw_files = list(iter_files(paths, recursive, scan_workers=scan_workers))
    logger.debug("Found %d files to process", len(raw_files))

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

    if isinstance(strip_metadata, str):
        if strip_metadata == 'both':
            passes = [False, True]
        else:
            raise ValueError(f"Unsupported strip_metadata mode: {strip_metadata}")
    else:
        passes = [bool(strip_metadata)]

    interrupted = False

    removed_roots: set[Path] = set()

    for index, strip_flag in enumerate(passes):
        if len(passes) > 1:
            logger.debug(
                "Starting %s dedupe pass (%d/%d)",
                'raw' if strip_flag else 'metadata',
                index + 1,
                len(passes),
            )

        cache_map: dict[Path, dict] = {}
        root_map: dict[Path, Path] = {}
        all_files: list[tuple[Path, Path, os.stat_result]] = []
        size_groups: defaultdict[int, list[Path]] = defaultdict(list)

        seen_paths: set[Path] = set()

        for f, root in raw_files:
            try:
                if f.name.startswith('.xxdedupi_cache') and f.suffix == '.json':
                    logger.debug("Skipping cache file %s", f)
                    continue
                resolved = f.resolve()
            except OSError as e:
                logger.warning("Skipping %s: %s", f, e)
                continue
            if resolved in seen_paths:
                logger.debug("Skipping already queued path %s", f)
                continue
            seen_paths.add(resolved)
            cache_root = f.parent
            if remove_cache_files and cache_root not in removed_roots:
                remove_cache(cache_root)
                removed_roots.add(cache_root)
            if not strip_flag:
                suffix = f.suffix.lower()
                if suffix not in MEDIA_EXTENSIONS:
                    logger.debug("Skipping non-media file %s in raw dedupe pass", f)
                    continue
            root_cache = cache_root if use_cache else root
            root_map[f] = root_cache
            if use_cache and root_cache not in cache_map:
                if remove_cache_files:
                    cache_map[root_cache] = {}
                else:
                    cache_map[root_cache] = load_cache(root_cache, strip_flag)
            try:
                stat = f.stat()
            except OSError as e:
                logger.warning("Skipping %s: %s", f, e)
                continue
            all_files.append((f, root_cache, stat))
            size_groups[stat.st_size].append(f)

        if strip_flag:
            hash_candidates = all_files
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(
                    "strip_metadata enabled; hashing all %d files regardless of size",
                    len(all_files),
                )
        else:
            hash_candidates = [
                entry for entry in all_files if len(size_groups[entry[2].st_size]) > 1
            ]
            if logger.isEnabledFor(logging.DEBUG):
                skipped = len(all_files) - len(hash_candidates)
                logger.debug("Skipping hashing for %d files with unique sizes", skipped)

        hash_map: defaultdict[str, list[Path]] = defaultdict(list)
        worker_count = threads if threads and threads > 0 else (os.cpu_count() or 1)
        logger.debug("Using %d worker threads", worker_count)

        def hash_with_cache(item: tuple[Path, Path, os.stat_result]) -> tuple[Path, str | None]:
            path, root_cache, _initial_stat = item
            try:
                stat = path.stat()
            except OSError as e:
                logger.warning("Skipping %s: %s", path, e)
                return path, None
            rel = str(path.relative_to(root_cache))
            digest: str | None = None
            error: str | None = None
            entry = None
            if use_cache:
                cache = cache_map.get(root_cache, {})
                entry = cache.get(rel)
                if entry and entry.get('size') == stat.st_size and entry.get('mtime') == stat.st_mtime:
                    failure = entry.get('xxh64_failed') or entry.get('hash_failed')
                    if failure:
                        logger.debug("Cache indicates failed xxh64 hash for %s; skipping", path)
                        return path, None
                    digest = entry.get('xxh64') or entry.get('hash')
                    if digest:
                        logger.debug("Cache hit for %s", path)
            if not digest:
                logger.debug("Hashing %s", path)
                _, digest, error = file_hash(path, strip_flag, 'xxh64')
                if use_cache:
                    cache_entry = cache_map.setdefault(root_cache, {}).setdefault(rel, {})
                    cache_entry['size'] = stat.st_size
                    cache_entry['mtime'] = stat.st_mtime
                    if digest:
                        cache_entry['xxh64'] = digest
                        cache_entry.pop('xxh64_failed', None)
                        cache_entry.pop('hash_failed', None)
                    else:
                        cache_entry.pop('xxh64', None)
                        cache_entry.pop('hash', None)
                        if error:
                            cache_entry['xxh64_failed'] = error
                        else:
                            cache_entry['xxh64_failed'] = True
            elif use_cache and entry and 'xxh64' not in entry:
                entry['xxh64'] = digest
            return path, digest

        progress_desc = None
        if len(passes) > 1:
            progress_desc = 'raw' if strip_flag else 'metadata'
        progress = tqdm(
            total=len(hash_candidates),
            unit="file",
            disable=not show_progress,
            desc=progress_desc,
        )
        try:
            with ThreadPoolExecutor(max_workers=worker_count) as ex:
                it = ex.map(hash_with_cache, hash_candidates)
                try:
                    for path, digest in it:
                        if digest:
                            hash_map[digest].append(path)
                        progress.update(1)
                except KeyboardInterrupt:
                    interrupted = True
                    logger.warning("Interrupted during hashing; processing partial results")
                    ex.shutdown(cancel_futures=True)
        finally:
            progress.close()

        if not interrupted:
            try:
                for digest, group in hash_map.items():
                    if len(group) < 2:
                        continue
                    strong_map: defaultdict[str, list[Path]] = defaultdict(list)
                    for f in group:
                        root_cache = root_map[f]
                        try:
                            stat = f.stat()
                        except OSError as e:
                            logger.warning("Skipping %s: %s", f, e)
                            continue
                        rel = str(f.relative_to(root_cache))
                        cache = cache_map.get(root_cache, {}) if use_cache else {}
                        entry = cache.get(rel) if use_cache else None
                        strong_digest: str | None = None
                        if use_cache and entry and entry.get('size') == stat.st_size and entry.get('mtime') == stat.st_mtime:
                            if entry.get('blake2b_failed'):
                                logger.debug("Cache indicates failed blake2b hash for %s; skipping", f)
                                continue
                            strong_digest = entry.get('blake2b')
                        if not strong_digest:
                            _, strong_digest, strong_error = file_hash(f, strip_flag, 'blake2b')
                            if use_cache:
                                cache_entry = cache.setdefault(rel, {
                                    'size': stat.st_size,
                                    'mtime': stat.st_mtime,
                                    'xxh64': entry.get('xxh64') or entry.get('hash') if entry else None,
                                })
                                if strong_digest:
                                    cache_entry['blake2b'] = strong_digest
                                    cache_entry.pop('blake2b_failed', None)
                                elif strong_error:
                                    cache_entry.pop('blake2b', None)
                                    cache_entry['blake2b_failed'] = strong_error
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
                                    _, current_digest, _ = file_hash(f, strip_flag, 'blake2b')
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
                interrupted = True
                logger.warning("Interrupted during duplicate verification; saving cache")

        if use_cache and delete:
            for root_cache, cache in cache_map.items():
                if cache:
                    save_cache(root_cache, cache, strip_flag)

        if interrupted:
            break

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
    p.add_argument('--scan-threads', type=int, default=os.cpu_count() or 1,
                   help="Threads for directory scanning")
    p.add_argument('-l', '--log-level', default='INFO', help="Logging level")
    p.add_argument('-v', '--verbose', action='store_true', help="Enable verbose (DEBUG) logging")
    p.add_argument('-p', '--no-progress', action='store_true', help="Disable progress bar")
    p.add_argument('-s', '--strip-metadata', action='store_true',
                   help="Hash file content with metadata removed")
    p.add_argument('-c', '--cache', action=argparse.BooleanOptionalAction, default=True,
                   help="Use persistent hash cache (use --no-cache to disable)")
    p.add_argument('--remove-cache', action='store_true',
                   help="Remove existing cache files before processing")
    p.add_argument('-r', '--recursive', action=argparse.BooleanOptionalAction, default=True,
                   help="Recurse into subdirectories (use --no-recursive to disable)")
    p.add_argument('--delete-within', action='append', default=None,
                   help="Restrict deletions to files under the specified directory")
    args = p.parse_args()

    if args.verbose:
        level = logging.DEBUG
    else:
        level = getattr(logging, args.log_level.upper(), logging.INFO)
    logging.basicConfig(level=level, format='%(levelname)s: %(message)s')
    if args.verbose:
        logger.debug("Verbose logging enabled")

    summary: DuplicateSummary | None = None
    try:
        summary = find_duplicates(
            args.paths,
            delete=args.delete,
            dry_run=args.dry_run,
            threads=args.threads,
            scan_workers=args.scan_threads,
            show_progress=not args.no_progress,
            strip_metadata=args.strip_metadata,
            recursive=args.recursive,
            use_cache=args.cache,
            delete_roots=[Path(p) for p in args.delete_within] if args.delete_within else None,
            remove_cache_files=args.remove_cache,
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
