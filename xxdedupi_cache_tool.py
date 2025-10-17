#!/usr/bin/env python3
"""Utility to remove cached hashes produced by :mod:`xxdedupi`."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Iterable

import xxdedupi

logger = logging.getLogger("xxdedupi-cache-tool")
CACHE_FILENAMES = tuple(path.name for path in xxdedupi.cache_files_for_root(Path(".")))


def _normalize_path(raw: str) -> Path:
    return Path(raw).expanduser().resolve()


def _discover_cache_files(root: Path, recursive: bool) -> set[Path]:
    caches: set[Path] = set()
    if not root.exists():
        logger.warning("Skipping %s (does not exist)", root)
        return caches
    if not root.is_dir():
        logger.warning("Skipping %s (not a directory)", root)
        return caches

    if recursive:
        for name in CACHE_FILENAMES:
            for candidate in root.rglob(name):
                if candidate.is_file():
                    caches.add(candidate)
    else:
        for cache_path in xxdedupi.cache_files_for_root(root):
            if cache_path.is_file():
                caches.add(cache_path)

    return caches


def remove_cache_files(paths: Iterable[str], recursive: bool = False, dry_run: bool = False) -> int:
    """Remove xxdedupi cache files under ``paths``.

    Returns the number of cache files that were removed (or would be removed
    during a dry-run).
    """

    seen: set[Path] = set()
    removed = 0
    for raw in paths:
        root = _normalize_path(raw)
        caches = _discover_cache_files(root, recursive)
        if not caches:
            logger.debug("No caches found under %s", root)
        for cache_path in sorted(caches):
            if cache_path in seen:
                continue
            seen.add(cache_path)
            if dry_run:
                logger.info("Would remove %s", cache_path)
                removed += 1
                continue
            try:
                cache_path.unlink()
            except FileNotFoundError:
                continue
            except OSError as exc:
                logger.warning("Failed to remove %s: %s", cache_path, exc)
            else:
                logger.info("Removed %s", cache_path)
                removed += 1
    return removed


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Remove xxdedupi cache files (.xxdedupi_cache*.json)."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=["."],
        help="Directories to scan (default: current directory)",
    )
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Scan directories recursively",
    )
    parser.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="Show which files would be removed without deleting them",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Only print warnings and errors",
    )
    return parser.parse_args(argv)


def configure_logging(verbose: bool, quiet: bool) -> None:
    if quiet:
        level = logging.WARNING
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    configure_logging(args.verbose, args.quiet)
    removed = remove_cache_files(args.paths, recursive=args.recursive, dry_run=args.dry_run)
    if removed == 0:
        message = "No cache files would be removed" if args.dry_run else "No cache files removed"
        logger.info(message)
    else:
        message = "Would remove %d cache file%s" if args.dry_run else "Removed %d cache file%s"
        plural = "s" if removed != 1 else ""
        logger.info(message, removed, plural)
    return 0


if __name__ == "__main__":  # pragma: no cover - manual execution entry point
    raise SystemExit(main())
