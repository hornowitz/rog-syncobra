#!/usr/bin/env python3
"""Watch directories and trigger Photoprism REST API reindexing."""

from __future__ import annotations

import argparse
import logging
import os
import select
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable

from photoprism_api import PhotoprismAPIConfig, handle_photoprism_index


LOGFILE = '/var/log/rog-syncobra/photoprism-watcher.log'


def _expand_path(path: str | Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(str(path)))).resolve()


def setup_logging() -> logging.Logger:
    logger = logging.getLogger('rog-syncobra')
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')

    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.INFO)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    logdir = os.path.dirname(LOGFILE)
    try:
        os.makedirs(logdir, exist_ok=True)
        fh = logging.FileHandler(LOGFILE)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning('Unable to set up file logging (%s)', exc)
    else:
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    try:
        from systemd.journal import JournalHandler  # type: ignore

        jh = JournalHandler()
    except Exception:  # pragma: no cover - optional dependency
        jh = None
    if jh is not None:
        jh.setLevel(logging.INFO)
        jh.setFormatter(fmt)
        logger.addHandler(jh)

    return logger


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Watch directories and reindex them via the Photoprism REST API',
    )
    parser.add_argument(
        '--watch',
        dest='watch_dirs',
        metavar='DIR',
        action='append',
        required=True,
        help='Directory to monitor for changes (may be specified multiple times)',
    )
    parser.add_argument(
        '--library-root',
        metavar='DIR',
        help='Photoprism library root; defaults to the common prefix of watch directories',
    )
    parser.add_argument(
        '--display-root',
        metavar='DIR',
        help='Optional path used when logging triggered targets',
    )
    parser.add_argument(
        '--grace',
        type=int,
        default=300,
        help='Seconds to wait after the last event before triggering the API (default: 300)',
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show actions without sending API requests',
    )
    parser.add_argument(
        '--initial-index',
        action='store_true',
        help='Trigger indexing for all watch directories before entering watch mode',
    )
    parser.add_argument(
        '--photoprism-api-base-url',
        required=True,
        help='Photoprism API base URL (e.g. https://photos.example.com)',
    )
    parser.add_argument(
        '--photoprism-api-username',
        required=True,
        help='Photoprism API username',
    )
    parser.add_argument(
        '--photoprism-api-password',
        required=True,
        help='Photoprism API password',
    )
    parser.add_argument(
        '--photoprism-api-rescan',
        action='store_true',
        help='Request a full rescan when triggering the Photoprism API',
    )
    parser.add_argument(
        '--photoprism-api-cleanup',
        action='store_true',
        help='Ask Photoprism to run cleanup after indexing',
    )
    parser.add_argument(
        '--photoprism-api-insecure',
        action='store_true',
        help='Disable TLS certificate verification for Photoprism API calls',
    )
    parser.add_argument(
        '--photoprism-api-strip-prefix',
        metavar='PREFIX',
        action='append',
        default=[],
        help='Strip PREFIX from paths before submitting them to the API',
    )

    args = parser.parse_args()

    if args.grace < 0:
        parser.error('--grace must be non-negative')

    return args


def check_program(name: str, logger: logging.Logger) -> None:
    if shutil.which(name):
        return
    logger.error("Required program '%s' not found in PATH.", name)
    sys.exit(1)


def determine_library_root(watch_paths: Iterable[Path], override: str | None) -> Path:
    if override:
        return _expand_path(override)

    paths = list(watch_paths)
    if not paths:
        raise ValueError('at least one watch path is required')
    if len(paths) == 1:
        return paths[0]

    common = os.path.commonpath([str(p) for p in paths])
    return _expand_path(common)


def build_api_config(args: argparse.Namespace) -> PhotoprismAPIConfig:
    return PhotoprismAPIConfig(
        base_url=args.photoprism_api_base_url.strip(),
        username=args.photoprism_api_username,
        password=args.photoprism_api_password,
        verify_tls=not args.photoprism_api_insecure,
        rescan=args.photoprism_api_rescan,
        cleanup=args.photoprism_api_cleanup,
        path_strip_prefixes=tuple(args.photoprism_api_strip_prefix or ()),
    )


def trigger_index(
    pending: set[Path],
    *,
    dry_run: bool,
    library_root: Path,
    display_root: Path | None,
    api_config: PhotoprismAPIConfig,
    logger: logging.Logger,
) -> None:
    if not pending:
        return

    sorted_targets = sorted(pending, key=lambda p: p.as_posix())
    logger.info(
        'Triggering Photoprism index for %s',
        ', '.join(p.as_posix() for p in sorted_targets),
    )
    handle_photoprism_index(
        dry_run,
        True,
        sorted_targets,
        library_root,
        api_config,
        display_root,
    )


def collect_target(path_str: str, *, library_root: Path, logger: logging.Logger) -> Path | None:
    candidate = Path(path_str)
    if not candidate.exists():
        candidate = candidate.parent
    elif candidate.is_file():
        candidate = candidate.parent

    if not str(candidate):
        candidate = Path('/')

    resolved = _expand_path(candidate)
    try:
        resolved.relative_to(library_root)
    except ValueError:
        logger.debug(
            'Ignoring event outside library root: %s (library root: %s)',
            resolved,
            library_root,
        )
        return None
    try:
        relative_parts = resolved.relative_to(library_root).parts
    except ValueError:  # pragma: no cover - defensive
        return resolved

    if len(relative_parts) >= 3 and relative_parts[0] == 'aktuell':
        resolved = library_root.joinpath(*relative_parts[:3])

    return resolved


def watch_directories(
    *,
    watch_paths: list[Path],
    grace: int,
    dry_run: bool,
    library_root: Path,
    display_root: Path | None,
    api_config: PhotoprismAPIConfig,
    logger: logging.Logger,
) -> None:
    cmd = [
        'inotifywait',
        '--quiet',
        '--monitor',
        '--recursive',
        '--format',
        '%w%f',
        '--event',
        'close_write,create,delete,move',
        *[p.as_posix() for p in watch_paths],
    ]
    logger.info('Starting inotifywait: %s', ' '.join(cmd))
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert proc.stdout is not None

    pending: set[Path] = set()

    def _flush() -> None:
        nonlocal pending
        if pending:
            trigger_index(
                pending,
                dry_run=dry_run,
                library_root=library_root,
                display_root=display_root,
                api_config=api_config,
                logger=logger,
            )
            pending.clear()

    try:
        while True:
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break
                time.sleep(0.1)
                continue
            line = line.strip()
            if not line:
                continue

            target = collect_target(line, library_root=library_root, logger=logger)
            if target is not None:
                pending.add(target)

            deadline = time.monotonic() + grace
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                ready, _, _ = select.select([proc.stdout], [], [], remaining)
                if not ready:
                    break
                follow_up = proc.stdout.readline()
                if not follow_up:
                    if proc.poll() is not None:
                        break
                    continue
                follow_up = follow_up.strip()
                if not follow_up:
                    continue
                target = collect_target(
                    follow_up,
                    library_root=library_root,
                    logger=logger,
                )
                if target is not None:
                    pending.add(target)
                deadline = time.monotonic() + grace

            _flush()
    except KeyboardInterrupt:
        logger.info('Interrupted by user, flushing pending events before exit')
        _flush()
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


def main() -> None:
    args = parse_args()
    logger = setup_logging()
    check_program('inotifywait', logger)

    watch_paths = [_expand_path(path) for path in args.watch_dirs]
    for path in watch_paths:
        if not path.exists():
            logger.error('Watch path does not exist: %s', path)
            sys.exit(1)
        if not path.is_dir():
            logger.error('Watch path is not a directory: %s', path)
            sys.exit(1)

    library_root = determine_library_root(watch_paths, args.library_root)
    for path in watch_paths:
        try:
            path.relative_to(library_root)
        except ValueError:
            logger.error(
                'Watch path %s is not within the Photoprism library root %s',
                path,
                library_root,
            )
            sys.exit(1)

    display_root = _expand_path(args.display_root) if args.display_root else library_root

    api_config = build_api_config(args)

    if args.initial_index:
        logger.info('Running initial index for watch directories')
        trigger_index(
            set(watch_paths),
            dry_run=args.dry_run,
            library_root=library_root,
            display_root=display_root,
            api_config=api_config,
            logger=logger,
        )

    watch_directories(
        watch_paths=watch_paths,
        grace=args.grace,
        dry_run=args.dry_run,
        library_root=library_root,
        display_root=display_root,
        api_config=api_config,
        logger=logger,
    )


if __name__ == '__main__':
    main()

