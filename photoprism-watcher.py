#!/usr/bin/env python3
"""Watch a directory tree structured as /SRC/YYYY/MM and trigger PhotoPrism indexing."""

from __future__ import annotations

import argparse
import logging
import os
import queue
import re
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple

import requests
from watchdog.events import (
    FileCreatedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer


MEDIA_EXT = {
    # photos
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
    ".heic",
    ".heif",
    ".tif",
    ".tiff",
    ".bmp",
    ".dng",
    ".cr2",
    ".cr3",
    ".nef",
    ".arw",
    # videos
    ".mp4",
    ".mov",
    ".m4v",
    ".avi",
    ".mkv",
    ".webm",
    ".3gp",
    ".mts",
    ".m2ts",
}

TMP_PATTERNS = [r"\\.part$", r"\\.tmp$", r"^\\.", r"\\.incomplete$", r"~$"]
TMP_RE = [re.compile(pattern, re.IGNORECASE) for pattern in TMP_PATTERNS]

MONTH_RE = re.compile(r"^(?P<year>\d{4})/(?P<month>\d{2})(?:/|$)")


DEFAULT_LOGFILE = '/var/log/rog-syncobra/photoprism-watcher.log'


def _resolve_logfile() -> Optional[str]:
    raw = os.environ.get('PHOTOPRISM_WATCHER_LOGFILE')
    if raw is None:
        return DEFAULT_LOGFILE
    candidate = raw.strip()
    if not candidate:
        return None
    return os.path.abspath(os.path.expanduser(candidate))


LOGFILE = _resolve_logfile()

logger = logging.getLogger('photoprism-watcher')
logger.setLevel(logging.INFO)
logger.propagate = False

_LOG_HANDLERS: list[logging.Handler] = []

fmt = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')

stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setLevel(logging.INFO)
stream_handler.setFormatter(fmt)
logger.addHandler(stream_handler)
_LOG_HANDLERS.append(stream_handler)

if LOGFILE:
    logdir = os.path.dirname(LOGFILE)
    try:
        os.makedirs(logdir, exist_ok=True)
    except Exception as exc:
        logger.error("Could not create log dir %s: %s", logdir, exc)
    try:
        file_handler = logging.FileHandler(LOGFILE)
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)
        _LOG_HANDLERS.append(file_handler)
    except Exception as exc:
        logger.error("Could not open log file %s: %s", LOGFILE, exc)


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)
    for handler in _LOG_HANDLERS:
        handler.setLevel(level)


def _normalize_pp_base_url(base_url: str) -> str:
    """Ensure the PhotoPrism base URL includes the /api/v1 suffix."""

    url = base_url.strip()
    if not url:
        raise ValueError("PhotoPrism base URL cannot be empty")
    url = url.rstrip('/')

    if url.endswith('/api/v1'):
        return url
    if url.endswith('/api'):
        return f"{url}/v1"
    if '/api/' in url:
        return url
    return f"{url}/api/v1"


@dataclass
class Config:
    """Runtime configuration for the watcher."""

    watch_dirs: Tuple[str, ...]
    dest_root: str
    pp_base_url: str
    pp_user: Optional[str] = None
    pp_pass: Optional[str] = None
    token: Optional[str] = None
    verify_tls: bool = True
    min_seconds_between_index: int = 300
    max_queue_lag: int = 300
    dry_run: bool = False
    verbose: bool = False

    def __post_init__(self) -> None:
        self.pp_base_url = _normalize_pp_base_url(self.pp_base_url)
        normalized: list[str] = []
        seen = set()
        for raw in self.watch_dirs:
            path = os.path.abspath(raw)
            if path not in seen:
                normalized.append(path)
                seen.add(path)
        if not normalized:
            raise ValueError("At least one watch directory must be provided")
        self.watch_dirs = tuple(normalized)


def verbose_print(cfg: Config, message: str) -> None:
    """Emit a message only when verbose mode is enabled."""

    if cfg.verbose:
        logger.debug(message)


class PhotoPrismClient:
    """Simple PhotoPrism REST API helper."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.session = requests.Session()
        self._token = cfg.token or os.environ.get("PHOTOPRISM_TOKEN")
        if self._token is None and cfg.pp_user and cfg.pp_pass:
            verbose_print(self.cfg, "[PhotoPrism] Logging in with provided credentials")
            self._login()

    def _login(self) -> None:
        url = f"{self.cfg.pp_base_url.rstrip('/')}/session"
        resp = self.session.post(
            url,
            json={"username": self.cfg.pp_user, "password": self.cfg.pp_pass},
            verify=self.cfg.verify_tls,
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data.get("access_token")
        if not self._token:
            raise RuntimeError("PhotoPrism login succeeded but no access_token in response")

    def _headers(self) -> dict[str, str]:
        if not self._token:
            raise RuntimeError(
                "No PhotoPrism token. Provide --pp-user/--pp-pass or PHOTOPRISM_TOKEN",
            )
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}

    def index_path(self, rel_dest_path: str) -> None:
        """Trigger PhotoPrism index for a path under the originals root (DEST)."""

        url = f"{self.cfg.pp_base_url.rstrip('/')}/index"
        payload = {
            "path": rel_dest_path,
            "rescan": False,
            "convert": False,
            "cleanup": False,
            "originals": True,
        }
        if self.cfg.dry_run:
            logger.info("DRY-RUN: would POST %s %s", url, payload)
            return
        verbose_print(self.cfg, f"[PhotoPrism] POST {url} {payload}")
        resp = self.session.post(
            url,
            json=payload,
            headers=self._headers(),
            verify=self.cfg.verify_tls,
            timeout=30,
        )
        if resp.status_code == 401 and self.cfg.pp_user and self.cfg.pp_pass:
            verbose_print(self.cfg, "[PhotoPrism] Token expired, attempting re-login")
            self._login()
            resp = self.session.post(
                url,
                json=payload,
                headers=self._headers(),
                verify=self.cfg.verify_tls,
                timeout=30,
            )
        resp.raise_for_status()
        logger.info("[PhotoPrism] Index triggered for %s: %s", rel_dest_path, resp.status_code)


@dataclass
class IndexBudget:
    last_index_ts: Dict[str, float] = field(default_factory=dict)

    def allowed(self, key: str, min_interval_s: int) -> bool:
        now = time.time()
        last = self.last_index_ts.get(key, 0)
        if now - last >= min_interval_s:
            self.last_index_ts[key] = now
            return True
        return False


class MonthQueue:
    """A queue that deduplicates months currently waiting to be processed."""

    def __init__(self) -> None:
        self._queue: queue.Queue[str] = queue.Queue()
        self._seen: Set[str] = set()
        self._lock = threading.Lock()

    def put(self, item: str) -> bool:
        with self._lock:
            if item in self._seen:
                return False
            self._seen.add(item)
        self._queue.put(item)
        return True

    def get(self, timeout: Optional[float] = None) -> str:
        return self._queue.get(timeout=timeout)

    def mark_processed(self, item: str) -> None:
        with self._lock:
            self._seen.discard(item)


class MonthEventHandler(FileSystemEventHandler):
    def __init__(self, cfg: Config, out_queue: MonthQueue):
        super().__init__()
        self.cfg = cfg
        self.out_q = out_queue
        self.src_roots = cfg.watch_dirs

    def _is_tmp(self, name: str) -> bool:
        return any(pattern.search(name) for pattern in TMP_RE)

    def _is_media(self, path: str) -> bool:
        return os.path.splitext(path)[1].lower() in MEDIA_EXT

    def _month_key(self, abs_path: str) -> Optional[str]:
        candidate = os.path.abspath(abs_path)
        for root in self.src_roots:
            try:
                common = os.path.commonpath([candidate, root])
            except ValueError:
                continue
            if common != root:
                continue
            try:
                rel = os.path.relpath(candidate, root)
            except ValueError:
                continue
            match = MONTH_RE.match(rel)
            if not match:
                continue
            year = match.group("year")
            month = match.group("month")
            return f"{year}/{month}"
        return None

    def _maybe_enqueue(self, path: str) -> None:
        name = os.path.basename(path)
        if self._is_tmp(name):
            verbose_print(self.cfg, f"[Watcher] Ignoring temporary file {path}")
            return
        if not self._is_media(path):
            verbose_print(self.cfg, f"[Watcher] Ignoring non-media file {path}")
            return
        key = self._month_key(path)
        if not key:
            verbose_print(self.cfg, f"[Watcher] Ignoring path outside YYYY/MM layout: {path}")
            return
        if self.out_q.put(key):
            verbose_print(self.cfg, f"[Watcher] Enqueued month {key} due to {path}")
        else:
            verbose_print(
                self.cfg, f"[Watcher] Month {key} already pending; ignoring {path}"
            )

    def on_created(self, event):  # type: ignore[override]
        if isinstance(event, FileCreatedEvent) and not event.is_directory:
            self._maybe_enqueue(event.src_path)

    def on_moved(self, event):  # type: ignore[override]
        if isinstance(event, FileMovedEvent) and not event.is_directory:
            self._maybe_enqueue(event.dest_path)

    def on_modified(self, event):  # type: ignore[override]
        if isinstance(event, FileModifiedEvent) and not event.is_directory:
            self._maybe_enqueue(event.src_path)


def worker_loop(cfg: Config, q: MonthQueue, client: PhotoPrismClient) -> None:
    budget = IndexBudget()
    pending: Set[str] = set()
    last_activity = time.time()

    while True:
        try:
            key = q.get(timeout=1)
            if key in pending:
                verbose_print(cfg, f"[Worker] Ignoring duplicate month {key}")
                q.mark_processed(key)
                continue
            pending.add(key)
            last_activity = time.time()
            verbose_print(cfg, f"[Worker] Queued months now: {sorted(pending)}")
        except queue.Empty:
            if pending and (time.time() - last_activity) >= cfg.max_queue_lag:
                months = sorted(pending)
                pending.clear()
                verbose_print(cfg, f"[Worker] Flushing months {months}")
                for ym in months:
                    if budget.allowed(ym, cfg.min_seconds_between_index):
                        dest = f"{cfg.dest_root.rstrip('/')}/{ym}"
                        verbose_print(cfg, f"[Worker] Triggering index for {dest}")
                        try:
                            client.index_path(dest)
                        except requests.exceptions.HTTPError as exc:
                            status = exc.response.status_code if exc.response else "?"
                            body = ""
                            if exc.response is not None:
                                body = exc.response.text.strip()
                                if len(body) > 200:
                                    body = f"{body[:200]}…"
                            logger.error(
                                "[Worker] Failed to index %s: HTTP %s %s",
                                dest,
                                status,
                                body,
                            )
                            pending.add(ym)
                            last_activity = time.time()
                        except Exception as exc:  # pragma: no cover - defensive
                            logger.error(
                                "[Worker] Unexpected error indexing %s: %s",
                                dest,
                                exc,
                            )
                            pending.add(ym)
                            last_activity = time.time()
                    else:
                        logger.info("[Debounce] Skipping %s (too soon)", ym)
                    q.mark_processed(ym)


def parse_args() -> Config:
    parser = argparse.ArgumentParser(
        description='Watch /SRC/YYYY/MM and index /DEST/YYYY/MM in PhotoPrism',
    )
    parser.add_argument(
        '--watch-dir',
        dest='watch_dirs',
        action='append',
        required=True,
        help='Source root(s) to watch, repeat or use pathsep-delimited list',
    )
    parser.add_argument(
        '--dest-root',
        required=True,
        help='Destination originals root, e.g., /aktuell',
    )
    parser.add_argument(
        '--pp-base-url',
        required=True,
        help='PhotoPrism API base, e.g., http://host:2342/api/v1',
    )
    parser.add_argument('--pp-user', help='PhotoPrism username (optional if token provided)')
    parser.add_argument('--pp-pass', help='PhotoPrism password (optional if token provided)')
    parser.add_argument('--token', help='PhotoPrism token (or via PHOTOPRISM_TOKEN env)')
    parser.add_argument(
        '--insecure',
        action='store_true',
        help='Disable TLS verification',
    )
    parser.add_argument(
        '-m',
        '--min-seconds-between-index',
        type=int,
        default=300,
        help='Min seconds between index calls per YYYY/MM',
    )
    parser.add_argument(
        '-q',
        '--max-queue-lag',
        type=int,
        default=300,
        help='Seconds of idle before flushing pending months',
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Log actions without calling PhotoPrism',
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Increase logging verbosity',
    )

    args = parser.parse_args()
    raw_watch_dirs: list[str] = []
    for value in args.watch_dirs:
        for part in value.split(os.pathsep):
            part = part.strip()
            if part:
                raw_watch_dirs.append(part)

    return Config(
        watch_dirs=tuple(raw_watch_dirs),
        dest_root=args.dest_root,
        pp_base_url=args.pp_base_url,
        pp_user=args.pp_user,
        pp_pass=args.pp_pass,
        token=args.token,
        verify_tls=not args.insecure,
        min_seconds_between_index=args.min_seconds_between_index,
        max_queue_lag=args.max_queue_lag,
        dry_run=args.dry_run,
        verbose=args.verbose,
    )


def main() -> None:
    cfg = parse_args()

    configure_logging(cfg.verbose)

    missing = [path for path in cfg.watch_dirs if not os.path.isdir(path)]
    if missing:
        logger.error(
            "ERROR: watch dir(s) not found: %s",
            ", ".join(sorted(missing)),
        )
        sys.exit(2)

    client = PhotoPrismClient(cfg)

    q = MonthQueue()
    handler = MonthEventHandler(cfg, q)

    observer = Observer()
    for watch_dir in cfg.watch_dirs:
        observer.schedule(handler, path=watch_dir, recursive=True)

    stop_event = threading.Event()

    def handle_sig(signum, frame):  # type: ignore[override]
        logger.info("Stopping...")
        stop_event.set()
        observer.stop()

    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    observer.start()
    watches = ", ".join(cfg.watch_dirs)
    logger.info(
        "Watching: %s -> index under %s (PhotoPrism %s)",
        watches,
        cfg.dest_root,
        cfg.pp_base_url,
    )
    verbose_print(
        cfg,
        "[Watcher] Verbose mode enabled; detailed events will be printed",
    )

    worker = threading.Thread(target=worker_loop, args=(cfg, q, client), daemon=True)
    worker.start()

    try:
        while not stop_event.is_set():
            time.sleep(0.5)
    finally:
        observer.stop()
        observer.join()


if __name__ == '__main__':
    main()
