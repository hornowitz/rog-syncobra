#!/usr/bin/env python3
"""Watch a directory tree structured as /SRC/YYYY/MM and trigger PhotoPrism indexing."""

from __future__ import annotations

import argparse
import os
import queue
import re
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Set

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


@dataclass
class Config:
    """Runtime configuration for the watcher."""

    watch_dir: str
    dest_root: str
    pp_base_url: str
    pp_user: Optional[str] = None
    pp_pass: Optional[str] = None
    token: Optional[str] = None
    verify_tls: bool = True
    min_seconds_between_index: int = 60
    max_queue_lag: int = 5
    dry_run: bool = False
    verbose: bool = False


def verbose_print(cfg: Config, message: str) -> None:
    """Emit a message only when verbose mode is enabled."""

    if cfg.verbose:
        print(message)


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
            print(f"DRY-RUN: would POST {url} {payload}")
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
        print(f"[PhotoPrism] Index triggered for {rel_dest_path}: {resp.status_code}")


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


class MonthEventHandler(FileSystemEventHandler):
    def __init__(self, cfg: Config, out_queue: queue.Queue[str]):
        super().__init__()
        self.cfg = cfg
        self.out_q = out_queue
        self.src_root = os.path.abspath(cfg.watch_dir)

    def _is_tmp(self, name: str) -> bool:
        return any(pattern.search(name) for pattern in TMP_RE)

    def _is_media(self, path: str) -> bool:
        return os.path.splitext(path)[1].lower() in MEDIA_EXT

    def _month_key(self, abs_path: str) -> Optional[str]:
        try:
            rel = os.path.relpath(abs_path, self.src_root)
        except ValueError:
            return None
        match = MONTH_RE.match(rel)
        if not match:
            return None
        year = match.group("year")
        month = match.group("month")
        return f"{year}/{month}"

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
        self.out_q.put(key)
        verbose_print(self.cfg, f"[Watcher] Enqueued month {key} due to {path}")

    def on_created(self, event):  # type: ignore[override]
        if isinstance(event, FileCreatedEvent) and not event.is_directory:
            self._maybe_enqueue(event.src_path)

    def on_moved(self, event):  # type: ignore[override]
        if isinstance(event, FileMovedEvent) and not event.is_directory:
            self._maybe_enqueue(event.dest_path)

    def on_modified(self, event):  # type: ignore[override]
        if isinstance(event, FileModifiedEvent) and not event.is_directory:
            self._maybe_enqueue(event.src_path)


def worker_loop(cfg: Config, q: queue.Queue[str], client: PhotoPrismClient) -> None:
    budget = IndexBudget()
    pending: Set[str] = set()
    last_activity = time.time()

    while True:
        try:
            key = q.get(timeout=1)
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
                        client.index_path(dest)
                    else:
                        print(f"[Debounce] Skipping {ym} (too soon)")


def parse_args() -> Config:
    parser = argparse.ArgumentParser(
        description='Watch /SRC/YYYY/MM and index /DEST/YYYY/MM in PhotoPrism',
    )
    parser.add_argument(
        '--watch-dir',
        required=True,
        help='Source root to watch, e.g., /rogaliki/obrazy',
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
        '--min-seconds-between-index',
        type=int,
        default=60,
        help='Min seconds between index calls per YYYY/MM',
    )
    parser.add_argument(
        '--max-queue-lag',
        type=int,
        default=5,
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
    return Config(
        watch_dir=args.watch_dir,
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

    if not os.path.isdir(cfg.watch_dir):
        print(f"ERROR: watch dir not found: {cfg.watch_dir}", file=sys.stderr)
        sys.exit(2)

    client = PhotoPrismClient(cfg)

    q: queue.Queue[str] = queue.Queue()
    handler = MonthEventHandler(cfg, q)

    observer = Observer()
    observer.schedule(handler, path=cfg.watch_dir, recursive=True)

    stop_event = threading.Event()

    def handle_sig(signum, frame):  # type: ignore[override]
        print("Stopping...")
        stop_event.set()
        observer.stop()

    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    observer.start()
    print(
        f"Watching: {cfg.watch_dir} -> index under {cfg.dest_root} "
        f"(PhotoPrism {cfg.pp_base_url})",
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
